package core

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/common/destinations"
	"github.com/AnixOps/anix-agent/v5/conf"
	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
	log "github.com/sirupsen/logrus"
)

// ErrNodeNotFound is answered for a tag the core does not run. A caller
// removing a node may take it as already removed.
var ErrNodeNotFound = errors.New("the node is not have")

type Selector struct {
	cores map[string]Core
	// order is the configuration order of cores: a node that names no
	// core runs on the first one that serves its protocol.
	order []string
	nodes sync.Map
}

func NewSelector(c []conf.CoreConfig) (Core, error) {
	cs := make(map[string]Core, len(c))
	order := make([]string, 0, len(c))
	for _, t := range c {
		// A configuration that listed several of the retired cores
		// (xray, sing, hysteria2) now names anixcore more than once.
		if _, seen := cs[coreKey(t)]; seen {
			continue
		}
		f, ok := cores[strings.ToLower(t.Type)]
		if !ok {
			return nil, errors.New("unknown core type: " + t.Type)
		}
		core1, err := f(&t)
		if err != nil {
			return nil, err
		}
		key := coreKey(t)
		order = append(order, key)
		cs[key] = core1
	}
	return &Selector{
		cores: cs,
		order: order,
	}, nil
}

func coreKey(t conf.CoreConfig) string {
	if t.Name != "" {
		return t.Name
	}
	return t.Type
}

func (s *Selector) Start() error {
	for i := range s.cores {
		err := s.cores[i].Start()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Selector) Close() error {
	var errs []error
	for i := range s.cores {
		if err := s.cores[i].Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func isSupported(protocol string, protocols []string) bool {
	for i := range protocols {
		if protocol == protocols[i] {
			return true
		}
	}
	return false
}

func (s *Selector) AddNode(tag string, info *panel.NodeInfo, option *conf.Options) error {
	if len(option.CoreName) == 0 && len(option.Core) == 0 {
		return s.addByProtocol(tag, info, option)
	}
	var core Core
	if len(option.CoreName) > 0 {
		// use name to select core
		if c, ok := s.cores[option.CoreName]; ok {
			core = c
		}
	} else {
		for _, key := range s.order {
			if c := s.cores[key]; option.Core == c.Type() {
				core = c
				break
			}
		}
	}
	if core == nil {
		// A node that names a core by CoreName or Core which is not
		// configured (the retired xray, sing or hysteria2, whose names
		// Control may still send) runs on the first core that serves its
		// protocol.
		log.WithFields(log.Fields{"tag": tag, "core": option.Core, "core_name": option.CoreName}).Warn("the node names a core that is not configured; running it on the first core that serves its protocol")
		option.Core, option.CoreName = "", ""
		return s.addByProtocol(tag, info, option)
	}
	err := core.AddNode(tag, info, option)
	if err != nil {
		return err
	}
	s.nodes.Store(tag, core)
	return nil
}

// addByProtocol runs the node on the first core in configuration order that
// serves its protocol. A core that refuses the node (anixcore, for a setting
// it does not have yet) hands it to the next one.
func (s *Selector) addByProtocol(tag string, info *panel.NodeInfo, option *conf.Options) error {
	raw := option.RawOptions
	var refused error
	for _, key := range s.order {
		core := s.cores[key]
		if !isSupported(info.Type, core.Protocols()) {
			continue
		}
		option.Core = core.Type()
		if err := option.UnmarshalJSON(raw); err != nil {
			return fmt.Errorf("unmarshal option error: %s", err)
		}
		option.RawOptions = nil
		err := core.AddNode(tag, info, option)
		if err == nil {
			s.nodes.Store(tag, core)
			return nil
		}
		refused = errors.Join(refused, fmt.Errorf("%s: %w", core.Type(), err))
		log.WithFields(log.Fields{"tag": tag, "core": core.Type()}).WithError(err).Warn("core refused the node; trying the next core that serves its protocol")
	}
	if refused != nil {
		return refused
	}
	return errors.New("the node type is not support")
}

func (s *Selector) DelNode(tag string) error {
	if t, e := s.nodes.Load(tag); e {
		err := t.(Core).DelNode(tag)
		if err != nil {
			return err
		}
		s.nodes.Delete(tag)
		return nil
	}
	return ErrNodeNotFound
}

func (s *Selector) AddUsers(p *AddUsersParams) (added int, err error) {
	t, e := s.nodes.Load(p.Tag)
	if !e {
		return 0, ErrNodeNotFound
	}
	return t.(Core).AddUsers(p)
}

func (s *Selector) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	t, e := s.nodes.Load(tag)
	if !e {
		return nil, ErrNodeNotFound
	}
	return t.(Core).GetUserTrafficSlice(tag, reset)
}

func (s *Selector) GetOnlineDevice(tag string) ([]panel.OnlineUser, error) {
	t, e := s.nodes.Load(tag)
	if !e {
		return nil, ErrNodeNotFound
	}
	provider, ok := t.(OnlineDeviceProvider)
	if !ok {
		return nil, nil
	}
	return provider.GetOnlineDevice(tag)
}

func (s *Selector) GetDestinationTraffic(tag string) ([]destinations.Traffic, error) {
	t, e := s.nodes.Load(tag)
	if !e {
		return nil, ErrNodeNotFound
	}
	provider, ok := t.(DestinationProvider)
	if !ok {
		return nil, nil
	}
	return provider.GetDestinationTraffic(tag)
}

func (s *Selector) UpdateUserRateLimit(tag, uuid string, speedLimit int) error {
	t, ok := s.nodes.Load(tag)
	if !ok {
		return ErrNodeNotFound
	}
	updater, ok := t.(RateLimitUpdater)
	if !ok {
		return nil
	}
	return updater.UpdateUserRateLimit(tag, uuid, speedLimit)
}

func (s *Selector) RollbackUserTrafficSlice(tag string, traffic []panel.UserTraffic) error {
	t, ok := s.nodes.Load(tag)
	if !ok {
		return ErrNodeNotFound
	}
	rollbacker, ok := t.(TrafficRollbacker)
	if !ok {
		return nil
	}
	return rollbacker.RollbackUserTrafficSlice(tag, traffic)
}

func (s *Selector) DelUsers(users []panel.UserInfo, tag string, info *panel.NodeInfo) error {
	t, e := s.nodes.Load(tag)
	if !e {
		return ErrNodeNotFound
	}
	return t.(Core).DelUsers(users, tag, info)
}

func (s *Selector) Protocols() []string {
	protocols := make([]string, 0)
	for _, key := range s.order {
		protocols = append(protocols, s.cores[key].Protocols()...)
	}
	return protocols
}

func (s *Selector) Type() string {
	t := "Selector("
	var flag bool
	for _, n := range s.order {
		c := s.cores[n]
		if flag {
			t += " "
		} else {
			flag = true
		}
		if len(n) == 0 {
			t += c.Type()
		} else {
			t += n
		}
	}
	t += ")"
	return t
}

// ErrEgressUnsupported is answered for egress routes when no core of the
// configuration runs them.
var ErrEgressUnsupported = errors.New("no core of this Agent runs egress routes (they need the xray or anixcore core)")

// ApplyEgress implements EgressApplier: the first core in configuration
// order that runs egress routes runs them all.
func (s *Selector) ApplyEgress(config *panel.EgressConfig) error {
	for _, key := range s.order {
		if applier, ok := s.cores[key].(EgressApplier); ok {
			return applier.ApplyEgress(config)
		}
	}
	if config.Empty() {
		return nil
	}
	return ErrEgressUnsupported
}

// networkApplier is the first core in configuration order that runs the
// device network model, nil for none.
func (s *Selector) networkApplier() NetworkApplier {
	for _, key := range s.order {
		if applier, ok := s.cores[key].(NetworkApplier); ok && len(applier.NetworkKinds()) > 0 {
			return applier
		}
	}
	return nil
}

// NetworkKinds implements NetworkApplier: the kinds of the first core that
// runs the network model, which runs it all.
func (s *Selector) NetworkKinds() []*networkv1.KindSupport {
	if applier := s.networkApplier(); applier != nil {
		return applier.NetworkKinds()
	}
	return nil
}

// ErrNetworkUnsupported is answered for a network plan when no core of the
// configuration runs it.
var ErrNetworkUnsupported = errors.New("no core of this Agent runs the network model (it needs the anixcore core)")

// ApplyNetwork implements NetworkApplier.
func (s *Selector) ApplyNetwork(plan *networkv1.NetworkPlan) (*networkv1.NetworkStatus, error) {
	if applier := s.networkApplier(); applier != nil {
		return applier.ApplyNetwork(plan)
	}
	return nil, ErrNetworkUnsupported
}

// NetworkStatus implements NetworkApplier.
func (s *Selector) NetworkStatus() (*networkv1.NetworkStatus, error) {
	if applier := s.networkApplier(); applier != nil {
		return applier.NetworkStatus()
	}
	return nil, ErrNetworkUnsupported
}
