package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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

// Selector runs several cores as one: each node runs on one of them, and
// the per-node calls go to the core that runs the tag.
type Selector struct {
	// cores in configuration order; a node that names no core runs on the
	// first one that serves its protocol.
	cores []namedCore
	mu    sync.RWMutex
	nodes map[string]Core // by tag
}

type namedCore struct {
	name string // the configuration's Name, else its Type
	Core
}

func newSelector(configs []conf.CoreConfig) (*Selector, error) {
	s := &Selector{nodes: map[string]Core{}}
	for i := range configs {
		c := &configs[i]
		name := c.Name
		if name == "" {
			name = c.Type
		}
		// A configuration that listed several of the retired cores
		// (xray, sing, hysteria2) now names anixcore more than once.
		if slices.ContainsFunc(s.cores, func(n namedCore) bool { return n.name == name }) {
			continue
		}
		f, ok := factories[c.Type]
		if !ok {
			return nil, fmt.Errorf("unknown core type %q", c.Type)
		}
		core, err := f(c)
		if err != nil {
			return nil, err
		}
		s.cores = append(s.cores, namedCore{name, core})
	}
	return s, nil
}

func (s *Selector) Start() error {
	for _, c := range s.cores {
		if err := c.Start(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Selector) Close() error {
	var errs []error
	for _, c := range s.cores {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}

func (s *Selector) Type() string {
	names := make([]string, len(s.cores))
	for i, c := range s.cores {
		names[i] = c.name
	}
	return fmt.Sprintf("Selector%v", names)
}

func (s *Selector) Protocols() []string {
	var protocols []string
	for _, c := range s.cores {
		protocols = append(protocols, c.Protocols()...)
	}
	return protocols
}

// AddNode runs the node on the core its options name (CoreName, else
// Core), or else by its protocol.
func (s *Selector) AddNode(tag string, info *panel.NodeInfo, options *conf.Options) error {
	if options.CoreName == "" && options.Core == "" {
		return s.addByProtocol(tag, info, options)
	}
	i := slices.IndexFunc(s.cores, func(c namedCore) bool {
		if options.CoreName != "" {
			return c.name == options.CoreName
		}
		return c.Type() == options.Core
	})
	if i < 0 {
		// A node that names a core which is not configured (the retired
		// xray, sing or hysteria2, whose names Control may still send)
		// runs on the first core that serves its protocol.
		log.WithFields(log.Fields{"tag": tag, "core": options.Core, "core_name": options.CoreName}).Warn("the node names a core that is not configured; running it on the first core that serves its protocol")
		options.Core, options.CoreName = "", ""
		return s.addByProtocol(tag, info, options)
	}
	if err := s.cores[i].AddNode(tag, info, options); err != nil {
		return err
	}
	s.setNode(tag, s.cores[i].Core)
	return nil
}

// addByProtocol runs the node on the first core in configuration order that
// serves its protocol. A core that refuses the node (anixcore, for a setting
// it does not have yet) hands it to the next one. The options are read
// again for each core, as that core's options.
func (s *Selector) addByProtocol(tag string, info *panel.NodeInfo, options *conf.Options) error {
	raw := options.RawOptions
	var refused error
	for _, c := range s.cores {
		if !slices.Contains(c.Protocols(), info.Type) {
			continue
		}
		if err := options.UnmarshalJSON(raw); err != nil {
			return fmt.Errorf("node options: %w", err)
		}
		options.Core, options.RawOptions = c.Type(), nil
		err := c.AddNode(tag, info, options)
		if err == nil {
			s.setNode(tag, c.Core)
			return nil
		}
		refused = errors.Join(refused, fmt.Errorf("%s: %w", c.Type(), err))
		log.WithFields(log.Fields{"tag": tag, "core": c.Type()}).WithError(err).Warn("core refused the node; trying the next core that serves its protocol")
	}
	if refused != nil {
		return refused
	}
	return fmt.Errorf("no core serves %s nodes", info.Type)
}

func (s *Selector) setNode(tag string, c Core) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c == nil {
		delete(s.nodes, tag)
	} else {
		s.nodes[tag] = c
	}
}

// node is the core that runs tag.
func (s *Selector) node(tag string) (Core, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.nodes[tag]; ok {
		return c, nil
	}
	return nil, ErrNodeNotFound
}

func (s *Selector) DelNode(tag string) error {
	c, err := s.node(tag)
	if err != nil {
		return err
	}
	if err := c.DelNode(tag); err != nil {
		return err
	}
	s.setNode(tag, nil)
	return nil
}

func (s *Selector) AddUsers(tag string, info *panel.NodeInfo, users []panel.UserInfo) (int, error) {
	c, err := s.node(tag)
	if err != nil {
		return 0, err
	}
	return c.AddUsers(tag, info, users)
}

func (s *Selector) DelUsers(tag string, info *panel.NodeInfo, users []panel.UserInfo) error {
	c, err := s.node(tag)
	if err != nil {
		return err
	}
	return c.DelUsers(tag, info, users)
}

func (s *Selector) UserTraffic(tag string, reset bool) ([]panel.UserTraffic, error) {
	c, err := s.node(tag)
	if err != nil {
		return nil, err
	}
	return c.UserTraffic(tag, reset)
}

// nodeAs is the core that runs tag as an optional interface T; ok is false
// when that core does not implement it.
func nodeAs[T any](s *Selector, tag string) (impl T, ok bool, err error) {
	c, err := s.node(tag)
	if err != nil {
		return impl, false, err
	}
	impl, ok = c.(T)
	return impl, ok, nil
}

func (s *Selector) GetOnlineDevice(tag string) ([]panel.OnlineUser, error) {
	p, ok, err := nodeAs[OnlineDeviceProvider](s, tag)
	if !ok {
		return nil, err
	}
	return p.GetOnlineDevice(tag)
}

func (s *Selector) GetDestinationTraffic(tag string) ([]destinations.Traffic, error) {
	p, ok, err := nodeAs[DestinationProvider](s, tag)
	if !ok {
		return nil, err
	}
	return p.GetDestinationTraffic(tag)
}

func (s *Selector) UpdateUserRateLimit(tag, uuid string, speedLimit int) error {
	p, ok, err := nodeAs[RateLimitUpdater](s, tag)
	if !ok {
		return err
	}
	return p.UpdateUserRateLimit(tag, uuid, speedLimit)
}

func (s *Selector) RollbackUserTraffic(tag string, traffic []panel.UserTraffic) error {
	p, ok, err := nodeAs[TrafficRollbacker](s, tag)
	if !ok {
		return err
	}
	return p.RollbackUserTraffic(tag, traffic)
}

// firstAs is the first core in configuration order that implements T.
func firstAs[T any](s *Selector) (T, bool) {
	for _, c := range s.cores {
		if impl, ok := c.Core.(T); ok {
			return impl, true
		}
	}
	var none T
	return none, false
}

// ErrEgressUnsupported is answered for egress routes when no core of the
// configuration runs them.
var ErrEgressUnsupported = errors.New("no core of this Agent runs egress routes (they need the anixcore core)")

// ApplyEgress implements EgressApplier: the first core in configuration
// order that runs egress routes runs them all.
func (s *Selector) ApplyEgress(config *panel.EgressConfig) error {
	if a, ok := firstAs[EgressApplier](s); ok {
		return a.ApplyEgress(config)
	}
	if config.Empty() {
		return nil
	}
	return ErrEgressUnsupported
}

// ApplyQoS implements QoSApplier: the first core in configuration order
// that runs traffic priorities runs them; without one, they are left out
// (traffic still flows).
func (s *Selector) ApplyQoS(config json.RawMessage) error {
	if a, ok := firstAs[QoSApplier](s); ok {
		return a.ApplyQoS(config)
	}
	return nil
}

// ApplyExitPolicy implements ExitPolicyApplier: the first core in
// configuration order that runs an exit policy runs it; without one, it is
// left out.
func (s *Selector) ApplyExitPolicy(policy panel.ExitPolicy) error {
	if a, ok := firstAs[ExitPolicyApplier](s); ok {
		return a.ApplyExitPolicy(policy)
	}
	return nil
}

// MainlandBlocked implements MainlandCounter with the core that runs the
// exit policy.
func (s *Selector) MainlandBlocked(ctx context.Context) (uint64, error) {
	if c, ok := firstAs[MainlandCounter](s); ok {
		return c.MainlandBlocked(ctx)
	}
	return 0, nil
}

// networkApplier is the first core in configuration order that runs the
// device network model, nil for none.
func (s *Selector) networkApplier() NetworkApplier {
	for _, c := range s.cores {
		if a, ok := c.Core.(NetworkApplier); ok && len(a.NetworkKinds()) > 0 {
			return a
		}
	}
	return nil
}

// NetworkKinds implements NetworkApplier: the kinds of the first core that
// runs the network model, which runs it all.
func (s *Selector) NetworkKinds() []*networkv1.KindSupport {
	if a := s.networkApplier(); a != nil {
		return a.NetworkKinds()
	}
	return nil
}

// ErrNetworkUnsupported is answered for a network plan when no core of the
// configuration runs it.
var ErrNetworkUnsupported = errors.New("no core of this Agent runs the network model (it needs the anixcore core)")

// ApplyNetwork implements NetworkApplier.
func (s *Selector) ApplyNetwork(plan *networkv1.NetworkPlan) (*networkv1.NetworkStatus, error) {
	if a := s.networkApplier(); a != nil {
		return a.ApplyNetwork(plan)
	}
	return nil, ErrNetworkUnsupported
}

// NetworkStatus implements NetworkApplier.
func (s *Selector) NetworkStatus() (*networkv1.NetworkStatus, error) {
	if a := s.networkApplier(); a != nil {
		return a.NetworkStatus()
	}
	return nil, ErrNetworkUnsupported
}
