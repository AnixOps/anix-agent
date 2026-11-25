package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/common/destinations"
	"github.com/AnixOps/anix-agent/v5/conf"
	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
	log "github.com/sirupsen/logrus"
)

var (
	ErrEgressUnsupported  = errors.New("no core of this Agent runs egress routes (they need the anixcore core)")
	ErrNetworkUnsupported = errors.New("no core of this Agent runs the network model (it needs the anixcore core)")
	// ErrTemporaryProxyUnsupported answers temporary proxies for an Agent
	// without the anixcore core.
	ErrTemporaryProxyUnsupported = errors.New("no core of this Agent runs temporary proxies (they need the anixcore core)")
	// ErrMeshUnsupported answers mesh networks for a kernel without the
	// mesh.
	ErrMeshUnsupported = errors.New("the kernel of this Agent has no intranet mesh; update it")
)

// namedCore is a configured core and its name (Name, else Type).
type namedCore struct {
	name string
	Core
}

// Selector runs several cores as one, sending each node to one of them.
type Selector struct {
	cores []namedCore
	mu    sync.RWMutex
	nodes map[string]Core
}

var (
	_ Core                 = (*Selector)(nil)
	_ OnlineDeviceProvider = (*Selector)(nil)
	_ RateLimitUpdater     = (*Selector)(nil)
	_ DestinationProvider  = (*Selector)(nil)
	_ EgressApplier        = (*Selector)(nil)
	_ QoSApplier           = (*Selector)(nil)
	_ ExitPolicyApplier    = (*Selector)(nil)
	_ MainlandCounter      = (*Selector)(nil)
	_ NetworkApplier       = (*Selector)(nil)
)

// newSelector builds the cores of configs in order; a name counts once.
func newSelector(configs []conf.CoreConfig) (Core, error) {
	s := &Selector{nodes: map[string]Core{}}
	for i := range configs {
		name := configs[i].Name
		if name == "" {
			name = configs[i].Type
		}
		if slices.ContainsFunc(s.cores, func(c namedCore) bool { return c.name == name }) {
			continue
		}
		c, err := newCore(&configs[i])
		if err != nil {
			return nil, err
		}
		s.cores = append(s.cores, namedCore{name, c})
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
	types := make([]string, len(s.cores))
	for i, c := range s.cores {
		types[i] = c.Type()
	}
	return "Selector[" + strings.Join(types, " ") + "]"
}

func (s *Selector) Protocols() []string {
	var protocols []string
	for _, c := range s.cores {
		protocols = append(protocols, c.Protocols()...)
	}
	return protocols
}

// AddNode runs the node on the core it names, else on the first core that
// serves its protocol and accepts it.
func (s *Selector) AddNode(tag string, info *panel.NodeInfo, options *conf.Options) error {
	if c := s.named(options); c != nil {
		return s.add(c, tag, info, options)
	}
	if options.CoreName != "" || options.Core != "" {
		log.WithFields(log.Fields{"tag": tag, "core": options.Core, "name": options.CoreName}).
			Warn("the node's core is not configured, picking one by protocol")
		options.CoreName, options.Core = "", ""
	}
	raw := options.RawOptions
	var errs []error
	for _, c := range s.cores {
		if !slices.Contains(c.Protocols(), info.Type) {
			continue
		}
		if len(raw) > 0 {
			if err := options.UnmarshalJSON(raw); err != nil {
				return err
			}
		}
		options.Core, options.RawOptions = c.Type(), nil
		err := s.add(c.Core, tag, info, options)
		if err == nil {
			return nil
		}
		log.WithFields(log.Fields{"tag": tag, "core": c.name}).WithError(err).Warn("core refused the node, trying the next")
		errs = append(errs, fmt.Errorf("%s: %w", c.name, err))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return fmt.Errorf("no core serves protocol %s", info.Type)
}

// named answers the configured core options name, if any.
func (s *Selector) named(options *conf.Options) Core {
	for _, c := range s.cores {
		if options.CoreName != "" {
			if c.name == options.CoreName {
				return c.Core
			}
		} else if options.Core != "" && c.Type() == options.Core {
			return c.Core
		}
	}
	return nil
}

func (s *Selector) add(c Core, tag string, info *panel.NodeInfo, options *conf.Options) error {
	if err := c.AddNode(tag, info, options); err != nil {
		return err
	}
	s.mu.Lock()
	s.nodes[tag] = c
	s.mu.Unlock()
	return nil
}

// coreOf answers the core that runs tag.
func (s *Selector) coreOf(tag string) (Core, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.nodes[tag]
	if !ok {
		return nil, ErrNodeNotFound
	}
	return c, nil
}

func (s *Selector) DelNode(tag string) error {
	c, err := s.coreOf(tag)
	if err != nil {
		return err
	}
	if err := c.DelNode(tag); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.nodes, tag)
	s.mu.Unlock()
	return nil
}

func (s *Selector) AddUsers(tag string, info *panel.NodeInfo, users []panel.UserInfo) (int, error) {
	c, err := s.coreOf(tag)
	if err != nil {
		return 0, err
	}
	return c.AddUsers(tag, info, users)
}

func (s *Selector) DelUsers(tag string, info *panel.NodeInfo, users []panel.UserInfo) error {
	c, err := s.coreOf(tag)
	if err != nil {
		return err
	}
	return c.DelUsers(tag, info, users)
}

func (s *Selector) UserTraffic(tag string, reset bool) ([]panel.UserTraffic, error) {
	c, err := s.coreOf(tag)
	if err != nil {
		return nil, err
	}
	return c.UserTraffic(tag, reset)
}

func (s *Selector) GetOnlineDevice(tag string) ([]panel.OnlineUser, error) {
	c, err := s.coreOf(tag)
	if err != nil {
		return nil, err
	}
	if p, ok := c.(OnlineDeviceProvider); ok {
		return p.GetOnlineDevice(tag)
	}
	return nil, nil
}

func (s *Selector) GetDestinationTraffic(tag string) ([]destinations.Traffic, error) {
	c, err := s.coreOf(tag)
	if err != nil {
		return nil, err
	}
	if p, ok := c.(DestinationProvider); ok {
		return p.GetDestinationTraffic(tag)
	}
	return nil, nil
}

func (s *Selector) UpdateUserRateLimit(tag, uuid string, bytesPerSecond int) error {
	c, err := s.coreOf(tag)
	if err != nil {
		return err
	}
	if u, ok := c.(RateLimitUpdater); ok {
		return u.UpdateUserRateLimit(tag, uuid, bytesPerSecond)
	}
	return nil
}

// first answers the first configured core that implements T.
func first[T any](s *Selector) (T, bool) {
	for _, c := range s.cores {
		if t, ok := c.Core.(T); ok {
			return t, true
		}
	}
	var zero T
	return zero, false
}

func (s *Selector) ApplyEgress(config *panel.EgressConfig) error {
	if a, ok := first[EgressApplier](s); ok {
		return a.ApplyEgress(config)
	}
	if config.Empty() {
		return nil
	}
	return ErrEgressUnsupported
}

func (s *Selector) ApplyQoS(config json.RawMessage) error {
	if a, ok := first[QoSApplier](s); ok {
		return a.ApplyQoS(config)
	}
	return nil
}

func (s *Selector) ApplyExitPolicy(policy panel.ExitPolicy) error {
	if a, ok := first[ExitPolicyApplier](s); ok {
		return a.ApplyExitPolicy(policy)
	}
	return nil
}

func (s *Selector) ApplyTemporaryProxies(proxies []panel.TemporaryProxy) error {
	if a, ok := first[TemporaryProxyApplier](s); ok {
		return a.ApplyTemporaryProxies(proxies)
	}
	if len(proxies) == 0 {
		return nil
	}
	return ErrTemporaryProxyUnsupported
}

func (s *Selector) MeshSupported() bool {
	a, ok := first[MeshApplier](s)
	return ok && a.MeshSupported()
}

func (s *Selector) ApplyMesh(networks []panel.MeshNetwork) error {
	if a, ok := first[MeshApplier](s); ok {
		return a.ApplyMesh(networks)
	}
	if len(networks) == 0 {
		return nil
	}
	return ErrMeshUnsupported
}

func (s *Selector) MeshStatus(ctx context.Context) ([]panel.MeshNetworkStatus, error) {
	if a, ok := first[MeshApplier](s); ok {
		return a.MeshStatus(ctx)
	}
	return nil, ErrMeshUnsupported
}

func (s *Selector) MainlandBlocked(ctx context.Context) (uint64, error) {
	if m, ok := first[MainlandCounter](s); ok {
		return m.MainlandBlocked(ctx)
	}
	return 0, nil
}

// network answers the first core that runs the network model.
func (s *Selector) network() NetworkApplier {
	for _, c := range s.cores {
		if a, ok := c.Core.(NetworkApplier); ok && len(a.NetworkKinds()) > 0 {
			return a
		}
	}
	return nil
}

func (s *Selector) NetworkKinds() []*networkv1.KindSupport {
	if a := s.network(); a != nil {
		return a.NetworkKinds()
	}
	return nil
}

func (s *Selector) ApplyNetwork(plan *networkv1.NetworkPlan) (*networkv1.NetworkStatus, error) {
	if a := s.network(); a != nil {
		return a.ApplyNetwork(plan)
	}
	return nil, ErrNetworkUnsupported
}

func (s *Selector) NetworkStatus() (*networkv1.NetworkStatus, error) {
	if a := s.network(); a != nil {
		return a.NetworkStatus()
	}
	return nil, ErrNetworkUnsupported
}
