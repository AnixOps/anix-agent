package forward

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v5/api/agent"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"github.com/AnixOps/anix-control/sdk/forward/wire"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

// Cadences (forward-sdk.md section 8).
const (
	// DefaultReportInterval: a report every 60 s ...
	DefaultReportInterval = 60 * time.Second
	// DefaultReportMinGap: ... and after an apply or a vantage change, at
	// most one every 10 s.
	DefaultReportMinGap = 10 * time.Second
	// defaultProbeTick is the vantage scheduler's resolution.
	defaultProbeTick = time.Second
	// maxProbes bounds the vantage probes in flight.
	maxProbes = 32
)

// Options configure a Component.
type Options struct {
	// Node is the node the Agent speaks for: its state's node_ref and its
	// reports' (forward-41, proxy-7).
	Node agentcontrol.AgentNode
	// StateDir holds the persisted state (absolute; the Agent's own state
	// directory).
	StateDir string
	// AgentVersion goes into NodeCapabilities.
	AgentVersion string
	// Host is the rest of NodeCapabilities; ProbeHost reads it.
	Host HostInfo
	// Dial runs the vantage probes and the forward diagnostic checks (TCP
	// connect, and UDP for the checks); nil uses net.Dialer.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// Lookup resolves a target name for the diagnostic checks; nil uses
	// the system resolver.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// Run runs the diagnostic checks' read-only host commands (ss, nft);
	// nil runs them.
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)
	// SS and NFT are those binaries; empty runs them from PATH.
	SS, NFT string

	// Cadences; zero means the default. Tests shorten them.
	ReportInterval time.Duration
	ReportMinGap   time.Duration
	// ProbeTick is the vantage scheduler's resolution (1 s).
	ProbeTick time.Duration
	// Now defaults to time.Now.
	Now func() time.Time
}

// Component is the Agent's forward component (forward-sdk.md sections 6 to
// 8, F3b). See the package documentation.
type Component struct {
	opts    Options
	nodeRef string
	store   *stateStore
	logger  *log.Entry

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// applyMu serialises applies (snapshots, retries, the boot re-apply).
	applyMu sync.Mutex

	mu      sync.Mutex
	started bool
	// desired is the state last accepted from Control (persisted), nil
	// before the first.
	desired   *forwardv1.NodeForwardState
	hopErrors []*forwardv1.HopError
	// Reports.
	sender        func(*agentv1pb.PackageReport) error
	negotiated    bool
	reportPending bool
	lastReport    time.Time
	reportsSent   uint64
	// logged holds the last value of each condition logChange logs.
	logged map[string]string
	// Vantage probes (vantage.go): per probe, its hysteresis.
	vantage map[vantageKey]*vantageState

	reportWake chan struct{}
	probes     chan struct{}
}

// New answers a component. Start it before the Agent connects to Control.
func New(opts Options) (*Component, error) {
	if !opts.Node.Valid() {
		return nil, fmt.Errorf("forward: invalid node %q", opts.Node.String())
	}
	if opts.ReportInterval <= 0 {
		opts.ReportInterval = DefaultReportInterval
	}
	if opts.ReportMinGap <= 0 {
		opts.ReportMinGap = DefaultReportMinGap
	}
	if opts.ProbeTick <= 0 {
		opts.ProbeTick = defaultProbeTick
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Dial == nil {
		var dialer net.Dialer
		opts.Dial = dialer.DialContext
	}
	nodeRef := opts.Node.String()
	store, err := openStateStore(opts.StateDir, nodeRef)
	if err != nil {
		return nil, err
	}
	c := &Component{
		opts: opts, nodeRef: nodeRef, store: store,
		logger:  log.WithFields(log.Fields{"component": "forward", "node": nodeRef}),
		vantage: map[vantageKey]*vantageState{},
		logged:  map[string]string{},
		// Buffered: a wake never blocks and never gets lost.
		reportWake: make(chan struct{}, 1),
		probes:     make(chan struct{}, maxProbes),
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	return c, nil
}

// NodeRef answers the node's reference (forward-41).
func (c *Component) NodeRef() string { return c.nodeRef }

// Start loads the persisted state, before the Agent connects to Control,
// so the vantage probes go on while Control is down, then runs the probe
// and report loops until Close.
func (c *Component) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return errors.New("forward: component already started")
	}
	c.started = true
	c.mu.Unlock()
	state, _, err := c.store.load()
	if err != nil {
		c.logger.WithError(err).Warn("Could not use the persisted forwarding state; waiting for Control's")
	}
	if state != nil {
		c.logger.WithFields(log.Fields{"generation": state.GetGeneration(), "hops": len(state.GetHops())}).
			Info("Loaded the persisted forwarding state before connecting to Control")
		c.applyMu.Lock()
		c.apply(state)
		c.applyMu.Unlock()
	}
	c.wg.Add(2)
	go func() { defer c.wg.Done(); c.runProbes() }()
	go func() { defer c.wg.Done(); c.runReports() }()
	return nil
}

// Close stops the loops.
func (c *Component) Close() {
	c.cancel()
	c.wg.Wait()
}

// runProbes starts the vantage probes that are due every ProbeTick.
func (c *Component) runProbes() {
	ticker := time.NewTicker(c.opts.ProbeTick)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		}
		c.scheduleVantage(c.opts.Now())
	}
}

// SetSender sets how reports reach Control: the data plane's
// SendForwardReport. Reports wait until a session negotiated forward.v1.
func (c *Component) SetSender(send func(*agentv1pb.PackageReport) error) {
	c.mu.Lock()
	c.sender = send
	c.mu.Unlock()
}

// ForwardSession implements agent.ForwardHandler: a session started; when
// it negotiated forward.v1 a report goes out at once (rate limit kept).
func (c *Component) ForwardSession(negotiated bool) {
	c.mu.Lock()
	c.negotiated = negotiated
	if negotiated {
		c.reportPending = true
	}
	c.mu.Unlock()
	if negotiated {
		wake(c.reportWake)
	}
}

func wake(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// ApplySnapshot takes the forwarding state of a configuration snapshot
// (forward-sdk.md 8.1, PROTOCOL.md "Forwarding"): the node's ConfigApplier
// calls it with every snapshot, before the rest of the document.
//
//   - A snapshot without forwarding (anixops.nodeconfig/v1, or v2 without
//     the member) leaves forwarding as it is.
//   - generation 0: Control has no state for the node yet; keep what runs.
//   - An older generation is ignored; the same generation is compared by
//     state_hash, never by content: equal and applied is nothing to do,
//     another hash is a conflict and ignored.
//   - A newer generation is taken and persisted.
//
// It answers an error only when the document cannot be applied as a whole
// (a malformed member, another node's state): ConfigStatus applied false.
// No engine runs a hop on the Agent any more, so every hop the state holds
// goes in the report as a hop error.
func (c *Component) ApplySnapshot(_ context.Context, snapshot *agentv1pb.ConfigSnapshot) error {
	state, found, err := wire.StateFromNodeConfig(snapshot.GetFormat(), snapshot.GetConfigJson())
	if err != nil {
		return agentapi.InvalidConfig(err)
	}
	if !found {
		return nil
	}
	if ref := state.GetNodeRef(); ref != "" && ref != c.nodeRef {
		return agentapi.InvalidConfig(fmt.Errorf("the forwarding state is node %q's, not %q's", ref, c.nodeRef))
	}
	entry := c.logger.WithFields(log.Fields{"generation": state.GetGeneration(), "state_hash": state.GetStateHash(), "config_revision": snapshot.GetConfigRevision()})
	if state.GetGeneration() == 0 {
		entry.Debug("Control has no forwarding state for the node yet; keeping what runs")
		return nil
	}
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	c.mu.Lock()
	current := c.desired
	c.mu.Unlock()
	if current != nil {
		switch {
		case state.GetGeneration() < current.GetGeneration():
			entry.WithField("running_generation", current.GetGeneration()).Warn("Ignoring an older forwarding generation")
			return nil
		case state.GetGeneration() == current.GetGeneration() && state.GetStateHash() != current.GetStateHash():
			entry.WithField("running_state_hash", current.GetStateHash()).Error("Control sent the running forwarding generation with another state_hash; ignoring it")
			return nil
		case state.GetGeneration() == current.GetGeneration():
			return nil
		}
	}
	c.apply(state)
	return nil
}

// apply takes state: every hop it holds is a hop error (no engine runs it
// on the Agent), and its vantage probes run from now on. It records the
// outcome and persists the state. The caller holds applyMu.
func (c *Component) apply(state *forwardv1.NodeForwardState) {
	entry := c.logger.WithFields(log.Fields{"generation": state.GetGeneration(), "state_hash": state.GetStateHash()})
	hopErrors := removedHopErrors(state)
	now := c.opts.Now()
	c.mu.Lock()
	c.desired, c.hopErrors = state, hopErrors
	c.reportPending = true
	c.mu.Unlock()
	if err := c.store.save(state, true, now); err != nil {
		entry.WithError(err).Warn("Could not persist the forwarding state; a restart while Control is unreachable starts without it")
	}
	fields := log.Fields{"hops": len(state.GetHops()), "vantage_probes": len(state.GetVantageProbes()), "hop_errors": len(hopErrors)}
	if len(hopErrors) == 0 {
		entry.WithFields(fields).Info("Took the forwarding state")
	} else {
		entry.WithFields(fields).Warn("The forwarding state holds hops no engine on the Agent runs")
	}
	wake(c.reportWake)
}

// removedHopErrors answers one hop error per hop of state, sorted.
func removedHopErrors(state *forwardv1.NodeForwardState) []*forwardv1.HopError {
	type hopKey struct {
		route string
		hop   uint32
	}
	seen := map[hopKey]bool{}
	var out []*forwardv1.HopError
	for _, hop := range state.GetHops() {
		key := hopKey{hop.GetRouteId(), hop.GetHopIndex()}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, &forwardv1.HopError{
			RouteId: hop.GetRouteId(), HopIndex: hop.GetHopIndex(), Engine: hop.GetEngine(),
			Message: removedEngineMessage(hop.GetEngine()),
		})
	}
	sortHopErrors(out)
	return out
}

func sortHopErrors(errs []*forwardv1.HopError) {
	sort.SliceStable(errs, func(i, j int) bool {
		a, b := errs[i], errs[j]
		if a.GetRouteId() != b.GetRouteId() {
			return a.GetRouteId() < b.GetRouteId()
		}
		return a.GetHopIndex() < b.GetHopIndex()
	})
}

// logChange logs through f when the value of what changed since the last
// call, so a condition repeating every tick is logged once.
func (c *Component) logChange(what, value string, f func(*log.Entry)) {
	c.mu.Lock()
	old, seen := c.logged[what]
	c.logged[what] = value
	c.mu.Unlock()
	if (seen && old == value) || (!seen && value == "") || f == nil {
		return
	}
	f(c.logger)
}

// Status is the component's state for status output and tests.
type Status struct {
	Generation  uint64
	StateHash   string
	Applied     bool
	Hops        int
	HopErrors   int
	ReportsSent uint64
}

// Status answers the component's state.
func (c *Component) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Status{
		Generation: c.desired.GetGeneration(), StateHash: c.desired.GetStateHash(), Applied: c.desired != nil,
		Hops: len(c.desired.GetHops()), HopErrors: len(c.hopErrors), ReportsSent: c.reportsSent,
	}
}

// desiredState answers a copy of the desired state, nil without one.
func (c *Component) desiredState() *forwardv1.NodeForwardState {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.desired == nil {
		return nil
	}
	return proto.Clone(c.desired).(*forwardv1.NodeForwardState)
}

// Applier answers the node's ConfigApplier: every snapshot goes to
// ApplySnapshot, then, unless the forwarding member is malformed, to next.
// A forward node has nothing else the Agent runs (next nil); a proxy node's
// next is its controllers.
func (c *Component) Applier(next agentapi.ConfigApplier) agentapi.ConfigApplier {
	return applier{c: c, next: next}
}

type applier struct {
	c    *Component
	next agentapi.ConfigApplier
}

func (a applier) ApplyConfig(ctx context.Context, snapshot *agentv1pb.ConfigSnapshot) error {
	if err := a.c.ApplySnapshot(ctx, snapshot); err != nil {
		return err
	}
	if a.next == nil {
		return nil
	}
	return a.next.ApplyConfig(ctx, snapshot)
}
