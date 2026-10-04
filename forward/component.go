package forward

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"github.com/AnixOps/anix-control/sdk/forward/driver"
	"github.com/AnixOps/anix-control/sdk/forward/leastconn"
	"github.com/AnixOps/anix-control/sdk/forward/model"
	"github.com/AnixOps/anix-control/sdk/forward/wire"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

// Cadences (forward-sdk.md sections 7 and 8; owner decision H21).
const (
	// DefaultReportInterval: a report every 60 s ...
	DefaultReportInterval = 60 * time.Second
	// DefaultReportMinGap: ... and after an apply or a health change, at
	// most one every 10 s.
	DefaultReportMinGap = 10 * time.Second
	// DefaultReconcileInterval is how often the component observes the
	// drivers, enforces soft quotas and re-asserts the health loop's
	// rotation (after a changing apply or a gost restart put every
	// upstream back). It is the default health-check interval, so a soft
	// quota holds within one check interval.
	DefaultReconcileInterval = model.DefaultHealthInterval
	// DefaultRetryInterval spaces out new attempts to apply a state an
	// earlier apply could not: Control does not send a snapshot again for
	// the revision the Agent reported, so the component retries itself.
	DefaultRetryInterval = 30 * time.Second
	// defaultHealthTick is the health scheduler's resolution: each
	// upstream is probed every health.interval_ms of its hop.
	defaultHealthTick = time.Second
	// maxProbes bounds the health probes in flight.
	maxProbes = 32
	// applyTimeout and observeTimeout bound one apply and one observation
	// of every driver.
	applyTimeout   = 2 * time.Minute
	observeTimeout = 20 * time.Second
)

// Options configure a Component.
type Options struct {
	// Node is the node the Agent speaks for: its state's node_ref and its
	// reports' (forward-41, proxy-7).
	Node agentcontrol.AgentNode
	// Registry holds the drivers the host can run, already probed
	// (nftables.Probe, gost.Probe). Engines the host lacks are not
	// registered: their hops come back as hop errors (no driver).
	Registry *driver.Registry
	// Unavailable lists the engines the host lacks with the reason, for
	// the Hello's NodeCapabilities.
	Unavailable []*forwardv1.EngineCapabilities
	// Retired is the buffer the drivers' WithRetiredCounters hook fills;
	// nil for drivers without one.
	Retired *Retired
	// Sources supply live connections for LEAST_CONN re-weighting per
	// engine, besides drivers that are a leastconn.Source themselves
	// (gost, fake): the conntrack source for nftables.
	Sources map[forwardv1.Engine]leastconn.Source
	// StateDir holds the persisted state (absolute; the Agent's own state
	// directory, never gost's).
	StateDir string
	// AgentVersion goes into NodeCapabilities.
	AgentVersion string
	// Host is the rest of NodeCapabilities; ProbeHost reads it.
	Host HostInfo
	// LinkCertificates tells whether the gost driver was built with the
	// node's forward link certificate (H28). Without it gost carries RAW
	// links only, and a hop with an encrypted link is reported with a hop
	// error that says so.
	LinkCertificates bool
	// Links keeps the link certificate (IssueLinkCertificate,
	// GetLinkTrustBundle); nil leaves the files to someone else.
	Links *LinkOptions
	// Dial probes upstreams (TCP connect, and UDP for the forward
	// diagnostic checks); nil uses net.Dialer.
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
	ReportInterval    time.Duration
	ReportMinGap      time.Duration
	ReconcileInterval time.Duration
	ReweightInterval  time.Duration
	RetryInterval     time.Duration
	// HealthTick is the health scheduler's resolution (1 s).
	HealthTick  time.Duration
	RetiredKeep time.Duration
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
	// before the first; applied tells whether every engine runs it.
	desired   *forwardv1.NodeForwardState
	applied   bool
	hopErrors []*forwardv1.HopError
	retryAt   time.Time
	// Reports.
	sender        func(*agentv1pb.PackageReport) error
	negotiated    bool
	reportPending bool
	lastReport    time.Time
	reportsSent   uint64
	// Health loop: per upstream of each hop, the breaker; per hop, the
	// selection the loop keeps in rotation and the rotation last observed.
	health    map[upstreamKey]*upstreamState
	selection map[driver.HopKey][]driver.Upstream
	rotation  map[driver.HopKey][]driver.Upstream
	logged    map[string]string

	reportWake    chan struct{}
	reconcileWake chan struct{}
	probes        chan struct{}

	// Forward link certificates (linkcert.go).
	links linkState
}

// New answers a component. Start it before the Agent connects to Control.
func New(opts Options) (*Component, error) {
	if !opts.Node.Valid() {
		return nil, fmt.Errorf("forward: invalid node %q", opts.Node.String())
	}
	if opts.Registry == nil {
		return nil, errors.New("forward: a driver registry is required")
	}
	if opts.ReportInterval <= 0 {
		opts.ReportInterval = DefaultReportInterval
	}
	if opts.ReportMinGap <= 0 {
		opts.ReportMinGap = DefaultReportMinGap
	}
	if opts.ReconcileInterval <= 0 {
		opts.ReconcileInterval = DefaultReconcileInterval
	}
	if opts.ReweightInterval <= 0 {
		opts.ReweightInterval = model.DefaultLeastConnReweight
	}
	if opts.RetryInterval <= 0 {
		opts.RetryInterval = DefaultRetryInterval
	}
	if opts.HealthTick <= 0 {
		opts.HealthTick = defaultHealthTick
	}
	if opts.RetiredKeep <= 0 {
		opts.RetiredKeep = DefaultRetiredKeep
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Dial == nil {
		var dialer net.Dialer
		opts.Dial = dialer.DialContext
	}
	if opts.Retired == nil {
		opts.Retired = NewRetired()
	}
	nodeRef := opts.Node.String()
	store, err := openStateStore(opts.StateDir, nodeRef)
	if err != nil {
		return nil, err
	}
	c := &Component{
		opts: opts, nodeRef: nodeRef, store: store,
		logger:    log.WithFields(log.Fields{"component": "forward", "node": nodeRef}),
		health:    map[upstreamKey]*upstreamState{},
		selection: map[driver.HopKey][]driver.Upstream{},
		rotation:  map[driver.HopKey][]driver.Upstream{},
		logged:    map[string]string{},
		// Buffered: a wake never blocks and never gets lost.
		reportWake:    make(chan struct{}, 1),
		reconcileWake: make(chan struct{}, 1),
		probes:        make(chan struct{}, maxProbes),
		links:         linkState{wake: make(chan struct{}, 1)},
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	return c, nil
}

// NodeRef answers the node's reference (forward-41).
func (c *Component) NodeRef() string { return c.nodeRef }

// Start re-applies the persisted state, before the Agent connects to
// Control (nftables rules do not survive a reboot; forwarding goes on
// while Control is down), then runs the health, report and re-weighting
// loops until Close.
func (c *Component) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return errors.New("forward: component already started")
	}
	c.started = true
	c.mu.Unlock()
	state, applied, err := c.store.load()
	if err != nil {
		c.logger.WithError(err).Warn("Could not use the persisted forwarding state; waiting for Control's")
	}
	if state != nil {
		c.mu.Lock()
		c.desired, c.applied = state, applied
		c.mu.Unlock()
	}
	if c.opts.Links != nil {
		c.startLinks()
	}
	if state != nil {
		c.logger.WithFields(log.Fields{"generation": state.GetGeneration(), "hops": len(state.GetHops())}).
			Info("Re-applying the persisted forwarding state before connecting to Control")
		c.applyMu.Lock()
		c.apply(ctx, state)
		c.applyMu.Unlock()
	}
	c.wg.Add(3)
	go func() { defer c.wg.Done(); c.runHealth() }()
	go func() { defer c.wg.Done(); c.runReports() }()
	go func() { defer c.wg.Done(); c.runReweight() }()
	return nil
}

// Close stops the loops. Forwarding keeps running: nftables rules stay in
// the kernel and gost is a unit of its own (H20); nothing is removed.
func (c *Component) Close() {
	c.cancel()
	c.wg.Wait()
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
	if c.opts.Links != nil {
		// A HelloAck that lists forward.v1: Control issues link
		// certificates to the node now.
		c.links.mu.Lock()
		c.links.negotiated = negotiated
		if negotiated {
			c.links.issueAt = time.Time{}
		}
		c.links.mu.Unlock()
		wake(c.links.wake)
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
//   - A newer generation is applied (an empty state removes everything the
//     drivers own) and persisted.
//
// It answers an error only when the document cannot be applied as a whole
// (a malformed member, another node's state): ConfigStatus applied false.
// A hop a driver cannot run, or an engine whose Apply fails, goes in the
// report, and a failed apply is retried.
func (c *Component) ApplySnapshot(ctx context.Context, snapshot *agentv1pb.ConfigSnapshot) error {
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
	current, applied := c.desired, c.applied
	c.mu.Unlock()
	if current != nil {
		switch {
		case state.GetGeneration() < current.GetGeneration():
			entry.WithField("running_generation", current.GetGeneration()).Warn("Ignoring an older forwarding generation")
			return nil
		case state.GetGeneration() == current.GetGeneration() && state.GetStateHash() != current.GetStateHash():
			entry.WithField("running_state_hash", current.GetStateHash()).Error("Control sent the running forwarding generation with another state_hash; ignoring it")
			return nil
		case state.GetGeneration() == current.GetGeneration() && applied:
			return nil
		}
	}
	c.apply(ctx, state)
	return nil
}

// apply renders state with every driver, applies each engine's artifact,
// enforces soft quotas, records the outcome and persists the state. The
// caller holds applyMu.
func (c *Component) apply(parent context.Context, state *forwardv1.NodeForwardState) {
	ctx, cancel := context.WithTimeout(parent, applyTimeout)
	defer cancel()
	entry := c.logger.WithFields(log.Fields{"generation": state.GetGeneration(), "state_hash": state.GetStateHash()})
	allApplied, changed := true, false
	var hopErrors []*forwardv1.HopError
	artifacts, renderErrors, err := c.opts.Registry.Render(state)
	if err != nil {
		allApplied = false
		hopErrors = hopErrorsFor(state, nil, func(forwardv1.Engine) bool { return true }, fmt.Errorf("render: %w", err))
		entry.WithError(err).Error("Could not render the forwarding state")
	} else {
		failed := map[driver.HopKey]bool{}
		for _, he := range renderErrors {
			failed[he.Key] = true
			hopErrors = append(hopErrors, c.hopErrorProto(state, he))
		}
		engines := make([]forwardv1.Engine, 0, len(artifacts))
		for engine := range artifacts {
			engines = append(engines, engine)
		}
		slices.Sort(engines)
		for _, engine := range engines {
			d, _ := c.opts.Registry.Get(engine)
			result, err := d.Apply(ctx, artifacts[engine])
			if err != nil {
				allApplied = false
				hopErrors = append(hopErrors, hopErrorsFor(state, failed, func(e forwardv1.Engine) bool { return e == engine }, fmt.Errorf("apply: %w", err))...)
				entry.WithError(err).WithField("engine", engine.String()).Error("Could not apply the forwarding state")
				continue
			}
			changed = changed || result.Changed
		}
	}
	c.enforceQuotas(ctx)
	sortHopErrors(hopErrors)
	now := c.opts.Now()
	c.mu.Lock()
	c.desired, c.applied, c.hopErrors = state, allApplied, hopErrors
	if allApplied {
		c.retryAt = time.Time{}
	} else {
		c.retryAt = now.Add(c.opts.RetryInterval)
	}
	c.reportPending = true
	c.mu.Unlock()
	if err := c.store.save(state, allApplied, now); err != nil {
		entry.WithError(err).Warn("Could not persist the forwarding state; a restart while Control is unreachable starts without it")
	}
	fields := log.Fields{"hops": len(state.GetHops()), "changed": changed, "hop_errors": len(hopErrors)}
	if allApplied {
		entry.WithFields(fields).Info("Applied the forwarding state")
	} else {
		entry.WithFields(fields).Warn("The forwarding state is not fully applied; retrying")
	}
	wake(c.reportWake)
	wake(c.reconcileWake)
}

// hopErrorsFor answers err for every hop of state whose engine matches and
// that is not in skip.
func hopErrorsFor(state *forwardv1.NodeForwardState, skip map[driver.HopKey]bool, engine func(forwardv1.Engine) bool, err error) []*forwardv1.HopError {
	seen := map[driver.HopKey]bool{}
	var out []*forwardv1.HopError
	for _, hop := range state.GetHops() {
		key := driver.KeyOf(hop)
		if skip[key] || seen[key] || !engine(hop.GetEngine()) {
			continue
		}
		seen[key] = true
		out = append(out, (&driver.HopError{Key: key, Engine: hop.GetEngine(), Err: err}).ToProto())
	}
	return out
}

// hopErrorProto converts a render hop error, saying why when an encrypted
// gost link fails for want of the link certificate (H28).
func (c *Component) hopErrorProto(state *forwardv1.NodeForwardState, he *driver.HopError) *forwardv1.HopError {
	out := he.ToProto()
	if c.linksAvailable() || he.Engine != forwardv1.Engine_ENGINE_GOST || !errors.Is(he, driver.ErrUnsupported) {
		return out
	}
	for _, hop := range state.GetHops() {
		if driver.KeyOf(hop) == he.Key && encryptedLink(hop) {
			out.Message = truncate(out.Message+"; encrypted gost links need the node's forward link certificate, which Control's link CA issues once the node negotiated forward.v1 (H28); until then gost carries RAW links only", wire.MaxTextBytes)
			break
		}
	}
	return out
}

// encryptedLink tells whether a hop terminates or originates a link other
// than RAW.
func encryptedLink(hop *forwardv1.NodeHop) bool {
	secure := func(t *forwardv1.LinkTransport) bool {
		s := t.GetSecurity()
		return s != forwardv1.LinkSecurity_LINK_SECURITY_UNSPECIFIED && s != forwardv1.LinkSecurity_LINK_SECURITY_RAW
	}
	if secure(hop.GetIngress()) {
		return true
	}
	for _, u := range hop.GetUpstreams() {
		if secure(u.GetEgress()) {
			return true
		}
	}
	return false
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

// enforceQuotas calls every soft-quota driver's EnforceQuotas (gost): after
// every Observe and every Apply (driver.QuotaEnforcer).
func (c *Component) enforceQuotas(ctx context.Context) {
	for _, engine := range c.opts.Registry.Engines() {
		d, _ := c.opts.Registry.Get(engine)
		enforcer, ok := d.(driver.QuotaEnforcer)
		if !ok {
			continue
		}
		held, err := enforcer.EnforceQuotas(ctx)
		if err != nil {
			c.logChange("quota/"+engine.String(), err.Error(), func(e *log.Entry) { e.WithError(err).Warn("Could not enforce the soft quotas") })
			continue
		}
		c.logChange("quota/"+engine.String(), fmt.Sprint(held), func(e *log.Entry) {
			if len(held) > 0 {
				e.WithField("hops", held).Info("Hops hold new connections for their quota")
			}
		})
	}
}

// observeAll observes every driver and enforces the soft quotas after.
func (c *Component) observeAll(parent context.Context) map[forwardv1.Engine]driver.Observation {
	ctx, cancel := context.WithTimeout(parent, observeTimeout)
	defer cancel()
	out := map[forwardv1.Engine]driver.Observation{}
	for _, engine := range c.opts.Registry.Engines() {
		d, _ := c.opts.Registry.Get(engine)
		obs, err := d.Observe(ctx)
		if err != nil {
			c.logChange("observe/"+engine.String(), err.Error(), func(e *log.Entry) {
				e.WithError(err).WithField("engine", engine.String()).Warn("Could not observe the forwarding engine")
			})
			continue
		}
		c.logChange("observe/"+engine.String(), "", nil)
		out[engine] = obs
	}
	c.enforceQuotas(ctx)
	return out
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
		Generation: c.desired.GetGeneration(), StateHash: c.desired.GetStateHash(), Applied: c.desired != nil && c.applied,
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
