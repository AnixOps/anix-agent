package forward

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"github.com/AnixOps/anix-control/sdk/forward/driver"
	"github.com/AnixOps/anix-control/sdk/forward/leastconn"
	"github.com/AnixOps/anix-control/sdk/forward/model"
	log "github.com/sirupsen/logrus"
)

// The health loop (forward-sdk.md section 7.3, owner decision H21). Each
// node checks its own upstreams, so failover works while Control is down:
//
//   - every upstream of every hop is dialled (TCP connect) every
//     health.interval_ms (default 5 s) with timeout_ms (default 2 s);
//   - failure_threshold failures in a row (default 3) open its breaker: it
//     leaves rotation for open_ms (default 30 s), then one trial decides;
//     one success brings it back;
//   - a hop never loses its last upstream: when every one is open the
//     previous selection stays in rotation, and the health entries say so;
//   - the selection is asserted through the driver's SetUpstreams whenever
//     the rotation the driver reports differs (a changing Apply or a gost
//     restart puts every upstream back); an error is retried next round;
//   - both levels are the same loop: an entry or relay hop's upstreams are
//     the next hop's nodes (exit level), the last hop's are the targets
//     (target level).
//
// Not checked (always in rotation): hops with health.disabled, paused
// hops, UDP-only hops and QUIC links (a TCP connect says nothing about
// them; the UDP exchange of section 7.3 needs our node at the far end and
// is not implemented). Passive failures (a real connection's failed dial)
// are not counted: neither engine exposes them.

// udpOnly tells whether the link's listener holds a UDP port only, so that a
// TCP connect says nothing about it: gost's QUIC link and the anixops QUIC
// carrier (AUTO listens on TCP too).
func udpOnly(t *forwardv1.LinkTransport) bool {
	switch t.GetSecurity() {
	case forwardv1.LinkSecurity_LINK_SECURITY_QUIC:
		return true
	case forwardv1.LinkSecurity_LINK_SECURITY_ANIXOPS:
		return t.GetCarrier() == forwardv1.AnixOpsCarrier_ANIXOPS_CARRIER_QUIC
	}
	return false
}

// upstreamKey is one upstream of one hop.
type upstreamKey struct {
	route   string
	hop     uint32
	address string
	port    uint32
}

// upstreamState is an upstream's breaker.
type upstreamState struct {
	state     forwardv1.HealthState
	failures  uint32
	openUntil time.Time
	rtt       time.Duration
	checkedAt time.Time
	nextCheck time.Time
	inFlight  bool
}

// hopPlan is what the health loop needs of one hop of the desired state.
type hopPlan struct {
	key       driver.HopKey
	engine    forwardv1.Engine
	balance   forwardv1.BalanceStrategy
	upstreams []plannedUpstream
	interval  time.Duration
	timeout   time.Duration
	threshold uint32
	openFor   time.Duration
}

type plannedUpstream struct {
	up driver.Upstream // rendered weight, at least 1
	// priority orders the fallback when every upstream is open.
	priority uint32
	checked  bool
}

// plans answers the hops of the desired state.
func (c *Component) plans() []hopPlan {
	state := c.desiredState()
	var out []hopPlan
	for _, hop := range state.GetHops() {
		health := model.HealthCheck{
			Interval: time.Duration(hop.GetHealth().GetIntervalMs()) * time.Millisecond,
			Timeout:  time.Duration(hop.GetHealth().GetTimeoutMs()) * time.Millisecond,
		}.WithDefaults()
		breaker := model.CircuitBreaker{
			FailureThreshold: hop.GetCircuitBreaker().GetFailureThreshold(),
			OpenFor:          time.Duration(hop.GetCircuitBreaker().GetOpenMs()) * time.Millisecond,
		}.WithDefaults()
		p := hopPlan{
			key: driver.KeyOf(hop), engine: hop.GetEngine(), balance: hop.GetBalance(),
			interval: health.Interval, timeout: health.Timeout, threshold: breaker.FailureThreshold, openFor: breaker.OpenFor,
		}
		checks := !hop.GetHealth().GetDisabled() && !hop.GetPaused() && hop.GetListen().GetProtocol() != forwardv1.L4Protocol_L4_PROTOCOL_UDP
		for _, u := range hop.GetUpstreams() {
			p.upstreams = append(p.upstreams, plannedUpstream{
				up:       driver.Upstream{Address: u.GetAddress(), Port: u.GetPort(), Weight: max(u.GetWeight(), 1)},
				priority: u.GetPriority(),
				checked:  checks && !udpOnly(u.GetEgress()),
			})
		}
		out = append(out, p)
	}
	return out
}

func keyOf(p hopPlan, u driver.Upstream) upstreamKey {
	return upstreamKey{route: p.key.RouteID, hop: p.key.HopIndex, address: normalizeAddress(u.Address), port: u.Port}
}

func normalizeAddress(address string) string {
	if a, err := netip.ParseAddr(address); err == nil {
		return a.Unmap().String()
	}
	return strings.ToLower(address)
}

// runHealth schedules the probes every HealthTick, reconciles every
// ReconcileInterval and when woken (a probe changed a breaker, an apply),
// and retries a state an apply could not finish.
func (c *Component) runHealth() {
	ticker := time.NewTicker(c.opts.HealthTick)
	defer ticker.Stop()
	reconcileAt := time.Time{}
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		case <-c.reconcileWake:
			reconcileAt = time.Time{}
		}
		now := c.opts.Now()
		c.retryIfDue(now)
		plans := c.plans()
		c.scheduleProbes(plans, now)
		if reconcileAt.IsZero() || !now.Before(reconcileAt) {
			c.reconcile(c.ctx, plans)
			reconcileAt = now.Add(c.opts.ReconcileInterval)
		}
	}
}

// retryIfDue applies the desired state again when the last apply failed
// and the retry interval passed.
func (c *Component) retryIfDue(now time.Time) {
	c.mu.Lock()
	state, due := c.desired, c.desired != nil && !c.applied && !c.retryAt.IsZero() && !now.Before(c.retryAt)
	c.mu.Unlock()
	if !due || !c.applyMu.TryLock() {
		return
	}
	defer c.applyMu.Unlock()
	c.mu.Lock()
	still := c.desired == state && !c.applied
	c.mu.Unlock()
	if still {
		c.logger.WithField("generation", state.GetGeneration()).Info("Retrying the forwarding state")
		c.apply(c.ctx, state)
	}
}

// scheduleProbes starts the probes that are due and forgets upstreams the
// state no longer has.
func (c *Component) scheduleProbes(plans []hopPlan, now time.Time) {
	type probe struct {
		key     upstreamKey
		plan    hopPlan
		address string
	}
	var due []probe
	c.mu.Lock()
	present := map[upstreamKey]bool{}
	for _, p := range plans {
		for _, u := range p.upstreams {
			if !u.checked {
				continue
			}
			k := keyOf(p, u.up)
			present[k] = true
			st := c.health[k]
			if st == nil {
				st = &upstreamState{state: forwardv1.HealthState_HEALTH_STATE_UNSPECIFIED}
				c.health[k] = st
			}
			if st.inFlight || now.Before(st.nextCheck) {
				continue
			}
			if st.state == forwardv1.HealthState_HEALTH_STATE_CIRCUIT_OPEN && now.Before(st.openUntil) {
				st.nextCheck = st.openUntil
				continue
			}
			st.inFlight = true
			due = append(due, probe{key: k, plan: p, address: net.JoinHostPort(u.up.Address, strconv.FormatUint(uint64(u.up.Port), 10))})
		}
	}
	for k := range c.health {
		if !present[k] {
			delete(c.health, k)
		}
	}
	c.mu.Unlock()
	for _, pr := range due {
		select {
		case c.probes <- struct{}{}:
		case <-c.ctx.Done():
			return
		}
		go func() {
			defer func() { <-c.probes }()
			c.probe(pr.key, pr.plan, pr.address)
		}()
	}
}

// probe dials one upstream and records the outcome in its breaker.
func (c *Component) probe(key upstreamKey, p hopPlan, address string) {
	ctx, cancel := context.WithTimeout(c.ctx, p.timeout)
	start := time.Now()
	conn, err := c.opts.Dial(ctx, "tcp", address)
	rtt := time.Since(start)
	cancel()
	if conn != nil {
		_ = conn.Close()
	}
	if c.ctx.Err() != nil {
		return
	}
	now := c.opts.Now()
	c.mu.Lock()
	st := c.health[key]
	if st == nil {
		c.mu.Unlock()
		return
	}
	before := st.state
	st.inFlight = false
	st.checkedAt = now
	st.nextCheck = now.Add(p.interval)
	if err == nil {
		st.state, st.failures, st.openUntil, st.rtt = forwardv1.HealthState_HEALTH_STATE_HEALTHY, 0, time.Time{}, rtt
	} else {
		st.failures++
		st.rtt = 0
		if before == forwardv1.HealthState_HEALTH_STATE_CIRCUIT_OPEN || st.failures >= p.threshold {
			// Opened, or a half-open trial failed: skip it for open_ms.
			st.state, st.openUntil = forwardv1.HealthState_HEALTH_STATE_CIRCUIT_OPEN, now.Add(p.openFor)
			st.nextCheck = st.openUntil
		} else {
			st.state = forwardv1.HealthState_HEALTH_STATE_UNHEALTHY
		}
	}
	after := st.state
	c.mu.Unlock()
	if before != after {
		entry := c.logger.WithFields(log.Fields{"route_id": key.route, "hop_index": key.hop, "upstream": address, "state": after.String()})
		if err != nil {
			entry = entry.WithError(err)
		}
		if after == forwardv1.HealthState_HEALTH_STATE_HEALTHY {
			entry.Info("Forward upstream is healthy")
		} else {
			entry.Warn("Forward upstream failed its health check")
		}
		c.mu.Lock()
		c.reportPending = true
		c.mu.Unlock()
		wake(c.reportWake)
		wake(c.reconcileWake)
	}
}

// selectFor answers the upstreams p keeps in rotation: every upstream whose
// breaker is not open, else the previous selection, else the best-priority
// upstream (never none). The caller holds mu.
func (c *Component) selectFor(p hopPlan) []driver.Upstream {
	var sel []driver.Upstream
	for _, u := range p.upstreams {
		if u.checked {
			if st := c.health[keyOf(p, u.up)]; st != nil && st.state == forwardv1.HealthState_HEALTH_STATE_CIRCUIT_OPEN {
				continue
			}
		}
		sel = append(sel, u.up)
	}
	if len(sel) > 0 || len(p.upstreams) == 0 {
		return sel
	}
	rendered := map[string]driver.Upstream{}
	for _, u := range p.upstreams {
		rendered[upstreamID(u.up)] = u.up
	}
	for _, u := range c.selection[p.key] {
		if r, ok := rendered[upstreamID(u)]; ok {
			sel = append(sel, r)
		}
	}
	if len(sel) > 0 {
		return sel
	}
	best := p.upstreams[0]
	for _, u := range p.upstreams[1:] {
		if u.priority < best.priority {
			best = u
		}
	}
	return []driver.Upstream{best.up}
}

func upstreamID(u driver.Upstream) string {
	return normalizeAddress(u.Address) + "|" + strconv.FormatUint(uint64(u.Port), 10)
}

// sameUpstreams reports whether two selections hold the same upstreams,
// whatever their weights and order.
func sameUpstreams(a, b []driver.Upstream) bool {
	if len(a) != len(b) {
		return false
	}
	ka, kb := make([]string, len(a)), make([]string, len(b))
	for i := range a {
		ka[i], kb[i] = upstreamID(a[i]), upstreamID(b[i])
	}
	slices.Sort(ka)
	slices.Sort(kb)
	return slices.Equal(ka, kb)
}

// reconcile observes the drivers (enforcing the soft quotas), computes
// every hop's selection and asserts it where the driver's rotation
// differs.
func (c *Component) reconcile(ctx context.Context, plans []hopPlan) {
	observations := c.observeAll(ctx)
	rotations := map[driver.HopKey][]driver.Upstream{}
	for _, obs := range observations {
		for _, r := range obs.Rotation {
			rotations[driver.HopKey{RouteID: r.RouteID, HopIndex: r.HopIndex}] = r.Active
		}
	}
	selections := map[driver.HopKey][]driver.Upstream{}
	c.mu.Lock()
	for _, p := range plans {
		sel := c.selectFor(p)
		if len(p.upstreams) > 0 && len(sel) > 0 {
			allOpen := true
			for _, u := range p.upstreams {
				st := c.health[keyOf(p, u.up)]
				if !u.checked || st == nil || st.state != forwardv1.HealthState_HEALTH_STATE_CIRCUIT_OPEN {
					allOpen = false
					break
				}
			}
			if allOpen && !sameUpstreams(sel, c.selection[p.key]) {
				c.logger.WithFields(log.Fields{"route_id": p.key.RouteID, "hop_index": p.key.HopIndex, "kept": upstreamID(sel[0])}).
					Warn("Every upstream of the hop is down; keeping the last one in rotation")
			}
		}
		selections[p.key] = sel
	}
	c.selection = selections
	c.rotation = rotations
	c.mu.Unlock()

	for _, p := range plans {
		rotation, applied := rotations[p.key]
		sel := selections[p.key]
		if !applied || len(sel) == 0 || sameUpstreams(sel, rotation) {
			continue
		}
		d, ok := c.opts.Registry.Get(p.engine)
		if !ok {
			continue
		}
		what := "rotation/" + p.key.String()
		var err error
		if p.balance == forwardv1.BalanceStrategy_BALANCE_STRATEGY_LEAST_CONN {
			err = c.reweightHop(ctx, d, p, sel, nil)
		} else {
			err = d.SetUpstreams(ctx, p.key.RouteID, p.key.HopIndex, renderedWeights(sel))
		}
		if err != nil {
			// gost down, a hop the driver does not run yet: next round.
			c.logChange(what, err.Error(), func(e *log.Entry) {
				e.WithError(err).WithField("hop", p.key.String()).Warn("Could not put the healthy upstreams in rotation; retrying")
			})
			continue
		}
		c.logChange(what, "", nil)
		c.logger.WithFields(log.Fields{"hop": p.key.String(), "upstreams": len(sel), "rendered": len(p.upstreams)}).Info("Asserted the forward hop's rotation")
	}
}

// renderedWeights selects ups with their rendered weights (weight 0).
func renderedWeights(ups []driver.Upstream) []driver.Upstream {
	out := slices.Clone(ups)
	for i := range out {
		out[i].Weight = 0
	}
	return out
}

// source answers the live-connection source of an engine, nil without.
func (c *Component) source(engine forwardv1.Engine, d driver.Driver) leastconn.Source {
	if s, ok := c.opts.Sources[engine]; ok && s != nil {
		return s
	}
	if s, ok := d.(leastconn.Source); ok {
		return s
	}
	return nil
}

// reweightHop puts sel in rotation with least-connections weights (L1),
// or with the rendered weights when the engine has no connection source.
func (c *Component) reweightHop(ctx context.Context, d driver.Driver, p hopPlan, sel, rotation []driver.Upstream) error {
	src := c.source(p.engine, d)
	if src == nil {
		if rotation != nil {
			return nil
		}
		return d.SetUpstreams(ctx, p.key.RouteID, p.key.HopIndex, renderedWeights(sel))
	}
	r := leastconn.Reweighter{Source: src, Setter: d}
	err := r.Tick(ctx, []leastconn.Hop{{RouteID: p.key.RouteID, HopIndex: p.key.HopIndex, Upstreams: sel, Rotation: rotation}})
	if err != nil && rotation == nil {
		// The source failed: at least the healthy set, weighted random.
		if setErr := d.SetUpstreams(ctx, p.key.RouteID, p.key.HopIndex, renderedWeights(sel)); setErr != nil {
			return fmt.Errorf("%w; %w", err, setErr)
		}
		return nil
	}
	return err
}

// runReweight re-weights the LEAST_CONN hops every ReweightInterval (10 s,
// H21) from their live connections, over the upstreams the health loop
// keeps in rotation.
func (c *Component) runReweight() {
	ticker := time.NewTicker(c.opts.ReweightInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		}
		c.reweightAll(c.ctx)
	}
}

func (c *Component) reweightAll(ctx context.Context) {
	plans := c.plans()
	byEngine := map[forwardv1.Engine][]leastconn.Hop{}
	c.mu.Lock()
	for _, p := range plans {
		if p.balance != forwardv1.BalanceStrategy_BALANCE_STRATEGY_LEAST_CONN {
			continue
		}
		rotation, applied := c.rotation[p.key]
		sel := c.selection[p.key]
		if !applied || len(sel) == 0 || !sameUpstreams(sel, rotation) {
			// Not applied yet, or the next reconcile changes its set.
			continue
		}
		byEngine[p.engine] = append(byEngine[p.engine], leastconn.Hop{RouteID: p.key.RouteID, HopIndex: p.key.HopIndex, Upstreams: slices.Clone(sel), Rotation: slices.Clone(rotation)})
	}
	c.mu.Unlock()
	for engine, hops := range byEngine {
		d, ok := c.opts.Registry.Get(engine)
		if !ok {
			continue
		}
		src := c.source(engine, d)
		if src == nil {
			continue
		}
		err := leastconn.Reweighter{Source: src, Setter: d}.Tick(ctx, hops)
		value := ""
		if err != nil {
			value = err.Error()
		}
		c.logChange("leastconn/"+engine.String(), value, func(e *log.Entry) {
			if err != nil {
				e.WithError(err).Warn("Could not re-weight the least-connections hops")
			}
		})
	}
}

// healthEntries answers the health loop's view of every checked upstream,
// for the report.
func (c *Component) healthEntries(plans []hopPlan) []*forwardv1.UpstreamHealth {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*forwardv1.UpstreamHealth
	for _, p := range plans {
		for _, u := range p.upstreams {
			st := c.health[keyOf(p, u.up)]
			if !u.checked || st == nil || st.checkedAt.IsZero() {
				continue
			}
			h := &forwardv1.UpstreamHealth{
				RouteId: p.key.RouteID, HopIndex: p.key.HopIndex, Address: u.up.Address, Port: u.up.Port,
				State: st.state, ConsecutiveFailures: st.failures, CheckedAtUnixMs: st.checkedAt.UnixMilli(),
				RttUs: uint32(min(st.rtt.Microseconds(), int64(^uint32(0)))), // #nosec G115 -- bounded
			}
			if !st.openUntil.IsZero() {
				h.CircuitOpenUntilUnixMs = st.openUntil.UnixMilli()
			}
			out = append(out, h)
		}
	}
	return out
}
