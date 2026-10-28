package forward

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"time"

	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	log "github.com/sirupsen/logrus"
)

// Vantage probes (L4, forward-sdk.md section 7.4). A node whose labels
// match a DNS binding's vantage selector gets probes in its desired state
// (NodeForwardState.vantage_probes): the published addresses of another
// route's entry nodes, dialled from this side of the network so Control can
// leave out of DNS an entry address the clients cannot reach.
//
//   - Only what the state names is dialled, and only global unicast
//     addresses (never loopback, private, link-local or multicast).
//   - Each probe is a TCP connect every interval_ms (default 30 s) with
//     timeout_ms (default 3 s); its state turns UNHEALTHY after
//     vantageThreshold failures in a row and HEALTHY after as many
//     successes, so one lost SYN changes nothing.
//   - Every report carries each probe's state (NodeForwardReport.vantage);
//     a state change asks for a report.

const (
	vantageThreshold      = 3
	defaultVantageEvery   = 30 * time.Second
	defaultVantageTimeout = 3 * time.Second
	maxVantageProbes      = 512
)

// vantageKey is one probe.
type vantageKey struct {
	binding uint64
	address string
	port    uint32
}

// vantageState is a probe's hysteresis.
type vantageState struct {
	probe     *forwardv1.VantageProbe
	state     forwardv1.HealthState
	failures  uint32
	successes uint32
	rtt       time.Duration
	checkedAt time.Time
	nextCheck time.Time
	inFlight  bool
}

// vantageTarget answers a probe's dial address, false for anything but a
// global unicast address and a port.
func vantageTarget(p *forwardv1.VantageProbe) (string, bool) {
	addr, err := netip.ParseAddr(p.GetAddress())
	if err != nil || p.GetPort() == 0 || p.GetPort() > 65535 {
		return "", false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.Zone() != "" {
		return "", false
	}
	return net.JoinHostPort(addr.String(), strconv.FormatUint(uint64(p.GetPort()), 10)), true
}

func vantageKeyOf(p *forwardv1.VantageProbe) vantageKey {
	return vantageKey{binding: p.GetBindingId(), address: normalizeAddress(p.GetAddress()), port: p.GetPort()}
}

// scheduleVantage starts the vantage probes that are due and forgets those
// the state no longer has.
func (c *Component) scheduleVantage(now time.Time) {
	type due struct {
		key     vantageKey
		address string
		timeout time.Duration
	}
	var start []due
	c.mu.Lock()
	probes := c.desired.GetVantageProbes()
	if len(probes) > maxVantageProbes {
		probes = probes[:maxVantageProbes]
	}
	present := map[vantageKey]bool{}
	for _, p := range probes {
		address, ok := vantageTarget(p)
		if !ok {
			continue
		}
		k := vantageKeyOf(p)
		present[k] = true
		st := c.vantage[k]
		if st == nil {
			st = &vantageState{state: forwardv1.HealthState_HEALTH_STATE_UNSPECIFIED}
			c.vantage[k] = st
		}
		st.probe = p
		if st.inFlight || now.Before(st.nextCheck) {
			continue
		}
		st.inFlight = true
		timeout := time.Duration(p.GetTimeoutMs()) * time.Millisecond
		if timeout <= 0 {
			timeout = defaultVantageTimeout
		}
		start = append(start, due{key: k, address: address, timeout: timeout})
	}
	for k := range c.vantage {
		if !present[k] {
			delete(c.vantage, k)
		}
	}
	c.mu.Unlock()
	for _, d := range start {
		select {
		case c.probes <- struct{}{}:
		case <-c.ctx.Done():
			return
		}
		go func() {
			defer func() { <-c.probes }()
			c.probeVantage(d.key, d.address, d.timeout)
		}()
	}
}

// probeVantage dials one vantage target and records the outcome.
func (c *Component) probeVantage(key vantageKey, address string, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(c.ctx, timeout)
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
	st := c.vantage[key]
	if st == nil {
		c.mu.Unlock()
		return
	}
	before := st.state
	every := time.Duration(st.probe.GetIntervalMs()) * time.Millisecond
	if every <= 0 {
		every = defaultVantageEvery
	}
	st.inFlight, st.checkedAt, st.nextCheck = false, now, now.Add(every)
	if err == nil {
		st.successes, st.failures, st.rtt = st.successes+1, 0, rtt
		if st.successes >= vantageThreshold {
			st.state = forwardv1.HealthState_HEALTH_STATE_HEALTHY
		}
	} else {
		st.failures, st.successes, st.rtt = st.failures+1, 0, 0
		if st.failures >= vantageThreshold {
			st.state = forwardv1.HealthState_HEALTH_STATE_UNHEALTHY
		}
	}
	after := st.state
	c.mu.Unlock()
	if before != after {
		entry := c.logger.WithFields(log.Fields{"binding_id": key.binding, "target": address, "state": after.String()})
		if err != nil {
			entry = entry.WithError(err)
		}
		entry.Info("Vantage probe changed state")
		c.mu.Lock()
		c.reportPending = true
		c.mu.Unlock()
		wake(c.reportWake)
	}
}

// vantageResults answers the judged probes for a report, sorted.
func (c *Component) vantageResults() []*forwardv1.VantageResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*forwardv1.VantageResult
	for _, st := range c.vantage {
		if st.probe == nil || st.state == forwardv1.HealthState_HEALTH_STATE_UNSPECIFIED {
			continue
		}
		out = append(out, &forwardv1.VantageResult{
			BindingId: st.probe.GetBindingId(), RouteId: st.probe.GetRouteId(), NodeRef: st.probe.GetNodeRef(),
			Address: st.probe.GetAddress(), Port: st.probe.GetPort(), State: st.state,
			ConsecutiveFailures: st.failures, RttUs: uint32(min(st.rtt.Microseconds(), int64(^uint32(0)))), // #nosec G115 -- clamped to uint32.
			CheckedAtUnixMs: st.checkedAt.UnixMilli(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.GetBindingId() != b.GetBindingId() {
			return a.GetBindingId() < b.GetBindingId()
		}
		if a.GetAddress() != b.GetAddress() {
			return a.GetAddress() < b.GetAddress()
		}
		return a.GetPort() < b.GetPort()
	})
	return out
}
