package forward

import (
	"context"
	"errors"
	"sort"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"github.com/AnixOps/anix-control/sdk/forward/wire"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

// Reports (forward-sdk.md 8.2, PROTOCOL.md "Forwarding"): the node's
// NodeForwardReport as a PackageReport (wire.Report), every
// ReportInterval (60 s) and after an apply or a health change, at most one
// every ReportMinGap (10 s), while a session negotiated forward.v1. A
// report is the latest value only: counters are cumulative within a
// counter epoch, so a lost report loses nothing; the last counters of an
// epoch an apply ended (Retired) ride along for RetiredKeep.

// runReports sends the reports.
func (c *Component) runReports() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		c.mu.Lock()
		negotiated, pending, last := c.negotiated && c.sender != nil, c.reportPending, c.lastReport
		c.mu.Unlock()
		var wait time.Duration
		now := c.opts.Now()
		switch {
		case !negotiated:
			wait = time.Hour
		case last.IsZero():
			wait = 0
		case pending:
			wait = last.Add(c.opts.ReportMinGap).Sub(now)
		default:
			wait = last.Add(c.opts.ReportInterval).Sub(now)
		}
		if wait <= 0 {
			c.sendReport(c.ctx)
			continue
		}
		timer.Reset(wait)
		select {
		case <-c.ctx.Done():
			return
		case <-c.reportWake:
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}

// sendReport builds and sends one report.
func (c *Component) sendReport(ctx context.Context) {
	report := c.Report(ctx)
	now := c.opts.Now()
	c.mu.Lock()
	send := c.sender
	c.lastReport = now
	c.reportPending = false
	c.mu.Unlock()
	message, err := encodeReport(report)
	if err != nil {
		c.logChange("report", err.Error(), func(e *log.Entry) { e.WithError(err).Error("Could not encode the forward report") })
		return
	}
	if send == nil {
		return
	}
	if err := send(message); err != nil {
		if errors.Is(err, agentapi.ErrSessionGone) {
			// The session ended: send again once a session negotiates.
			c.mu.Lock()
			c.negotiated, c.reportPending = false, true
			c.mu.Unlock()
			return
		}
		c.logChange("report", err.Error(), func(e *log.Entry) { e.WithError(err).Warn("Could not send the forward report") })
		return
	}
	c.logChange("report", "", nil)
	c.mu.Lock()
	c.reportsSent++
	c.mu.Unlock()
}

// encodeReport answers the PackageReport of report, dropping the health
// entries and then the counters when it exceeds the payload cap (about 800
// hops of counters; chunking is deferred, forward-sdk.md 8.2).
func encodeReport(report *forwardv1.NodeForwardReport) (*agentv1pb.PackageReport, error) {
	message, err := wire.Report(report)
	if err == nil {
		return message, nil
	}
	trimmed := proto.Clone(report).(*forwardv1.NodeForwardReport)
	trimmed.Health = nil
	if message, err2 := wire.Report(trimmed); err2 == nil {
		return message, nil
	}
	trimmed.Counters = nil
	if message, err2 := wire.Report(trimmed); err2 == nil {
		return message, nil
	}
	return nil, err
}

// Report answers the node's report now: what the drivers observe (counters
// and their own health view, after the soft quotas), the health loop's
// view, the retired counters, the hop errors of the last apply, and the
// generation it runs.
func (c *Component) Report(ctx context.Context) *forwardv1.NodeForwardReport {
	observations := c.observeAll(ctx)
	plans := c.plans()
	health := c.healthEntries(plans)
	now := c.opts.Now()
	c.mu.Lock()
	desired, applied := c.desired, c.applied
	hopErrors := make([]*forwardv1.HopError, len(c.hopErrors))
	for i, e := range c.hopErrors {
		hopErrors[i] = proto.Clone(e).(*forwardv1.HopError)
	}
	c.mu.Unlock()
	report := &forwardv1.NodeForwardReport{NodeRef: c.nodeRef, Errors: hopErrors, ObservedAtUnixMs: now.UnixMilli()}
	if desired != nil {
		report.Generation, report.StateHash, report.Applied = desired.GetGeneration(), desired.GetStateHash(), applied
	} else {
		// No state from Control yet: what the drivers run, when they agree.
		var gen uint64
		var hash string
		agree, found := true, false
		for _, obs := range observations {
			if !obs.Applied {
				continue
			}
			if found && (obs.Generation != gen || obs.StateHash != hash) {
				agree = false
			}
			gen, hash, found = obs.Generation, obs.StateHash, true
		}
		if found && agree {
			report.Generation, report.StateHash, report.Applied = gen, hash, true
		}
	}

	counters := map[counterKey]*forwardv1.Counters{}
	add := func(cs []*forwardv1.Counters) {
		for _, cnt := range cs {
			if cnt == nil || cnt.GetCounterEpoch() == "" {
				continue
			}
			cnt = proto.Clone(cnt).(*forwardv1.Counters)
			cnt.NodeRef = c.nodeRef
			k := keyOfCounters(cnt)
			if old, ok := counters[k]; ok && total(old) >= total(cnt) {
				continue
			}
			counters[k] = cnt
		}
	}
	engines := make([]forwardv1.Engine, 0, len(observations))
	for engine := range observations {
		engines = append(engines, engine)
	}
	sort.Slice(engines, func(i, j int) bool { return engines[i] < engines[j] })
	for _, engine := range engines {
		add(observations[engine].Counters)
	}
	add(c.opts.Retired.take(c.opts.RetiredKeep))
	for _, cnt := range counters {
		report.Counters = append(report.Counters, cnt)
	}
	sort.Slice(report.Counters, func(i, j int) bool {
		a, b := report.Counters[i], report.Counters[j]
		if a.GetRouteId() != b.GetRouteId() {
			return a.GetRouteId() < b.GetRouteId()
		}
		if a.GetHopIndex() != b.GetHopIndex() {
			return a.GetHopIndex() < b.GetHopIndex()
		}
		return a.GetCounterEpoch() < b.GetCounterEpoch()
	})

	// The health loop is the source of truth; an engine's own view (gost
	// fail marking, none today) fills in upstreams the loop does not check.
	ours := map[upstreamKey]bool{}
	for _, h := range health {
		ours[upstreamKey{route: h.GetRouteId(), hop: h.GetHopIndex(), address: normalizeAddress(h.GetAddress()), port: h.GetPort()}] = true
	}
	for _, engine := range engines {
		for _, h := range observations[engine].Health {
			k := upstreamKey{route: h.GetRouteId(), hop: h.GetHopIndex(), address: normalizeAddress(h.GetAddress()), port: h.GetPort()}
			if !ours[k] {
				ours[k] = true
				health = append(health, proto.Clone(h).(*forwardv1.UpstreamHealth))
			}
		}
	}
	report.Health = health
	return report
}
