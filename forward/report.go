package forward

import (
	"context"
	"errors"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v5/api/agent"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"github.com/AnixOps/anix-control/sdk/forward/wire"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

// Reports (forward-sdk.md 8.2, PROTOCOL.md "Forwarding"): the node's
// NodeForwardReport as a PackageReport (wire.Report), every
// ReportInterval (60 s) and after an apply or a vantage change, at most one
// every ReportMinGap (10 s), while a session negotiated forward.v1. A
// report is the latest value only, so a lost report loses nothing.

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

// encodeReport answers the PackageReport of report, dropping the vantage
// results when it exceeds the payload cap.
func encodeReport(report *forwardv1.NodeForwardReport) (*agentv1pb.PackageReport, error) {
	message, err := wire.Report(report)
	if err == nil {
		return message, nil
	}
	trimmed := proto.Clone(report).(*forwardv1.NodeForwardReport)
	trimmed.Vantage = nil
	if message, err2 := wire.Report(trimmed); err2 == nil {
		return message, nil
	}
	return nil, err
}

// Report answers the node's report now: the generation it holds, the hop
// errors of its hops and the judged vantage probes.
func (c *Component) Report(context.Context) *forwardv1.NodeForwardReport {
	now := c.opts.Now()
	c.mu.Lock()
	desired := c.desired
	hopErrors := make([]*forwardv1.HopError, len(c.hopErrors))
	for i, e := range c.hopErrors {
		hopErrors[i] = proto.Clone(e).(*forwardv1.HopError)
	}
	c.mu.Unlock()
	report := &forwardv1.NodeForwardReport{NodeRef: c.nodeRef, Errors: hopErrors, ObservedAtUnixMs: now.UnixMilli()}
	if desired != nil {
		report.Generation, report.StateHash, report.Applied = desired.GetGeneration(), desired.GetStateHash(), true
	}
	report.Vantage = c.vantageResults()
	return report
}
