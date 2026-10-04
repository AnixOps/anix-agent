package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AnixOps/anix-agent/v4/api/agent/spool"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

// Reports on the stream (reports.v1; PROTOCOL.md, "Reports") and package
// reports (package-reports.v1). Traffic and log batches carry a batch id,
// node:proxy-<id>:<boot id>:<sequence>, kept when resent. Each is written to
// the on-disk spool before it counts as reported, sent on the stream in
// order, resent on the stream (never over a legacy transport) until Control
// answers its ReportAck, and dropped from the spool on any ReportAck:
// applied, recorded before, or refused for good. Control sends no ReportAck
// for a batch it cannot record for now; the Agent resends it after
// reportAckTimeout. An Agent that lists reports.v1 with the transient_ack
// attribute gets report_unavailable instead: the batch stays and is sent
// again not before retry_after_ms. NodeStatus and PackageReport are the latest value only:
// never spooled or resent.

// Report spool and cadence defaults.
const (
	DefaultTrafficSpoolBytes = 64 << 20
	DefaultLogsSpoolBytes    = 16 << 20
	DefaultSpoolMaxAge       = 72 * time.Hour
	DefaultStatusInterval    = time.Minute
	// DefaultPackageReportInterval is how often the latest package
	// observations are sent; well inside Control's 25-minute staleness
	// of a systemd.services report.
	DefaultPackageReportInterval = 5 * time.Minute
)

var (
	// reportAckTimeout is how long a sent batch waits for its ReportAck
	// before it is sent again on the session (a variable for tests).
	reportAckTimeout = 30 * time.Second
	// reportWindow bounds the batches awaiting a ReportAck on a session.
	reportWindow = 16
)

// Heartbeat metric keys of the reports.
const (
	MetricReportSpoolBatches = "agent_dataplane_report_spool_batches"
	MetricReportSpoolBytes   = "agent_dataplane_report_spool_bytes"
	// MetricReportSpoolDropped counts batches the spool dropped at its
	// size, age or count bound since the Agent started.
	MetricReportSpoolDropped = "agent_dataplane_report_spool_dropped_total"
	MetricReportsAcked       = "agent_dataplane_reports_acked_total"
	MetricReportsRefused     = "agent_dataplane_reports_refused_total"
	// MetricReportsDeferred counts report_unavailable answers.
	MetricReportsDeferred = "agent_dataplane_reports_deferred_total"
)

// ReportsConfig turns on reports.v1.
type ReportsConfig struct {
	// TrafficMaxBytes and LogsMaxBytes bound the two spools; defaults
	// DefaultTrafficSpoolBytes and DefaultLogsSpoolBytes. Logs have their
	// own spool so they never push traffic out.
	TrafficMaxBytes int64
	LogsMaxBytes    int64
	// MaxAge drops spooled batches older than it; default
	// DefaultSpoolMaxAge, at most spool.MaxRetention (Control remembers a
	// batch id for 7 days).
	MaxAge time.Duration
	// Status returns the node's status, sent every StatusInterval (default
	// DefaultStatusInterval) and at each session start.
	Status         func(context.Context) (*agentv1pb.NodeStatus, error)
	StatusInterval time.Duration
}

// PackageReportsConfig turns on package-reports.v1.
type PackageReportsConfig struct {
	// Collect returns the latest observation of each plugin package and
	// kind; each is sent once per session and observation.
	Collect func(context.Context) ([]*agentv1pb.PackageReport, error)
	// Interval defaults to DefaultPackageReportInterval.
	Interval time.Duration
}

// ReportsStatus describes the reports for status output.
type ReportsStatus struct {
	Spooled  int         `json:"spooled"`
	Bytes    int64       `json:"bytes"`
	Dropped  spool.Drops `json:"dropped"`
	Acked    uint64      `json:"acked"`
	Refused  uint64      `json:"refused"`
	InFlight int         `json:"in_flight"`
}

// reportsState is the reports part of the data plane.
type reportsState struct {
	bootID string
	seq    atomic.Uint64
	wake   chan struct{}

	traffic *spool.Spool
	logs    *spool.Spool

	mu       sync.Mutex
	session  string
	inflight map[string]time.Time
	// notBefore holds batches Control answered with report_unavailable:
	// they are sent again not before then.
	notBefore map[string]time.Time
	statusAt  time.Time
	// statusNow asks for a status at once (a runtime health change).
	statusNow   bool
	packageAt   time.Time
	packageSent map[string]int64
	pending     bool

	acked, duplicates, refused, deferred atomic.Uint64
}

// openReports opens the spools under the state directory.
func (d *DataPlane) openReports() error {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	d.reports.bootID = hex.EncodeToString(random)
	d.reports.wake = make(chan struct{}, 1)
	d.reports.inflight = map[string]time.Time{}
	d.reports.notBefore = map[string]time.Time{}
	d.reports.packageSent = map[string]int64{}
	config := d.config.Reports
	if config == nil {
		return nil
	}
	if config.TrafficMaxBytes <= 0 {
		config.TrafficMaxBytes = DefaultTrafficSpoolBytes
	}
	if config.LogsMaxBytes <= 0 {
		config.LogsMaxBytes = DefaultLogsSpoolBytes
	}
	if config.MaxAge <= 0 {
		config.MaxAge = DefaultSpoolMaxAge
	}
	if config.StatusInterval <= 0 {
		config.StatusInterval = DefaultStatusInterval
	}
	var err error
	root := filepath.Join(d.config.State.Dir(), "spool")
	if d.reports.traffic, err = spool.Open(filepath.Join(root, "traffic"), spool.Limits{MaxBytes: config.TrafficMaxBytes, MaxAge: config.MaxAge}, d.now); err != nil {
		return fmt.Errorf("traffic report spool: %w", err)
	}
	if d.reports.logs, err = spool.Open(filepath.Join(root, "logs"), spool.Limits{MaxBytes: config.LogsMaxBytes, MaxAge: config.MaxAge}, d.now); err != nil {
		return fmt.Errorf("log report spool: %w", err)
	}
	if count, bytes, _ := d.spoolStats(); count > 0 {
		d.logger().WithFields(log.Fields{"batches": count, "bytes": bytes}).Info("Report batches wait in the spool for the Agent control stream")
	}
	return nil
}

func (d *DataPlane) signalReports() {
	select {
	case d.reports.wake <- struct{}{}:
	default:
	}
}

// nextBatchID is node:proxy-<id>:<boot id>:<sequence> (at most 128 bytes).
func (d *DataPlane) nextBatchID() string {
	return "node:" + d.client.config.NodeKind + "-" + strconv.Itoa(d.client.config.NodeID) + ":" +
		d.reports.bootID + ":" + strconv.FormatUint(d.reports.seq.Add(1), 10)
}

// ErrReportsOff means the data plane has no reports.v1.
var ErrReportsOff = errors.New("agent data plane: reports are not configured")

// SubmitTraffic stores a traffic report in the spool, under a new batch id,
// and sends it when the stream carries reports.v1. Once it returns nil the
// report belongs to the stream: it is never resent over a legacy transport.
func (d *DataPlane) SubmitTraffic(report *agentv1pb.TrafficReport) error {
	if d.reports.traffic == nil {
		return ErrReportsOff
	}
	report = proto.Clone(report).(*agentv1pb.TrafficReport)
	report.BatchId = d.nextBatchID()
	return d.submit(d.reports.traffic, &agentv1pb.AgentToControl{Payload: &agentv1pb.AgentToControl_Traffic{Traffic: report}})
}

// SubmitLogs stores a log batch in the spool, as SubmitTraffic.
func (d *DataPlane) SubmitLogs(batch *agentv1pb.LogBatch) error {
	if d.reports.logs == nil {
		return ErrReportsOff
	}
	batch = proto.Clone(batch).(*agentv1pb.LogBatch)
	batch.BatchId = d.nextBatchID()
	return d.submit(d.reports.logs, &agentv1pb.AgentToControl{Payload: &agentv1pb.AgentToControl_Logs{Logs: batch}})
}

func (d *DataPlane) submit(target *spool.Spool, message *agentv1pb.AgentToControl) error {
	message.NodeId = uint32(d.client.config.NodeID) // #nosec G115 -- node IDs are uint32 on the wire.
	message.SentAtUnixMs = d.now().UnixMilli()
	if err := target.Append(message); err != nil {
		return err
	}
	d.signalReports()
	return nil
}

// receiveReportAck takes a ReportAck from the session's receive loop:
// every answer drops the batch from the spool, but report_unavailable,
// which keeps it for a resend after retry_after_ms.
func (d *DataPlane) receiveReportAck(sessionID string, ack *agentv1pb.ReportAck) {
	if ack == nil || ack.GetBatchId() == "" {
		return
	}
	id := ack.GetBatchId()
	code := ack.GetErrorCode()
	if !ack.GetApplied() && ack.GetError() == "" && code == agentcontrol.ReportErrorCodeUnavailable {
		retry := time.Duration(ack.GetRetryAfterMs()) * time.Millisecond
		if retry <= 0 {
			retry = reportAckTimeout
		}
		d.reports.deferred.Add(1)
		d.reports.mu.Lock()
		delete(d.reports.inflight, id)
		d.reports.notBefore[id] = d.now().Add(retry)
		d.reports.mu.Unlock()
		d.logger().WithFields(log.Fields{"batch_id": id, "error_code": code, "retry_in": retry.String(), "session_id": sessionID}).
			Info("Control could not record a report batch now; it stays in the spool")
		d.signalReports()
		return
	}
	removed := false
	if d.reports.traffic != nil && d.reports.traffic.Remove(id) {
		removed = true
	} else if d.reports.logs != nil && d.reports.logs.Remove(id) {
		removed = true
	}
	d.reports.mu.Lock()
	delete(d.reports.inflight, id)
	delete(d.reports.notBefore, id)
	d.reports.mu.Unlock()
	switch {
	case ack.GetApplied():
		d.reports.acked.Add(1)
	case ack.GetError() == "" && code == "":
		d.reports.duplicates.Add(1)
		d.reports.acked.Add(1)
	default:
		// A refusal, also one with only a code this Agent does not know.
		d.reports.refused.Add(1)
		d.logger().WithFields(log.Fields{"batch_id": id, "error": ack.GetError(), "error_code": code, "session_id": sessionID}).
			Warn("Control refused a report batch for good; dropping it")
	}
	if removed {
		d.signalReports()
	}
}

// StatusChanged asks for a NodeStatus at once, outside the status
// interval: the runtime health changed. The status carries the current
// system usage too, since Control writes both from one NodeStatus.
func (d *DataPlane) StatusChanged() {
	if d.config.Reports == nil {
		return
	}
	d.reports.mu.Lock()
	d.reports.statusNow = true
	d.reports.mu.Unlock()
	d.signalReports()
}

// SendStatus sends the node's status on the stream; ErrSessionGone when
// the stream does not carry reports.v1 now.
func (d *DataPlane) SendStatus(status *agentv1pb.NodeStatus) error {
	d.mu.Lock()
	session := d.session
	d.mu.Unlock()
	return d.sendStatus(session, status)
}

func (d *DataPlane) sendStatus(session DataPlaneSession, status *agentv1pb.NodeStatus) error {
	if !session.Has(agentcontrol.CapabilityReports) {
		return ErrSessionGone
	}
	return d.client.sendData(session.ID, agentcontrol.CapabilityReports, &agentv1pb.AgentToControl{
		RequestId: newID("status"), NodeId: uint32(d.client.config.NodeID), // #nosec G115 -- node IDs are uint32 on the wire.
		SentAtUnixMs: d.now().UnixMilli(),
		Payload:      &agentv1pb.AgentToControl_Status{Status: status},
	})
}

// runReports sends the spooled batches, the status and the package
// reports while the session carries their capabilities.
func (d *DataPlane) runReports() {
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-d.reports.wake:
		case <-timer.C:
		}
		d.mu.Lock()
		session := d.session
		d.mu.Unlock()
		now := d.now()
		d.reports.mu.Lock()
		if d.reports.session != session.ID {
			// A new session: everything in flight is sent again, and the
			// status and package reports go at once.
			d.reports.session = session.ID
			d.reports.inflight = map[string]time.Time{}
			d.reports.notBefore = map[string]time.Time{}
			d.reports.statusAt, d.reports.packageAt = time.Time{}, time.Time{}
			d.reports.packageSent = map[string]int64{}
		}
		d.reports.mu.Unlock()
		if session.Has(agentcontrol.CapabilityReports) {
			d.replay(session, now)
			d.reportStatus(session, now)
		} else if session.ID != "" {
			d.noteStuckBatches()
		}
		if session.Has(agentcontrol.CapabilityPackageReports) {
			d.reportPackages(session, now)
		}
		next := d.reportsWake(session)
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		if !next.IsZero() {
			timer.Reset(max(time.Until(next), 10*time.Millisecond))
		}
	}
}

// replay sends the spooled batches in order, traffic first, keeping at most
// reportWindow awaiting their ReportAck, and resends one whose ReportAck
// did not come within reportAckTimeout.
func (d *DataPlane) replay(session DataPlaneSession, now time.Time) {
	for _, target := range []*spool.Spool{d.reports.traffic, d.reports.logs} {
		if target == nil {
			continue
		}
		for _, entry := range target.Pending() {
			d.reports.mu.Lock()
			sentAt, inflight := d.reports.inflight[entry.BatchID]
			deferredUntil, deferred := d.reports.notBefore[entry.BatchID]
			if deferred && !now.Before(deferredUntil) {
				delete(d.reports.notBefore, entry.BatchID)
				deferred = false
			}
			waiting := 0
			for _, at := range d.reports.inflight {
				if now.Sub(at) < reportAckTimeout {
					waiting++
				}
			}
			d.reports.mu.Unlock()
			if deferred || (inflight && now.Sub(sentAt) < reportAckTimeout) {
				continue
			}
			if waiting >= reportWindow {
				return
			}
			message, ok, err := target.Read(entry.BatchID)
			if err != nil {
				d.logger().WithError(err).WithField("batch_id", entry.BatchID).Warn("Dropping a report batch the spool cannot read")
				target.Remove(entry.BatchID)
				continue
			}
			if !ok {
				continue
			}
			message.RequestId = newID("report")
			message.NodeId = uint32(d.client.config.NodeID) // #nosec G115 -- node IDs are uint32 on the wire.
			message.SentAtUnixMs = now.UnixMilli()
			if err := d.client.sendData(session.ID, agentcontrol.CapabilityReports, message); err != nil {
				return
			}
			d.reports.mu.Lock()
			d.reports.inflight[entry.BatchID] = now
			d.reports.mu.Unlock()
		}
	}
}

// noteStuckBatches logs once per session that spooled batches wait for a
// session that negotiates reports.v1: a batch never moves to a legacy
// transport, which has no batch ids and could count it twice.
func (d *DataPlane) noteStuckBatches() {
	d.reports.mu.Lock()
	logged := d.reports.pending
	d.reports.pending = true
	d.reports.mu.Unlock()
	if count, _, _ := d.spoolStats(); count > 0 && !logged {
		d.logger().WithField("batches", count).Warn("Report batches wait in the spool, but this Control session does not serve reports.v1; they are dropped at the spool's age bound if no later session does")
	}
}

func (d *DataPlane) reportStatus(session DataPlaneSession, now time.Time) {
	config := d.config.Reports
	if config == nil || config.Status == nil {
		return
	}
	d.reports.mu.Lock()
	due := d.reports.statusNow || d.reports.statusAt.IsZero() || now.Sub(d.reports.statusAt) >= config.StatusInterval
	if due {
		d.reports.statusAt, d.reports.statusNow = now, false
	}
	d.reports.mu.Unlock()
	if !due {
		return
	}
	ctx, cancel := context.WithTimeout(d.ctx, metricsProviderTimeout*5)
	status, err := config.Status(ctx)
	cancel()
	if err != nil || status == nil {
		if err != nil {
			d.logger().WithError(err).Warn("Could not read the node status")
		}
		return
	}
	_ = d.sendStatus(session, status)
}

func (d *DataPlane) reportPackages(session DataPlaneSession, now time.Time) {
	config := d.config.PackageReports
	if config == nil || config.Collect == nil {
		return
	}
	interval := config.Interval
	if interval <= 0 {
		interval = DefaultPackageReportInterval
	}
	d.reports.mu.Lock()
	due := d.reports.packageAt.IsZero() || now.Sub(d.reports.packageAt) >= interval
	if due {
		d.reports.packageAt = now
	}
	d.reports.mu.Unlock()
	if !due {
		return
	}
	ctx, cancel := context.WithTimeout(d.ctx, 30*time.Second)
	reports, err := config.Collect(ctx)
	cancel()
	if err != nil {
		d.logger().WithError(err).Warn("Could not collect every plugin package report")
	}
	for _, report := range reports {
		if report == nil || agentcontrol.ValidatePackageReportKind(report.GetKind()) != nil ||
			agentcontrol.ValidatePackageReportPayloadSize(report.GetPayloadJson()) != nil ||
			report.GetPluginId() == "" || report.GetVersion() == "" {
			d.logger().WithField("plugin_id", report.GetPluginId()).Warn("Not sending a malformed package report")
			continue
		}
		key := report.GetPluginId() + "\x00" + report.GetKind()
		d.reports.mu.Lock()
		sent := d.reports.packageSent[key] == report.GetObservedAtUnixMs() && report.GetObservedAtUnixMs() != 0
		d.reports.mu.Unlock()
		if sent {
			continue
		}
		if err := d.client.sendData(session.ID, agentcontrol.CapabilityPackageReports, &agentv1pb.AgentToControl{
			RequestId: newID("package-report"), NodeId: uint32(d.client.config.NodeID), // #nosec G115 -- node IDs are uint32 on the wire.
			SentAtUnixMs: now.UnixMilli(),
			Payload:      &agentv1pb.AgentToControl_PackageReport{PackageReport: report},
		}); err != nil {
			return
		}
		d.reports.mu.Lock()
		d.reports.packageSent[key] = report.GetObservedAtUnixMs()
		d.reports.mu.Unlock()
	}
}

// reportsWake is when the report loop has work without a signal: a
// ReportAck timeout, the next status or package report.
func (d *DataPlane) reportsWake(session DataPlaneSession) time.Time {
	d.reports.mu.Lock()
	defer d.reports.mu.Unlock()
	var next time.Time
	earliest := func(at time.Time) {
		if !at.IsZero() && (next.IsZero() || at.Before(next)) {
			next = at
		}
	}
	if session.Has(agentcontrol.CapabilityReports) {
		for _, sentAt := range d.reports.inflight {
			earliest(sentAt.Add(reportAckTimeout))
		}
		for _, at := range d.reports.notBefore {
			earliest(at)
		}
		if config := d.config.Reports; config != nil && config.Status != nil && !d.reports.statusAt.IsZero() {
			earliest(d.reports.statusAt.Add(config.StatusInterval))
		}
	}
	if config := d.config.PackageReports; config != nil && session.Has(agentcontrol.CapabilityPackageReports) && !d.reports.packageAt.IsZero() {
		interval := config.Interval
		if interval <= 0 {
			interval = DefaultPackageReportInterval
		}
		earliest(d.reports.packageAt.Add(interval))
	}
	return next
}

func (d *DataPlane) spoolStats() (count int, bytes int64, drops spool.Drops) {
	for _, target := range []*spool.Spool{d.reports.traffic, d.reports.logs} {
		if target == nil {
			continue
		}
		spooled, size, dropped := target.Stats()
		count += spooled
		bytes += size
		drops.Size += dropped.Size
		drops.Age += dropped.Age
		drops.Count += dropped.Count
	}
	return count, bytes, drops
}

// reportsMetrics are the reports' heartbeat metrics.
func (d *DataPlane) reportsMetrics(metrics map[string]float64) {
	if d.config.Reports == nil {
		return
	}
	count, bytes, drops := d.spoolStats()
	metrics[MetricReportSpoolBatches] = float64(count)
	metrics[MetricReportSpoolBytes] = float64(bytes)
	metrics[MetricReportSpoolDropped] = float64(drops.Size + drops.Age + drops.Count)
	metrics[MetricReportsAcked] = float64(d.reports.acked.Load())
	metrics[MetricReportsRefused] = float64(d.reports.refused.Load())
	metrics[MetricReportsDeferred] = float64(d.reports.deferred.Load())
}

func (d *DataPlane) reportsStatus() *ReportsStatus {
	if d.config.Reports == nil {
		return nil
	}
	count, bytes, drops := d.spoolStats()
	d.reports.mu.Lock()
	inflight := len(d.reports.inflight)
	d.reports.mu.Unlock()
	return &ReportsStatus{Spooled: count, Bytes: bytes, Dropped: drops, Acked: d.reports.acked.Load(), Refused: d.reports.refused.Load(), InFlight: inflight}
}
