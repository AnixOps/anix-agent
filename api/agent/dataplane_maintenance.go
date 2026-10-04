package agent

import (
	"sync"
	"sync/atomic"
	"time"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	log "github.com/sirupsen/logrus"
)

// The maintenance outbox on the stream (maintenance.v1; PROTOCOL.md,
// "Maintenance events"). The plugin supervisor keeps its health incidents
// and recoveries in a durable outbox until Control has stored them. While a
// session negotiated maintenance.v1 the data plane sends the outbox as
// MaintenanceEvents batches, oldest first, one batch awaiting its
// MaintenanceAck at a time, and applies each event's result: persisted
// removes it; a refusal (an error, or any error_code but
// maintenance_unavailable) removes it for good; neither keeps it and sends
// it again, not before retry_after_ms. The legacy maintenance-only
// WebSocket is not needed then.

// Maintenance defaults.
const (
	// DefaultMaintenanceInterval is how often the outbox is read for new
	// events while the stream carries maintenance.v1.
	DefaultMaintenanceInterval = 15 * time.Second
	// defaultMaintenanceRetry is the wait before resending an event Control
	// could not store now when its answer names no retry_after_ms.
	defaultMaintenanceRetry = 30 * time.Second
)

// maintenanceAckTimeout is how long a sent batch waits for its
// MaintenanceAck before it is sent again (a variable for tests).
var maintenanceAckTimeout = 30 * time.Second

// Heartbeat metric keys of the maintenance outbox.
const (
	// MetricMaintenancePending is the number of events the outbox held at
	// its last read (at most one batch).
	MetricMaintenancePending = "agent_dataplane_maintenance_pending"
	// MetricMaintenancePersisted counts events Control stored.
	MetricMaintenancePersisted = "agent_dataplane_maintenance_persisted_total"
	// MetricMaintenanceRefused counts events Control refused for good.
	MetricMaintenanceRefused = "agent_dataplane_maintenance_refused_total"
	// MetricMaintenanceDeferred counts events Control could not store now.
	MetricMaintenanceDeferred = "agent_dataplane_maintenance_deferred_total"
)

// MaintenanceEvent is one event of the outbox: its event_id and its JSON,
// one anixops.maintenance/v1 object.
type MaintenanceEvent struct {
	ID   string
	JSON []byte
}

// MaintenanceOutbox is the plugin supervisor's durable maintenance outbox.
type MaintenanceOutbox interface {
	// PendingMaintenance returns the oldest events, at most limit, within
	// agentcontrol.MaxMaintenanceBatchBytes together.
	PendingMaintenance(limit int) ([]MaintenanceEvent, error)
	// RemoveMaintenance removes events Control stored or refused for good.
	RemoveMaintenance(ids []string) error
}

// MaintenanceConfig turns on maintenance.v1.
type MaintenanceConfig struct {
	Outbox MaintenanceOutbox
	// Interval defaults to DefaultMaintenanceInterval.
	Interval time.Duration
}

// maintenanceState is the maintenance part of the data plane.
type maintenanceState struct {
	wake chan struct{}

	mu sync.Mutex
	// session is the session the in-flight batch was sent on.
	session  string
	inflight *maintenanceBatch
	// acks holds answers received and not yet applied.
	acks []maintenanceAnswer
	// notBefore holds, per event, when it may be sent again.
	notBefore map[string]time.Time
	// limit is the current batch size; it shrinks after
	// maintenance_batch_too_large.
	limit   int
	pending int

	persisted, refused, deferred atomic.Uint64
}

type maintenanceBatch struct {
	requestID string
	session   string
	events    []string
	sentAt    time.Time
}

type maintenanceAnswer struct {
	session   string
	requestID string
	ack       *agentv1pb.MaintenanceAck
}

func (d *DataPlane) signalMaintenance() {
	if d.config.Maintenance == nil {
		return
	}
	select {
	case d.maintenance.wake <- struct{}{}:
	default:
	}
}

// SignalMaintenance asks the data plane to read the outbox now, after the
// supervisor queued an event.
func (d *DataPlane) SignalMaintenance() { d.signalMaintenance() }

// receiveMaintenanceAck takes a MaintenanceAck from the session's receive
// loop; the outbox is changed by runMaintenance.
func (d *DataPlane) receiveMaintenanceAck(sessionID, requestID string, ack *agentv1pb.MaintenanceAck) {
	if ack == nil || d.config.Maintenance == nil {
		return
	}
	d.maintenance.mu.Lock()
	d.maintenance.acks = append(d.maintenance.acks, maintenanceAnswer{session: sessionID, requestID: requestID, ack: ack})
	d.maintenance.mu.Unlock()
	d.signalMaintenance()
}

// runMaintenance drains the outbox on sessions that negotiated
// maintenance.v1.
func (d *DataPlane) runMaintenance() {
	config := d.config.Maintenance
	interval := config.Interval
	if interval <= 0 {
		interval = DefaultMaintenanceInterval
	}
	d.maintenance.mu.Lock()
	d.maintenance.limit = agentcontrol.MaxMaintenanceBatchEvents
	d.maintenance.notBefore = map[string]time.Time{}
	d.maintenance.mu.Unlock()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-d.maintenance.wake:
		case <-timer.C:
		}
		d.mu.Lock()
		session := d.session
		d.mu.Unlock()
		d.applyMaintenanceAcks(session)
		next := d.sendMaintenance(session, interval)
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

// applyMaintenanceAcks applies the answers to the in-flight batch.
func (d *DataPlane) applyMaintenanceAcks(session DataPlaneSession) {
	state := &d.maintenance
	state.mu.Lock()
	answers := state.acks
	state.acks = nil
	if state.inflight != nil && state.inflight.session != session.ID {
		// The session ended before the answer: the batch goes again.
		state.inflight = nil
	}
	state.mu.Unlock()
	for _, answer := range answers {
		state.mu.Lock()
		batch := state.inflight
		if batch == nil || batch.requestID != answer.requestID || batch.session != answer.session {
			state.mu.Unlock()
			d.logger().WithField("request_id", answer.requestID).Debug("Ignoring a maintenance acknowledgement of no batch in flight")
			continue
		}
		state.inflight = nil
		state.mu.Unlock()
		d.applyMaintenanceAck(batch, answer.ack)
	}
}

// applyMaintenanceAck applies one MaintenanceAck, result by result in the
// batch's order.
func (d *DataPlane) applyMaintenanceAck(batch *maintenanceBatch, ack *agentv1pb.MaintenanceAck) {
	state := &d.maintenance
	now := d.now()
	results := ack.GetEvents()
	var remove []string
	tooLarge, allPersisted := false, len(results) == len(batch.events)
	for index, id := range batch.events {
		var result *agentv1pb.MaintenanceEventResult
		if index < len(results) {
			result = results[index]
		}
		entry := d.logger().WithFields(log.Fields{"event_id": id, "session_id": batch.session})
		switch {
		case result == nil:
			// No answer for it: sent again.
			allPersisted = false
			continue
		case result.GetEventId() != "" && result.GetEventId() != id:
			allPersisted = false
			entry.WithField("answered_event_id", result.GetEventId()).Warn("Control answered a maintenance event out of order; sending it again")
			continue
		case result.GetPersisted():
			state.persisted.Add(1)
			remove = append(remove, id)
			continue
		}
		allPersisted = false
		code := result.GetErrorCode()
		refused := result.GetError() != "" || (code != "" && code != agentcontrol.MaintenanceErrorCodeUnavailable)
		if !refused {
			state.deferred.Add(1)
			retry := time.Duration(result.GetRetryAfterMs()) * time.Millisecond
			if retry <= 0 {
				retry = defaultMaintenanceRetry
			}
			state.mu.Lock()
			state.notBefore[id] = now.Add(retry)
			state.mu.Unlock()
			entry.WithFields(log.Fields{"error_code": code, "retry_in": retry.String()}).Info("Control could not store a maintenance event now; it stays in the outbox")
			continue
		}
		if code == agentcontrol.MaintenanceErrorCodeBatchTooLarge && len(batch.events) > 1 {
			// Not the event's fault: send smaller batches.
			tooLarge = true
			continue
		}
		state.refused.Add(1)
		remove = append(remove, id)
		entry.WithFields(log.Fields{"error_code": code, "error": result.GetError()}).Warn("Control refused a maintenance event for good; dropping it from the outbox")
	}
	state.mu.Lock()
	switch {
	case tooLarge:
		state.limit = max(1, len(batch.events)/2)
		d.logger().WithField("batch_events", state.limit).Warn("Control refused a maintenance batch as too large; sending smaller batches")
	case allPersisted && state.limit < agentcontrol.MaxMaintenanceBatchEvents:
		state.limit = min(agentcontrol.MaxMaintenanceBatchEvents, state.limit*2)
	}
	for _, id := range remove {
		delete(state.notBefore, id)
	}
	state.mu.Unlock()
	if len(remove) > 0 {
		if err := d.config.Maintenance.Outbox.RemoveMaintenance(remove); err != nil {
			// They stay in the outbox and are sent again; Control stores
			// each once.
			d.logger().WithError(err).Warn("Could not remove answered events from the maintenance outbox")
		}
	}
	d.signalMaintenance()
}

// sendMaintenance sends the next batch when none is in flight, and returns
// when the loop should look again.
func (d *DataPlane) sendMaintenance(session DataPlaneSession, interval time.Duration) time.Time {
	now := d.now()
	if !session.Has(agentcontrol.CapabilityMaintenance) {
		return time.Time{}
	}
	state := &d.maintenance
	state.mu.Lock()
	if batch := state.inflight; batch != nil {
		state.mu.Unlock()
		if now.Sub(batch.sentAt) < maintenanceAckTimeout {
			return batch.sentAt.Add(maintenanceAckTimeout)
		}
		state.mu.Lock()
		state.inflight = nil
	}
	limit := state.limit
	state.mu.Unlock()
	events, err := d.config.Maintenance.Outbox.PendingMaintenance(agentcontrol.MaxMaintenanceBatchEvents)
	if err != nil {
		d.logger().WithError(err).Warn("Could not read the maintenance outbox")
		return now.Add(interval)
	}
	state.mu.Lock()
	state.pending = len(events)
	var batch []MaintenanceEvent
	var next time.Time
	size := 0
	for _, event := range events {
		if at, deferred := state.notBefore[event.ID]; deferred && now.Before(at) {
			if next.IsZero() || at.Before(next) {
				next = at
			}
			continue
		}
		if len(batch) >= limit || size+len(event.JSON) > agentcontrol.MaxMaintenanceBatchBytes {
			break
		}
		batch = append(batch, event)
		size += len(event.JSON)
	}
	// Events no longer in the outbox need no retry time.
	if len(events) < agentcontrol.MaxMaintenanceBatchEvents {
		present := make(map[string]bool, len(events))
		for _, event := range events {
			present[event.ID] = true
		}
		for id := range state.notBefore {
			if !present[id] {
				delete(state.notBefore, id)
			}
		}
	}
	state.mu.Unlock()
	if len(batch) == 0 {
		if next.IsZero() || now.Add(interval).Before(next) {
			next = now.Add(interval)
		}
		return next
	}
	message := &agentv1pb.MaintenanceEvents{Version: agentcontrol.MaintenanceSchemaV1}
	ids := make([]string, 0, len(batch))
	for _, event := range batch {
		message.EventsJson = append(message.EventsJson, event.JSON)
		ids = append(ids, event.ID)
	}
	requestID := newID("maintenance")
	if err := d.client.sendData(session.ID, agentcontrol.CapabilityMaintenance, &agentv1pb.AgentToControl{
		RequestId: requestID, NodeId: uint32(d.client.config.NodeID), // #nosec G115 -- node IDs are uint32 on the wire.
		SentAtUnixMs: now.UnixMilli(),
		Payload:      &agentv1pb.AgentToControl_MaintenanceEvents{MaintenanceEvents: message},
	}); err != nil {
		return now.Add(interval)
	}
	state.mu.Lock()
	state.inflight = &maintenanceBatch{requestID: requestID, session: session.ID, events: ids, sentAt: now}
	state.mu.Unlock()
	return now.Add(maintenanceAckTimeout)
}

// maintenanceMetrics are the outbox's heartbeat metrics.
func (d *DataPlane) maintenanceMetrics(metrics map[string]float64) {
	if d.config.Maintenance == nil {
		return
	}
	d.maintenance.mu.Lock()
	pending := d.maintenance.pending
	d.maintenance.mu.Unlock()
	metrics[MetricMaintenancePending] = float64(pending)
	metrics[MetricMaintenancePersisted] = float64(d.maintenance.persisted.Load())
	metrics[MetricMaintenanceRefused] = float64(d.maintenance.refused.Load())
	metrics[MetricMaintenanceDeferred] = float64(d.maintenance.deferred.Load())
}
