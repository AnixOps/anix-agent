package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AnixOps/anix-agent/v4/api/agent/state"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

// The data plane of the control stream (PROTOCOL.md, "Data plane";
// node-ops-service.md 5.5 and 5.7). With a DataPlaneConfig the client
// advertises the capabilities it has handlers for and carries the node's
// configuration (config.v1) on the stream in place of UniProxy, the v2board
// gRPC services and the WebSocket.
//
// What a capability's data rides on is its DataPlaneMode:
//
//   - stream: the current session negotiated it;
//   - pending: a session negotiated it (or the last one before a restart
//     did) and the stream has been down for less than LegacyGrace; the
//     legacy transports stay off;
//   - legacy: Control does not serve it on the current session, or the
//     stream has been down for longer than LegacyGrace, or never
//     negotiated it.

// DataPlaneMode says which transport carries a data-plane capability's data.
type DataPlaneMode int

const (
	// DataPlaneLegacy: the legacy transports (UniProxy, v2board gRPC,
	// WebSocket) carry the data.
	DataPlaneLegacy DataPlaneMode = iota
	// DataPlaneStream: the current session negotiated the capability.
	DataPlaneStream
	// DataPlanePending: the stream carried the capability and is down for
	// less than the grace period; the legacy transports stay off.
	DataPlanePending
)

func (m DataPlaneMode) String() string {
	switch m {
	case DataPlaneStream:
		return "stream"
	case DataPlanePending:
		return "pending"
	default:
		return "legacy"
	}
}

// DefaultLegacyGrace is how long the legacy transports stay off after the
// stream that carried a capability went down (node-ops-service.md 5.5).
const DefaultLegacyGrace = 5 * time.Minute

// ConfigFormatNodeConfigV1 is the ConfigSnapshot format this Agent applies
// (PROTOCOL.md, "Configuration").
const ConfigFormatNodeConfigV1 = "anixops.nodeconfig/v1"

// ErrConfigInvalid marks a configuration the node refused because the
// document does not parse or fails its checks (ConfigStatus.error_code
// config_invalid); other apply errors are config_apply_failed. Wrap it with
// InvalidConfig.
var ErrConfigInvalid = errors.New("invalid configuration")

// InvalidConfig marks err as a configuration the node cannot run because
// the document is invalid, not because applying it failed.
func InvalidConfig(err error) error {
	if err == nil {
		return nil
	}
	return &invalidConfigError{err: err}
}

type invalidConfigError struct{ err error }

func (e *invalidConfigError) Error() string { return e.err.Error() }
func (e *invalidConfigError) Unwrap() []error {
	return []error{e.err, ErrConfigInvalid}
}

// configErrorCode is ConfigStatus.error_code for an apply error.
func configErrorCode(err error) string {
	if errors.Is(err, ErrConfigInvalid) {
		return agentcontrol.ConfigErrorCodeInvalid
	}
	return agentcontrol.ConfigErrorCodeApplyFailed
}

// ErrSessionGone means a data-plane payload could not be sent because the
// session it belongs to has ended or did not negotiate its capability.
var ErrSessionGone = errors.New("agent control session is gone or did not negotiate the capability")

// ConfigApplier applies configuration snapshots (config.v1).
type ConfigApplier interface {
	// ApplyConfig makes the node run snapshot. The snapshot is verified (a
	// known format, the hash of its exact bytes). Calls come from one
	// goroutine, newest snapshot first: a snapshot superseded while an
	// earlier one applied is skipped.
	ApplyConfig(ctx context.Context, snapshot *agentv1pb.ConfigSnapshot) error
}

// DataPlaneConfig turns on the data plane of the control stream.
type DataPlaneConfig struct {
	// State keeps what the stream delivered (required).
	State *state.Store
	// Control identifies the Control the state belongs to; state of
	// another Control is discarded. Defaults to Config.Target.
	Control string
	// Config applies configuration snapshots; set, the client advertises
	// config.v1.
	Config ConfigApplier
	// Users applies user sets; set, the client advertises users.v1.
	Users UsersApplier
	// Reports turns on reports.v1: the spooled traffic and log batches and
	// the node status.
	Reports *ReportsConfig
	// PackageReports turns on package-reports.v1.
	PackageReports *PackageReportsConfig
	// Maintenance turns on maintenance.v1: the plugin supervisor's
	// maintenance outbox drains on the stream.
	Maintenance *MaintenanceConfig
	// Alive applies the alive list; set, the client advertises alive.v1.
	Alive AliveApplier
	// Artifacts advertises artifacts.v1 on sessions that present the
	// client certificate: plugin releases download from AgentArtifacts
	// (Client.PluginArtifacts).
	Artifacts bool
	// Forward is the node's forward component; set, the client advertises
	// forward.v1 (with package-reports.v1, which carries its reports) and
	// accepts anixops.nodeconfig/v2 snapshots. It needs Config: the
	// forwarding state rides in config.v1, and the ConfigApplier hands it
	// to the component.
	Forward ForwardHandler
	// Diagnostics advertises diag.v1: the Agent's agent.diagnostic handler
	// runs the forward checks of Control's route diagnosis (PROTOCOL.md,
	// "Diagnostic operation"). It adds no payload; set it only with that
	// handler and the agent.diagnostic capability.
	Diagnostics bool
	// LegacyGrace defaults to DefaultLegacyGrace.
	LegacyGrace time.Duration
	// Now defaults to time.Now (tests).
	Now func() time.Time
}

// DataPlaneSession is a session's view of the data plane.
type DataPlaneSession struct {
	ID         string
	Negotiated []string
	// TransientAcks: Control answers a batch it cannot record now with
	// report_unavailable (the transient_ack attribute of reports.v1).
	TransientAcks bool
}

// Has reports whether the session negotiated capability.
func (s DataPlaneSession) Has(capability string) bool {
	for _, name := range s.Negotiated {
		if name == capability {
			return true
		}
	}
	return false
}

// DataPlaneStatus describes the data plane for status output.
type DataPlaneStatus struct {
	StateDir       string            `json:"state_dir"`
	Modes          map[string]string `json:"modes"`
	ConfigRevision uint64            `json:"config_revision,omitempty"`
	ConfigHash     string            `json:"config_hash,omitempty"`
	ConfigError    string            `json:"config_error,omitempty"`
	UsersCursor    uint64            `json:"users_cursor,omitempty"`
	Users          int               `json:"users,omitempty"`
	UsersError     string            `json:"users_error,omitempty"`
	Reports        *ReportsStatus    `json:"reports,omitempty"`
}

// DataPlane is the client's data plane (Client.DataPlane).
type DataPlane struct {
	client *Client
	config DataPlaneConfig
	now    func() time.Time

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	wake   chan struct{}

	mu sync.Mutex
	// session is the current session, zero while disconnected.
	session DataPlaneSession
	// sessionReady is closed when a session starts; replaced after.
	sessionReady chan struct{}
	// streamUntil holds, per capability, when the stream last carried it:
	// the end of the session that negotiated it, or the Agent's start when
	// the state says the session before the restart did. A capability of
	// the current session is not in it.
	streamUntil map[string]time.Time
	active      bool

	// Configuration (config.v1).
	persistedConfig *agentv1pb.ConfigSnapshot
	appliedConfig   *agentv1pb.ConfigSnapshot
	pendingConfig   *agentv1pb.ConfigSnapshot
	configArrived   chan struct{}
	pendingStatus   *agentv1pb.ConfigStatus
	statusMu        sync.Mutex
	lastConfigError string

	// Users (users.v1).
	users usersState

	// Reports (reports.v1, package-reports.v1).
	reports reportsState

	// Maintenance outbox (maintenance.v1).
	maintenance maintenanceState

	// Alive list (alive.v1).
	alive aliveState

	counters dataPlaneCounters
}

type dataPlaneCounters struct {
	configApplied  atomic.Uint64
	configFailed   atomic.Uint64
	configRejected atomic.Uint64
	usersApplied   atomic.Uint64
	usersFailed    atomic.Uint64
}

// Heartbeat metric keys of the data plane.
const (
	// MetricConfigRevision is the configuration revision the node runs.
	MetricConfigRevision = "agent_dataplane_config_revision"
	// MetricConfigApplyFailures counts snapshots the node could not apply
	// or refused (unknown format, hash mismatch) since the Agent started.
	MetricConfigApplyFailures = "agent_dataplane_config_apply_failures_total"
	// MetricUsers is the number of users in the node's set from Control.
	MetricUsers = "agent_dataplane_users"
	// MetricUsersApplyFailures counts user sets the node could not apply
	// since the Agent started (each is retried).
	MetricUsersApplyFailures = "agent_dataplane_users_apply_failures_total"
)

func newDataPlane(client *Client, config DataPlaneConfig) (*DataPlane, error) {
	if config.State == nil {
		return nil, errors.New("agent data plane: a state store is required")
	}
	if config.Config == nil && config.Users == nil && config.Reports == nil && config.PackageReports == nil &&
		config.Maintenance == nil && config.Alive == nil && !config.Artifacts && config.Forward == nil {
		return nil, errors.New("agent data plane: no data-plane handler is configured")
	}
	if config.Forward != nil && config.Config == nil {
		return nil, errors.New("agent data plane: forward.v1 needs a ConfigApplier: the forwarding state rides in config.v1")
	}
	if config.LegacyGrace <= 0 {
		config.LegacyGrace = DefaultLegacyGrace
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Control == "" {
		config.Control = client.config.Target
	}
	plane := &DataPlane{
		client:        client,
		config:        config,
		now:           config.Now,
		wake:          make(chan struct{}, 1),
		sessionReady:  make(chan struct{}),
		configArrived: make(chan struct{}),
		streamUntil:   make(map[string]time.Time),
		users:         usersState{arrived: make(chan struct{})},
	}
	plane.ctx, plane.cancel = context.WithCancel(client.ctx)
	plane.maintenance.wake = make(chan struct{}, 1)
	plane.alive.arrived = make(chan struct{})
	plane.load()
	if err := plane.openReports(); err != nil {
		plane.cancel()
		return nil, err
	}
	return plane, nil
}

func (d *DataPlane) logger() *log.Entry {
	return log.WithFields(log.Fields{"component": "agent-dataplane", "node_id": d.client.config.NodeID})
}

// load reads the node's state: the Control it belongs to, the last
// session's capabilities and the last applied configuration.
func (d *DataPlane) load() {
	store := d.config.State
	discarded, err := store.BindControl(d.config.Control)
	if err != nil {
		d.logger().WithError(err).Warn("Could not bind the data-plane state to this Control; the stream state is not kept")
	} else if discarded {
		d.logger().WithField("dir", store.Dir()).Info("Discarded data-plane state of another Control")
	}
	if session, err := store.LoadSession(); err == nil && session.Control == d.config.Control {
		started := d.now()
		for _, capability := range session.Negotiated {
			d.streamUntil[capability] = started
		}
	}
	if d.config.Config != nil {
		snapshot, err := store.LoadConfig()
		switch {
		case err != nil:
			d.logger().WithError(err).Warn("Discarding the stored configuration snapshot")
			_ = store.DiscardConfig()
		case snapshot != nil && !d.acceptsFormat(snapshot.GetFormat()):
			_ = store.DiscardConfig()
		default:
			d.persistedConfig = snapshot
		}
	}
	if d.config.Users != nil {
		d.loadUsers()
	}
}

// capabilities lists the data-plane capabilities this configuration
// implements, for Hello.
func (d *DataPlane) capabilities() []string {
	var names []string
	if d.config.Config != nil {
		names = append(names, agentcontrol.CapabilityConfig)
	}
	if d.config.Users != nil {
		names = append(names, agentcontrol.CapabilityUsers)
	}
	if d.config.Reports != nil {
		names = append(names, agentcontrol.CapabilityReports)
	}
	if d.config.PackageReports != nil || d.config.Forward != nil {
		names = append(names, agentcontrol.CapabilityPackageReports)
	}
	if d.config.Forward != nil {
		names = append(names, agentcontrol.CapabilityForward)
	}
	if d.config.Maintenance != nil {
		names = append(names, agentcontrol.CapabilityMaintenance)
	}
	if d.config.Alive != nil {
		names = append(names, agentcontrol.CapabilityAlive)
	}
	if d.config.Artifacts {
		names = append(names, agentcontrol.CapabilityArtifacts)
	}
	if d.config.Diagnostics {
		names = append(names, agentcontrol.CapabilityDiag)
	}
	return names
}

func (d *DataPlane) start() {
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.run()
	}()
	if d.config.Reports != nil || d.config.PackageReports != nil {
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.runReports()
		}()
	}
	if d.config.Maintenance != nil {
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.runMaintenance()
		}()
	}
}

func (d *DataPlane) close() {
	d.cancel()
	d.wg.Wait()
}

func (d *DataPlane) signal() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// helloConfigRevision is Hello.config_revision: the revision the node runs,
// 0 for none.
func (d *DataPlane) helloConfigRevision() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.appliedConfig.GetConfigRevision()
}

// sessionStarted records a session after its HelloAck. transientAcks
// tells whether Control echoed the transient_ack attribute of reports.v1.
func (d *DataPlane) sessionStarted(sessionID string, negotiated []string, transientAcks bool) {
	d.mu.Lock()
	d.session = DataPlaneSession{ID: sessionID, Negotiated: append([]string(nil), negotiated...), TransientAcks: transientAcks}
	for _, capability := range negotiated {
		delete(d.streamUntil, capability)
	}
	close(d.sessionReady)
	d.mu.Unlock()
	d.signalReports()
	d.signalMaintenance()
	if d.config.Forward != nil {
		d.config.Forward.ForwardSession(forwardNegotiated(DataPlaneSession{Negotiated: negotiated}))
	}
	if err := d.config.State.SaveSession(state.Session{Control: d.config.Control, Negotiated: negotiated, At: d.now().UTC()}); err != nil {
		d.logger().WithError(err).Warn("Could not record the negotiated data-plane capabilities")
	}
	d.signal()
}

// sessionEnded records the end of a session.
func (d *DataPlane) sessionEnded(sessionID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.session.ID != sessionID {
		return
	}
	ended := d.now()
	for _, capability := range d.session.Negotiated {
		d.streamUntil[capability] = ended
	}
	d.dropUserPagesLocked(sessionID)
	d.dropAlivePagesLocked(sessionID)
	d.session = DataPlaneSession{}
	d.sessionReady = make(chan struct{})
}

// Mode says which transport carries capability's data now.
func (d *DataPlane) Mode(capability string) DataPlaneMode {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.modeLocked(capability)
}

func (d *DataPlane) modeLocked(capability string) DataPlaneMode {
	if d.session.ID != "" {
		if d.session.Has(capability) {
			return DataPlaneStream
		}
		return DataPlaneLegacy
	}
	if until, ok := d.streamUntil[capability]; ok && d.now().Sub(until) < d.config.LegacyGrace {
		return DataPlanePending
	}
	return DataPlaneLegacy
}

// WaitSession waits for a session with Control and returns it.
func (d *DataPlane) WaitSession(ctx context.Context) (DataPlaneSession, error) {
	for {
		d.mu.Lock()
		session, ready := d.session, d.sessionReady
		d.mu.Unlock()
		if session.ID != "" {
			return session, nil
		}
		select {
		case <-ctx.Done():
			return DataPlaneSession{}, ctx.Err()
		case <-d.ctx.Done():
			return DataPlaneSession{}, d.ctx.Err()
		case <-ready:
		}
	}
}

// Activate hands every later snapshot to the appliers. Before, snapshots
// wait for the node's startup (TakeConfig).
func (d *DataPlane) Activate() {
	d.mu.Lock()
	d.active = true
	d.mu.Unlock()
	d.signal()
}

// PersistedConfig is the configuration the node last applied, from its
// state, nil without one. The node runs it at startup (RestoreConfig)
// without waiting for Control.
func (d *DataPlane) PersistedConfig() *agentv1pb.ConfigSnapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.persistedConfig == nil {
		return nil
	}
	return proto.Clone(d.persistedConfig).(*agentv1pb.ConfigSnapshot)
}

// RestoreConfig records that the node runs the persisted snapshot: Hello
// reports its revision, so Control sends a snapshot only when the desired
// configuration moved.
func (d *DataPlane) RestoreConfig(snapshot *agentv1pb.ConfigSnapshot) {
	d.mu.Lock()
	d.appliedConfig = proto.Clone(snapshot).(*agentv1pb.ConfigSnapshot)
	d.mu.Unlock()
}

// DiscardPersistedConfig drops the persisted snapshot after the node could
// not run it; Hello reports no revision, so Control sends the desired one.
func (d *DataPlane) DiscardPersistedConfig() {
	d.mu.Lock()
	d.persistedConfig = nil
	d.mu.Unlock()
	if err := d.config.State.DiscardConfig(); err != nil {
		d.logger().WithError(err).Warn("Could not remove the stored configuration snapshot")
	}
}

// TakeConfig waits for a configuration snapshot from Control and takes it,
// for the node's startup. The node answers it with ConfigResult.
func (d *DataPlane) TakeConfig(ctx context.Context) (*agentv1pb.ConfigSnapshot, error) {
	for {
		d.mu.Lock()
		snapshot, arrived := d.pendingConfig, d.configArrived
		if snapshot != nil {
			d.pendingConfig = nil
			d.mu.Unlock()
			return snapshot, nil
		}
		d.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-d.ctx.Done():
			return nil, d.ctx.Err()
		case <-arrived:
		}
	}
}

// ConfigResult answers a snapshot the node applied itself (TakeConfig):
// stored and reported in Hello on success, and a ConfigStatus either way.
func (d *DataPlane) ConfigResult(snapshot *agentv1pb.ConfigSnapshot, err error) {
	d.finishConfig(snapshot, err)
}

// receive takes a negotiated data-plane payload from the session's receive
// loop. It never blocks on applying.
func (d *DataPlane) receive(sessionID, requestID string, payload any) {
	switch payload := payload.(type) {
	case *agentv1pb.ControlToAgent_Config:
		d.receiveConfig(sessionID, payload.Config)
	case *agentv1pb.ControlToAgent_Users:
		d.receiveUsers(sessionID, payload.Users)
	case *agentv1pb.ControlToAgent_ReportAck:
		d.receiveReportAck(sessionID, payload.ReportAck)
	case *agentv1pb.ControlToAgent_MaintenanceAck:
		d.receiveMaintenanceAck(sessionID, requestID, payload.MaintenanceAck)
	case *agentv1pb.ControlToAgent_AliveList:
		d.receiveAlive(sessionID, payload.AliveList)
	}
}

// receiveConfig takes a snapshot from the session's receive loop.
func (d *DataPlane) receiveConfig(sessionID string, snapshot *agentv1pb.ConfigSnapshot) {
	if snapshot == nil {
		return
	}
	if problem, code := d.verifySnapshot(snapshot); problem != "" {
		d.counters.configRejected.Add(1)
		d.logger().WithFields(log.Fields{"config_revision": snapshot.GetConfigRevision(), "problem": problem, "error_code": code}).
			Warn("Refusing a configuration snapshot from Control")
		if snapshot.GetConfigRevision() != 0 {
			d.queueStatus(&agentv1pb.ConfigStatus{
				ConfigRevision: snapshot.GetConfigRevision(), ConfigHash: snapshot.GetConfigHash(), Error: problem, ErrorCode: code,
			})
		}
		d.mu.Lock()
		d.lastConfigError = problem
		d.mu.Unlock()
		return
	}
	d.mu.Lock()
	d.pendingConfig = proto.Clone(snapshot).(*agentv1pb.ConfigSnapshot)
	close(d.configArrived)
	d.configArrived = make(chan struct{})
	d.mu.Unlock()
	d.signal()
}

// verifySnapshot returns why a snapshot cannot be applied and its
// ConfigStatus.error_code, "" when it can.
func (d *DataPlane) verifySnapshot(snapshot *agentv1pb.ConfigSnapshot) (problem, code string) {
	switch {
	case snapshot.GetConfigRevision() == 0:
		return "config_revision is required", agentcontrol.ConfigErrorCodeInvalid
	case !d.acceptsFormat(snapshot.GetFormat()):
		return fmt.Sprintf("unknown configuration format %q (this Agent applies %s)", snapshot.GetFormat(), d.formatsText()), agentcontrol.ConfigErrorCodeFormatUnsupported
	case !state.HashMatches(snapshot):
		return "config_hash does not match the SHA-256 of config_json", agentcontrol.ConfigErrorCodeHashMismatch
	}
	return "", ""
}

// run applies snapshots and user sets after Activate, delivers statuses
// and stores the user set.
func (d *DataPlane) run() {
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		select {
		case <-d.ctx.Done():
			d.saveUsers(true)
			return
		case <-d.wake:
		case <-timer.C:
		}
		d.flushStatus()
		d.applyPendingConfig()
		d.applyPendingUsers()
		d.applyPendingAlive()
		d.saveUsers(false)
		d.mu.Lock()
		next := d.usersWakeLocked()
		d.mu.Unlock()
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

func (d *DataPlane) applyPendingConfig() {
	for {
		d.mu.Lock()
		snapshot, applied := d.pendingConfig, d.appliedConfig
		if !d.active || snapshot == nil {
			d.mu.Unlock()
			return
		}
		d.pendingConfig = nil
		d.mu.Unlock()
		if applied != nil && applied.GetConfigRevision() == snapshot.GetConfigRevision() && applied.GetConfigHash() == snapshot.GetConfigHash() {
			// The node runs it already (a forced sync, or a Hello that
			// raced the restore): answer without restarting anything.
			d.queueStatus(&agentv1pb.ConfigStatus{ConfigRevision: snapshot.GetConfigRevision(), ConfigHash: snapshot.GetConfigHash(), Applied: true})
			continue
		}
		err := d.config.Config.ApplyConfig(d.ctx, snapshot)
		if d.ctx.Err() != nil {
			return
		}
		d.finishConfig(snapshot, err)
	}
}

func (d *DataPlane) finishConfig(snapshot *agentv1pb.ConfigSnapshot, err error) {
	entry := d.logger().WithFields(log.Fields{"config_revision": snapshot.GetConfigRevision(), "config_hash": snapshot.GetConfigHash()})
	status := &agentv1pb.ConfigStatus{ConfigRevision: snapshot.GetConfigRevision(), ConfigHash: snapshot.GetConfigHash(), Applied: err == nil}
	if err != nil {
		d.counters.configFailed.Add(1)
		status.Error, status.ErrorCode = err.Error(), configErrorCode(err)
		d.mu.Lock()
		d.lastConfigError = err.Error()
		d.mu.Unlock()
		entry.WithError(err).WithField("error_code", status.ErrorCode).Error("Could not apply the configuration snapshot from Control")
	} else {
		d.counters.configApplied.Add(1)
		d.mu.Lock()
		d.appliedConfig = proto.Clone(snapshot).(*agentv1pb.ConfigSnapshot)
		d.persistedConfig = proto.Clone(snapshot).(*agentv1pb.ConfigSnapshot)
		d.lastConfigError = ""
		d.mu.Unlock()
		if saveErr := d.config.State.SaveConfig(snapshot); saveErr != nil {
			entry.WithError(saveErr).Warn("Could not store the applied configuration snapshot; a restart while Control is unreachable starts without it")
		}
		entry.Info("Applied the configuration snapshot from Control")
	}
	d.queueStatus(status)
}

// queueStatus keeps status as the one to deliver (the newest wins) and
// delivers it when a session negotiated config.v1. A status that cannot be
// sent now goes out after the next HelloAck: Control does not send a
// snapshot again for the revision the Agent reports in Hello, so the status
// would otherwise be lost.
func (d *DataPlane) queueStatus(status *agentv1pb.ConfigStatus) {
	d.mu.Lock()
	d.pendingStatus = status
	d.mu.Unlock()
	d.flushStatus()
}

func (d *DataPlane) flushStatus() {
	// One flush at a time, so a status is sent once.
	d.statusMu.Lock()
	defer d.statusMu.Unlock()
	d.mu.Lock()
	status, session := d.pendingStatus, d.session
	d.mu.Unlock()
	if status == nil || !session.Has(agentcontrol.CapabilityConfig) {
		return
	}
	err := d.client.sendData(session.ID, agentcontrol.CapabilityConfig, &agentv1pb.AgentToControl{
		RequestId:    newID("config-status"),
		NodeId:       uint32(d.client.config.NodeID), // #nosec G115 -- node IDs are uint32 on the wire.
		SentAtUnixMs: d.now().UnixMilli(),
		Payload:      &agentv1pb.AgentToControl_ConfigStatus{ConfigStatus: status},
	})
	if err != nil {
		return
	}
	d.mu.Lock()
	if d.pendingStatus == status {
		d.pendingStatus = nil
	}
	d.mu.Unlock()
}

// metrics are the data plane's heartbeat metrics.
func (d *DataPlane) metrics() map[string]float64 {
	d.mu.Lock()
	revision := d.appliedConfig.GetConfigRevision()
	d.mu.Unlock()
	metrics := map[string]float64{}
	if d.config.Config != nil {
		metrics[MetricConfigRevision] = float64(revision)
		metrics[MetricConfigApplyFailures] = float64(d.counters.configFailed.Load() + d.counters.configRejected.Load())
	}
	if d.config.Users != nil {
		d.mu.Lock()
		users := len(d.users.set)
		d.mu.Unlock()
		metrics[MetricUsers] = float64(users)
		metrics[MetricUsersApplyFailures] = float64(d.counters.usersFailed.Load())
	}
	d.reportsMetrics(metrics)
	d.maintenanceMetrics(metrics)
	d.aliveMetrics(metrics)
	return metrics
}

// status describes the data plane for status output.
func (d *DataPlane) status() DataPlaneStatus {
	reports := d.reportsStatus()
	d.mu.Lock()
	defer d.mu.Unlock()
	status := DataPlaneStatus{StateDir: d.config.State.Dir(), Modes: map[string]string{}, Reports: reports}
	for _, capability := range d.capabilities() {
		status.Modes[capability+"."+agentcontrol.CapabilityVersionV1] = d.modeLocked(capability).String()
	}
	if d.appliedConfig != nil {
		status.ConfigRevision, status.ConfigHash = d.appliedConfig.GetConfigRevision(), d.appliedConfig.GetConfigHash()
	}
	status.ConfigError = d.lastConfigError
	if d.users.has {
		status.UsersCursor, status.Users = d.users.cursor, len(d.users.set)
	}
	status.UsersError = d.users.lastErr
	return status
}
