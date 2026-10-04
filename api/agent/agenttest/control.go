// Package agenttest is an in-process Control for tests of the Agent control
// stream: the AgentControlService and AgentEnrollment of anix-control's
// agent listener over TLS, with the agent PKI (A2-1), the
// agent_control.mtls modes (A2-6) and the data plane (A2-3: configuration
// snapshots and ConfigStatus; A2-4: user deltas from a change log, with
// cursors and paged resyncs), modelled on anix-control's internal/grpc
// agent_control_server.go, agent_control_config.go and
// agent_control_users.go; A2-5: reports with batch ids recorded once and
// ReportAck, package reports; A2-6b: the maintenance outbox
// (maintenance.v1), the alive list (alive.v1), AgentArtifacts by client
// certificate (artifacts.v1), error codes in refusals and acknowledgements
// and the capability offer as an intersection.
package agenttest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/AnixOps/anix-control/sdk/forward/wire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpccredentials "google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// agent_control.mtls modes.
const (
	ModeOff       = "off"
	ModeOptional  = "optional"
	ModePreferred = "preferred"
	ModeRequired  = "required"
)

// ConfigFormat is the snapshot format Control sends.
const ConfigFormat = "anixops.nodeconfig/v1"

// Control is the fake. Its exported fields are read when a stream starts;
// change them before the Agent connects, or through the setters.
type Control struct {
	agentv1pb.UnimplementedAgentControlServiceServer
	agentv1pb.UnimplementedAgentEnrollmentServer
	agentv1pb.UnimplementedAgentArtifactsServer

	NodeID uint32
	// NodeKind is the node's kind: agentcontrol.NodeKindProxy (when empty)
	// or agentcontrol.NodeKindForward (a forward node: certificate-only
	// streams, forward.v1, no users or reports.v1).
	NodeKind string
	APIKey   string
	Cluster  string
	// ServerName is the name in the server certificate.
	ServerName string
	// Address is the listener's host:port.
	Address string
	// ServerCAs verifies the server certificate (Agent RootCAs).
	ServerCAs *x509.CertPool

	t           testing.TB
	server      *grpc.Server
	agentCAKey  *ecdsa.PrivateKey
	agentCACert *x509.Certificate

	mu          sync.Mutex
	mode        string
	serves      map[string]bool
	credentials map[string]bool
	issued      []string
	sessions    map[string]*session
	sessionSeq  int
	hellos      []*agentv1pb.Hello
	streams     []StreamAuth
	received    []*agentv1pb.AgentToControl

	// Configuration (config.v1).
	desired  *agentv1pb.ConfigSnapshot
	statuses []*agentv1pb.ConfigStatus
	sent     []*agentv1pb.ConfigSnapshot

	// Users (users.v1): the node's users and the change log.
	users      map[uint64]*agentv1pb.NodeUser
	changes    []userChange
	cursor     uint64
	prunedTo   uint64
	pageSize   int
	userDeltas []*agentv1pb.UserDelta
	resyncs    int
	// dropAfterPages ends a session after that many pages of a full
	// resync (0: never), once.
	dropAfterPages int

	// Reports (reports.v1, package-reports.v1).
	batches        map[string]bool
	appliedTraffic map[uint64][2]uint64
	online         []*agentv1pb.OnlineUser
	logEntries     []*agentv1pb.LogEntry
	nodeStatuses   []*agentv1pb.NodeStatus
	packageReports []*agentv1pb.PackageReport
	reportAcks     []*agentv1pb.ReportAck
	holdAcks       bool
	refuseStreams  bool
	loseAcks       int
	refuse         func(batchID string) string
	deliveries     int
	// transientAcks: Control echoes transient_ack and answers
	// report_unavailable; unavailableReports counts the batches still to
	// answer so.
	transientAcks      bool
	unavailableReports int

	// Maintenance (maintenance.v1), alive list (alive.v1), artifacts
	// (artifacts.v1), operations and certificate refusals: streams.go.
	maintenance maintenanceState
	alive       aliveState
	artifacts   artifactsState
	operations  operationsState
	// refuseCertificate makes the certificate check of the serials in
	// refusedSerials fail with this code (agent_cert_*).
	refuseCertificate string
	refusedSerials    map[string]bool

	// Forwarding (forward.v1): forward.go; link certificates: link.go.
	forward forwardState
	link    linkState
}

// userChange is one row of the subscriber change log.
type userChange struct {
	id     uint64
	userID uint64
}

// StreamAuth records how a stream authenticated.
type StreamAuth struct {
	CertificateSerial string
	APIKey            bool
	Accepted          bool
}

type session struct {
	id     string
	stream agentv1pb.AgentControlService_ControlStreamServer
	sendMu sync.Mutex
	cancel context.CancelFunc
	hello  *agentv1pb.Hello
	// configSentMax is the newest revision sent on the session; config is
	// the revision the agent has (Hello) or was sent.
	configSentMax uint64
	configRev     uint64
	negotiated    map[string]bool
	// usersCursor is the change-log position the session was sent up to;
	// usersMu serializes the session's user sends.
	usersCursor  uint64
	usersStarted bool
	usersMu      sync.Mutex
	// transientAcks: the session negotiated transient_ack.
	transientAcks bool
	// aliveRevision counts the alive lists sent; aliveMu serializes them.
	aliveRevision uint64
	aliveMu       sync.Mutex
}

func (s *session) send(message *agentv1pb.ControlToAgent) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.stream.Send(message)
}

// New starts a fake Control on 127.0.0.1 in mode, serving the data-plane
// capabilities named in serves (config, users, reports, package-reports).
func New(t testing.TB, mode string, serves ...string) *Control {
	t.Helper()
	control := &Control{
		t: t, NodeID: 12, APIKey: "node-api-key", Cluster: "test-cluster", ServerName: "control.test",
		mode: mode, serves: map[string]bool{}, credentials: map[string]bool{}, sessions: map[string]*session{},
		users: map[uint64]*agentv1pb.NodeUser{}, pageSize: 500,
		batches: map[string]bool{}, appliedTraffic: map[uint64][2]uint64{},
		transientAcks: true,
	}
	control.initStreams()
	for _, name := range serves {
		control.serves[name] = true
	}
	serverCAKey, serverCACert := newCA(t, "control server CA")
	control.ServerCAs = x509.NewCertPool()
	control.ServerCAs.AddCert(serverCACert)
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: control.ServerName}, DNSNames: []string{control.ServerName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, serverCACert, &serverKey.PublicKey, serverCAKey)
	must(t, err)
	serverCertificate := tls.Certificate{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}
	control.agentCAKey, control.agentCACert = newCA(t, "agent CA")

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			config := &tls.Config{Certificates: []tls.Certificate{serverCertificate}, MinVersion: tls.VersionTLS12}
			if control.Mode() != ModeOff {
				config.ClientAuth = tls.RequestClientCert
			}
			return config, nil
		},
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	control.Address = listener.Addr().String()
	control.server = grpc.NewServer(grpc.Creds(grpccredentials.NewTLS(tlsConfig)))
	agentv1pb.RegisterAgentControlServiceServer(control.server, control)
	agentv1pb.RegisterAgentEnrollmentServer(control.server, control)
	agentv1pb.RegisterAgentArtifactsServer(control.server, control)
	go func() { _ = control.server.Serve(listener) }()
	t.Cleanup(control.server.Stop)
	return control
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func newCA(t testing.TB, name string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	must(t, err)
	certificate, err := x509.ParseCertificate(der)
	must(t, err)
	return key, certificate
}

// Close stops the listener and ends every stream, as Control going away
// would.
func (c *Control) Close() {
	c.server.Stop()
}

// Mode is the agent_control.mtls mode.
func (c *Control) Mode() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mode
}

// SetMode changes the mode for later connections.
func (c *Control) SetMode(mode string) {
	c.mu.Lock()
	c.mode = mode
	c.mu.Unlock()
}

// Serve sets whether Control serves a data-plane capability to later
// sessions.
func (c *Control) Serve(capability string, serve bool) {
	c.mu.Lock()
	c.serves[capability] = serve
	c.mu.Unlock()
}

// AddCredential registers a one-time anixagt_ enrollment credential.
func (c *Control) AddCredential(credential string) {
	c.mu.Lock()
	c.credentials[credential] = false
	c.mu.Unlock()
}

// Hellos returns every Hello received.
func (c *Control) Hellos() []*agentv1pb.Hello {
	c.mu.Lock()
	defer c.mu.Unlock()
	hellos := make([]*agentv1pb.Hello, 0, len(c.hellos))
	for _, hello := range c.hellos {
		hellos = append(hellos, proto.Clone(hello).(*agentv1pb.Hello))
	}
	return hellos
}

// Streams returns how every stream authenticated.
func (c *Control) Streams() []StreamAuth {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]StreamAuth(nil), c.streams...)
}

// Received returns every message after Hello, in order.
func (c *Control) Received() []*agentv1pb.AgentToControl {
	c.mu.Lock()
	defer c.mu.Unlock()
	messages := make([]*agentv1pb.AgentToControl, 0, len(c.received))
	for _, message := range c.received {
		messages = append(messages, proto.Clone(message).(*agentv1pb.AgentToControl))
	}
	return messages
}

// Connected reports whether a session is open.
func (c *Control) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sessions) > 0
}

// DropSessions ends every open stream, as a Control restart would.
func (c *Control) DropSessions() {
	c.mu.Lock()
	sessions := make([]*session, 0, len(c.sessions))
	for _, session := range c.sessions {
		sessions = append(sessions, session)
	}
	c.mu.Unlock()
	for _, session := range sessions {
		session.cancel()
	}
}

// Snapshot builds a ConfigSnapshot of document at revision, hashed as
// Control hashes it.
func Snapshot(revision uint64, document any) *agentv1pb.ConfigSnapshot {
	encoded, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(encoded)
	return &agentv1pb.ConfigSnapshot{ConfigRevision: revision, ConfigHash: hex.EncodeToString(sum[:]), Format: ConfigFormat, ConfigJson: encoded}
}

// SetDesiredConfig sets the node's desired configuration. With push, it is
// sent to the open sessions that negotiated config.v1 (a node.sync);
// otherwise sessions get it at their next Hello.
func (c *Control) SetDesiredConfig(snapshot *agentv1pb.ConfigSnapshot, push bool) {
	c.mu.Lock()
	c.desired = proto.Clone(snapshot).(*agentv1pb.ConfigSnapshot)
	sessions := c.openSessions()
	c.mu.Unlock()
	if !push {
		return
	}
	for _, session := range sessions {
		if session.negotiated[agentcontrol.CapabilityConfig] {
			_ = c.sendConfig(session, snapshot, true)
		}
	}
}

// ConfigStatuses returns every ConfigStatus received.
func (c *Control) ConfigStatuses() []*agentv1pb.ConfigStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	statuses := make([]*agentv1pb.ConfigStatus, 0, len(c.statuses))
	for _, status := range c.statuses {
		statuses = append(statuses, proto.Clone(status).(*agentv1pb.ConfigStatus))
	}
	return statuses
}

// SentConfigs returns every snapshot sent.
func (c *Control) SentConfigs() []*agentv1pb.ConfigSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*agentv1pb.ConfigSnapshot(nil), c.sent...)
}

func (c *Control) openSessions() []*session {
	sessions := make([]*session, 0, len(c.sessions))
	for _, session := range c.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// sendConfig sends snapshot unless the session was sent a newer revision
// or, without force, has this one (AgentControlConnection.sendConfig).
func (c *Control) sendConfig(session *session, snapshot *agentv1pb.ConfigSnapshot, force bool) error {
	c.mu.Lock()
	revision := snapshot.GetConfigRevision()
	if revision < session.configSentMax || (!force && revision == session.configRev) {
		c.mu.Unlock()
		return nil
	}
	session.configRev, session.configSentMax = revision, revision
	c.sent = append(c.sent, proto.Clone(snapshot).(*agentv1pb.ConfigSnapshot))
	c.mu.Unlock()
	return session.send(&agentv1pb.ControlToAgent{
		RequestId: "config-" + strconv.FormatUint(revision, 10), NodeId: c.NodeID, SentAtUnixMs: time.Now().UnixMilli(),
		Payload: &agentv1pb.ControlToAgent_Config{Config: snapshot},
	})
}

// SetUserPageSize sets the users per page of a full resync.
func (c *Control) SetUserPageSize(size int) {
	c.mu.Lock()
	c.pageSize = size
	c.mu.Unlock()
}

// DropNextResyncAfter makes the next full resync end its session after
// pages pages, before its last page.
func (c *Control) DropNextResyncAfter(pages int) {
	c.mu.Lock()
	c.dropAfterPages = pages
	c.mu.Unlock()
}

// UpsertUsers adds or changes users, records each in the change log and
// sends the delta to the sessions that negotiated users.v1.
func (c *Control) UpsertUsers(users ...*agentv1pb.NodeUser) {
	c.mu.Lock()
	for _, user := range users {
		c.users[user.GetUserId()] = proto.Clone(user).(*agentv1pb.NodeUser)
		c.cursor++
		c.changes = append(c.changes, userChange{id: c.cursor, userID: user.GetUserId()})
	}
	sessions := c.openSessions()
	c.mu.Unlock()
	c.pushUserChanges(sessions)
}

// RemoveUsers removes users (expired, banned, moved to another group),
// records each in the change log and sends the delta.
func (c *Control) RemoveUsers(ids ...uint64) {
	c.mu.Lock()
	for _, id := range ids {
		delete(c.users, id)
		c.cursor++
		c.changes = append(c.changes, userChange{id: c.cursor, userID: id})
	}
	sessions := c.openSessions()
	c.mu.Unlock()
	c.pushUserChanges(sessions)
}

// PruneUserLog drops the change log up to the latest change, as Control's
// retention does; a cursor before it then needs a full resync.
func (c *Control) PruneUserLog() {
	c.mu.Lock()
	c.changes = nil
	c.prunedTo = c.cursor
	c.mu.Unlock()
}

// ResetUserLog makes the change log start over from 0 (a restored
// database): every Agent cursor is then ahead of it.
func (c *Control) ResetUserLog() {
	c.mu.Lock()
	c.changes, c.cursor, c.prunedTo = nil, 0, 0
	c.mu.Unlock()
}

// UserCursor is the change log's latest position.
func (c *Control) UserCursor() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cursor
}

// UserDeltas returns every UserDelta page sent.
func (c *Control) UserDeltas() []*agentv1pb.UserDelta {
	c.mu.Lock()
	defer c.mu.Unlock()
	deltas := make([]*agentv1pb.UserDelta, 0, len(c.userDeltas))
	for _, delta := range c.userDeltas {
		deltas = append(deltas, proto.Clone(delta).(*agentv1pb.UserDelta))
	}
	return deltas
}

// Resyncs counts the full resyncs sent.
func (c *Control) Resyncs() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.resyncs
}

// startUsers starts a session's users from the Agent's cursor, as
// decideUsersStart: a full resync for no cursor, a cursor ahead of the log
// or one the log no longer covers; else the changes after it.
func (c *Control) startUsers(current *session, cursor uint64) error {
	c.mu.Lock()
	resync := cursor == 0 || cursor > c.cursor || cursor < c.prunedTo
	c.mu.Unlock()
	current.usersMu.Lock()
	defer current.usersMu.Unlock()
	current.usersStarted = true
	if resync {
		return c.resyncUsersLocked(current)
	}
	current.usersCursor = cursor
	return c.sendUserChangesLocked(current)
}

// resyncUsersLocked sends the whole set in pages, each with the cursor
// read before the listing. current.usersMu is held.
func (c *Control) resyncUsersLocked(current *session) error {
	c.mu.Lock()
	cursor, pageSize := c.cursor, c.pageSize
	ids := make([]uint64, 0, len(c.users))
	for id := range c.users {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	users := make([]*agentv1pb.NodeUser, 0, len(ids))
	for _, id := range ids {
		users = append(users, proto.Clone(c.users[id]).(*agentv1pb.NodeUser))
	}
	c.resyncs++
	dropAfter := c.dropAfterPages
	c.dropAfterPages = 0
	c.mu.Unlock()
	for start, pages := 0, 0; ; start += pageSize {
		end := min(start+pageSize, len(users))
		last := end >= len(users)
		if dropAfter > 0 && pages == dropAfter {
			current.cancel()
			return status.Error(codes.Unavailable, "session dropped during a resync")
		}
		if err := c.sendUsers(current, &agentv1pb.UserDelta{Cursor: cursor, Full: true, LastPage: last, Upserts: users[start:end]}); err != nil {
			return err
		}
		pages++
		if last {
			break
		}
	}
	current.usersCursor = cursor
	return nil
}

// sendUserChangesLocked sends the changes after the session's cursor as
// one delta of each changed user's current state. current.usersMu is held.
func (c *Control) sendUserChangesLocked(current *session) error {
	c.mu.Lock()
	if current.usersCursor < c.prunedTo {
		c.mu.Unlock()
		return c.resyncUsersLocked(current)
	}
	seen := map[uint64]bool{}
	delta := &agentv1pb.UserDelta{LastPage: true}
	for _, change := range c.changes {
		if change.id <= current.usersCursor || seen[change.userID] {
			continue
		}
		seen[change.userID] = true
		if user, ok := c.users[change.userID]; ok {
			delta.Upserts = append(delta.Upserts, proto.Clone(user).(*agentv1pb.NodeUser))
		} else {
			delta.RemovedUserIds = append(delta.RemovedUserIds, change.userID)
		}
	}
	delta.Cursor = c.cursor
	c.mu.Unlock()
	if len(seen) == 0 {
		return nil
	}
	if err := c.sendUsers(current, delta); err != nil {
		return err
	}
	current.usersCursor = delta.Cursor
	return nil
}

func (c *Control) pushUserChanges(sessions []*session) {
	for _, session := range sessions {
		if !session.negotiated[agentcontrol.CapabilityUsers] {
			continue
		}
		session.usersMu.Lock()
		if session.usersStarted {
			_ = c.sendUserChangesLocked(session)
		}
		session.usersMu.Unlock()
	}
}

func (c *Control) sendUsers(current *session, delta *agentv1pb.UserDelta) error {
	c.mu.Lock()
	c.userDeltas = append(c.userDeltas, proto.Clone(delta).(*agentv1pb.UserDelta))
	c.mu.Unlock()
	return current.send(&agentv1pb.ControlToAgent{
		RequestId: "users-" + strconv.FormatUint(delta.GetCursor(), 10), NodeId: c.NodeID, SentAtUnixMs: time.Now().UnixMilli(),
		Payload: &agentv1pb.ControlToAgent_Users{Users: delta},
	})
}

// RefuseStreams makes Control unavailable to new streams (and ends the
// open ones), as an outage would; false serves them again.
func (c *Control) RefuseStreams(refuse bool) {
	c.mu.Lock()
	c.refuseStreams = refuse
	c.mu.Unlock()
	if refuse {
		c.DropSessions()
	}
}

// UnavailableReports makes Control unable to record the next count
// batches: it answers report_unavailable (retry_after_ms 200) to an Agent
// that negotiated transient_ack, and nothing to others.
func (c *Control) UnavailableReports(count int) {
	c.mu.Lock()
	c.unavailableReports = count
	c.mu.Unlock()
}

// SetTransientAcks sets whether Control echoes transient_ack to later
// sessions (an older Control does not).
func (c *Control) SetTransientAcks(on bool) {
	c.mu.Lock()
	c.transientAcks = on
	c.mu.Unlock()
}

// HoldReportAcks makes Control answer no ReportAck, as when its database
// fails: the batches are not recorded and the Agent resends them.
func (c *Control) HoldReportAcks(hold bool) {
	c.mu.Lock()
	c.holdAcks = hold
	c.mu.Unlock()
}

// LoseNextAcks records the next count batches but loses their ReportAck,
// as a stream that breaks right after the commit: the Agent resends them,
// and Control answers that it recorded them before.
func (c *Control) LoseNextAcks(count int) {
	c.mu.Lock()
	c.loseAcks = count
	c.mu.Unlock()
}

// RefuseBatches makes Control refuse batches for good: refuse returns the
// refusal for a batch id, "" to record it.
func (c *Control) RefuseBatches(refuse func(batchID string) string) {
	c.mu.Lock()
	c.refuse = refuse
	c.mu.Unlock()
}

// handleBatch records a TrafficReport or LogBatch once per batch id and
// answers ReportAck, as AgentControlGRPCServer.handleReport.
func (c *Control) handleBatch(current *session, message *agentv1pb.AgentToControl) error {
	var batchID string
	c.mu.Lock()
	c.deliveries++
	if c.holdAcks {
		c.mu.Unlock()
		return nil
	}
	if c.unavailableReports > 0 {
		// The database failed: silence, or report_unavailable to an
		// Agent that negotiated transient_ack.
		c.unavailableReports--
		transient := current.transientAcks
		c.mu.Unlock()
		if !transient {
			return nil
		}
		switch payload := message.Payload.(type) {
		case *agentv1pb.AgentToControl_Traffic:
			batchID = payload.Traffic.GetBatchId()
		case *agentv1pb.AgentToControl_Logs:
			batchID = payload.Logs.GetBatchId()
		}
		ack := &agentv1pb.ReportAck{BatchId: batchID, ErrorCode: agentcontrol.ReportErrorCodeUnavailable, RetryAfterMs: 200}
		c.mu.Lock()
		c.reportAcks = append(c.reportAcks, proto.Clone(ack).(*agentv1pb.ReportAck))
		c.mu.Unlock()
		return current.send(&agentv1pb.ControlToAgent{
			RequestId: message.RequestId, NodeId: c.NodeID,
			Payload: &agentv1pb.ControlToAgent_ReportAck{ReportAck: ack},
		})
	}
	switch payload := message.Payload.(type) {
	case *agentv1pb.AgentToControl_Traffic:
		batchID = payload.Traffic.GetBatchId()
	case *agentv1pb.AgentToControl_Logs:
		batchID = payload.Logs.GetBatchId()
	}
	ack := &agentv1pb.ReportAck{BatchId: batchID}
	switch {
	case batchID == "" || len(batchID) > 128:
		ack.Error, ack.ErrorCode = "batch_id is required and at most 128 bytes", agentcontrol.ReportErrorCodeBatchIDInvalid
	case c.refuse != nil && c.refuse(batchID) != "":
		ack.Error, ack.ErrorCode = c.refuse(batchID), agentcontrol.ReportErrorCodeInvalid
	case c.batches[batchID]:
		// Recorded before: nothing counts again.
	default:
		c.batches[batchID] = true
		ack.Applied = true
		switch payload := message.Payload.(type) {
		case *agentv1pb.AgentToControl_Traffic:
			for _, user := range payload.Traffic.GetUsers() {
				total := c.appliedTraffic[user.GetUserId()]
				c.appliedTraffic[user.GetUserId()] = [2]uint64{total[0] + user.GetUploadBytes(), total[1] + user.GetDownloadBytes()}
			}
			c.online = nil
			for _, online := range payload.Traffic.GetOnline() {
				c.online = append(c.online, proto.Clone(online).(*agentv1pb.OnlineUser))
			}
		case *agentv1pb.AgentToControl_Logs:
			for _, entry := range payload.Logs.GetEntries() {
				c.logEntries = append(c.logEntries, proto.Clone(entry).(*agentv1pb.LogEntry))
			}
		}
	}
	if ack.Applied && c.loseAcks > 0 {
		c.loseAcks--
		c.mu.Unlock()
		return nil
	}
	c.reportAcks = append(c.reportAcks, proto.Clone(ack).(*agentv1pb.ReportAck))
	c.mu.Unlock()
	return current.send(&agentv1pb.ControlToAgent{
		RequestId: message.RequestId, NodeId: c.NodeID,
		Payload: &agentv1pb.ControlToAgent_ReportAck{ReportAck: ack},
	})
}

// Traffic returns the bytes recorded per user (upload, download): each
// batch counts once.
func (c *Control) Traffic() map[uint64][2]uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	traffic := make(map[uint64][2]uint64, len(c.appliedTraffic))
	for id, bytes := range c.appliedTraffic {
		traffic[id] = bytes
	}
	return traffic
}

// Online returns the node's alive set, as the last recorded report left it.
func (c *Control) Online() []*agentv1pb.OnlineUser {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*agentv1pb.OnlineUser(nil), c.online...)
}

// Batches returns the recorded batch ids.
func (c *Control) Batches() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	batches := make([]string, 0, len(c.batches))
	for id := range c.batches {
		batches = append(batches, id)
	}
	sort.Strings(batches)
	return batches
}

// Deliveries counts the TrafficReport and LogBatch messages received,
// resends included.
func (c *Control) Deliveries() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deliveries
}

// ReportAcks returns every ReportAck sent.
func (c *Control) ReportAcks() []*agentv1pb.ReportAck {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*agentv1pb.ReportAck(nil), c.reportAcks...)
}

// LogEntries returns the recorded log entries.
func (c *Control) LogEntries() []*agentv1pb.LogEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*agentv1pb.LogEntry(nil), c.logEntries...)
}

// NodeStatuses returns every NodeStatus received.
func (c *Control) NodeStatuses() []*agentv1pb.NodeStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*agentv1pb.NodeStatus(nil), c.nodeStatuses...)
}

// PackageReports returns every PackageReport received.
func (c *Control) PackageReports() []*agentv1pb.PackageReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*agentv1pb.PackageReport(nil), c.packageReports...)
}

func metadataValue(ctx context.Context, key string) string {
	md, _ := metadata.FromIncomingContext(ctx)
	if values := md.Get(key); len(values) > 0 {
		return values[0]
	}
	return ""
}

func peerChain(ctx context.Context) []*x509.Certificate {
	remote, ok := peer.FromContext(ctx)
	if !ok {
		return nil
	}
	info, ok := remote.AuthInfo.(grpccredentials.TLSInfo)
	if !ok {
		return nil
	}
	return info.State.PeerCertificates
}

func (c *Control) verifyPeer(ctx context.Context, chain []*x509.Certificate) (*x509.Certificate, error) {
	roots := x509.NewCertPool()
	roots.AddCert(c.agentCACert)
	leaf := chain[0]
	c.mu.Lock()
	refusal := c.refuseCertificate
	if !c.refusedSerials[hex.EncodeToString(leaf.SerialNumber.Bytes())] {
		refusal = ""
	}
	c.mu.Unlock()
	if refusal != "" {
		return nil, refuse(ctx, codes.Unauthenticated, refusal, "the agent certificate is refused")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, refuse(ctx, codes.Unauthenticated, agentcontrol.ErrorCodeCertInvalid, "the client certificate is not a valid agent certificate of this cluster")
	}
	identity, err := agentcontrol.AgentIdentityFromCertificate(leaf)
	switch {
	case err != nil:
		return nil, refuse(ctx, codes.Unauthenticated, agentcontrol.ErrorCodeCertInvalid, "the client certificate is not an agent certificate")
	case identity.Cluster != c.Cluster:
		return nil, refuse(ctx, codes.Unauthenticated, agentcontrol.ErrorCodeCertWrongCluster, "the client certificate is of another cluster")
	case identity.Node.ID != c.NodeID:
		return nil, refuse(ctx, codes.Unauthenticated, agentcontrol.ErrorCodeCertWrongNode, "the client certificate names another node")
	}
	return leaf, nil
}

// refuse answers a call with Control's error code: in the trailer and at
// the start of the status message.
func refuse(ctx context.Context, code codes.Code, errorCode, message string) error {
	_ = grpc.SetTrailer(ctx, metadata.Pairs(agentcontrol.MetadataErrorCode, errorCode))
	return status.Error(code, errorCode+": "+message)
}

// RefuseCertificates makes the check of every certificate issued so far
// fail with errorCode (agent_cert_revoked, ...), as a revocation would;
// later certificates are accepted. "" accepts them all again.
func (c *Control) RefuseCertificates(errorCode string) {
	c.mu.Lock()
	c.refuseCertificate = errorCode
	c.refusedSerials = map[string]bool{}
	if errorCode != "" {
		for _, serial := range c.issued {
			c.refusedSerials[serial] = true
		}
	}
	c.mu.Unlock()
}

func (c *Control) issue(csrDER []byte) (*agentv1pb.AgentCertificate, error) {
	request, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || request.CheckSignature() != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid CSR")
	}
	serialBytes := make([]byte, 16)
	_, _ = rand.Read(serialBytes)
	serialBytes[0] &= 0x7f
	serial := new(big.Int).SetBytes(serialBytes)
	now := time.Now()
	notAfter := now.Add(7 * 24 * time.Hour)
	identity, err := agentcontrol.NewAgentIdentity(c.Cluster, c.node())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: identity.String()},
		NotBefore: now.Add(-time.Second), NotAfter: notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:        []*url.URL{identity.URL()}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.agentCACert, request.PublicKey, c.agentCAKey)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	serialHex := hex.EncodeToString(serial.Bytes())
	c.mu.Lock()
	c.issued = append(c.issued, serialHex)
	c.mu.Unlock()
	return &agentv1pb.AgentCertificate{
		CertificateDer: der, TrustBundleDer: [][]byte{c.agentCACert.Raw}, SpiffeId: identity.String(),
		Node: identity.Node.String(), Serial: serialHex, NotAfterUnix: notAfter.Unix(),
		RenewAfterUnix: now.Add(notAfter.Sub(now) * 2 / 3).Unix(),
	}, nil
}

// Enroll implements AgentEnrollment.Enroll: a one-time credential in every
// mode but off, the node API key in optional and preferred.
func (c *Control) Enroll(ctx context.Context, request *agentv1pb.EnrollAgentRequest) (*agentv1pb.EnrollAgentResponse, error) {
	mode := c.Mode()
	if mode == ModeOff {
		return nil, status.Error(codes.FailedPrecondition, "agent enrollment needs the built-in CA")
	}
	if metadataValue(ctx, agentcontrol.MetadataNodeID) != strconv.FormatUint(uint64(c.NodeID), 10) {
		return nil, refuse(ctx, codes.Unauthenticated, agentcontrol.ErrorCodeEnrollmentRejected, "agent enrollment rejected")
	}
	if kind := metadataValue(ctx, agentcontrol.MetadataNodeKind); (kind == "" && c.node().Kind != agentcontrol.NodeKindProxy) || (kind != "" && kind != c.node().Kind) {
		return nil, refuse(ctx, codes.Unauthenticated, agentcontrol.ErrorCodeEnrollmentRejected, "agent enrollment rejected: another node kind")
	}
	if credential := request.EnrollmentCredential; credential != "" {
		c.mu.Lock()
		used, known := c.credentials[credential]
		if known && !used {
			c.credentials[credential] = true
		}
		c.mu.Unlock()
		if !known || used {
			return nil, refuse(ctx, codes.Unauthenticated, agentcontrol.ErrorCodeEnrollmentRejected, "agent enrollment rejected")
		}
	} else {
		if mode == ModeRequired {
			_ = grpc.SetTrailer(ctx, metadata.Pairs(agentcontrol.MetadataErrorCode, agentcontrol.ErrorCodeMTLSRequired))
			return nil, status.Error(codes.Unauthenticated, agentcontrol.ErrorCodeMTLSRequired+": an enrollment credential is required (agent_control.mtls: required)")
		}
		if metadataValue(ctx, agentcontrol.MetadataAPIKey) != c.APIKey {
			return nil, refuse(ctx, codes.Unauthenticated, agentcontrol.ErrorCodeEnrollmentRejected, "agent enrollment rejected")
		}
	}
	certificate, err := c.issue(request.CsrDer)
	if err != nil {
		return nil, err
	}
	return &agentv1pb.EnrollAgentResponse{Certificate: certificate}, nil
}

// Renew implements AgentEnrollment.Renew.
func (c *Control) Renew(ctx context.Context, request *agentv1pb.RenewAgentCertificateRequest) (*agentv1pb.RenewAgentCertificateResponse, error) {
	chain := peerChain(ctx)
	if len(chain) == 0 {
		return nil, refuse(ctx, codes.Unauthenticated, agentcontrol.ErrorCodeCertInvalid, "renewal requires the current agent client certificate")
	}
	if _, err := c.verifyPeer(ctx, chain); err != nil {
		return nil, err
	}
	certificate, err := c.issue(request.CsrDer)
	if err != nil {
		return nil, err
	}
	return &agentv1pb.RenewAgentCertificateResponse{Certificate: certificate}, nil
}

// serverCapabilities lists what Control serves to an agent's Hello, as
// AgentControlGRPCServer.serverCapabilities: the offer rule, the
// intersection of what the agent lists and what Control serves the node;
// artifacts.v1 only on a session authenticated by client certificate;
// reports.v1 echoes transient_ack when the agent asked for it.
func (c *Control) serverCapabilities(hello *agentv1pb.Hello, certificate bool) []*agentv1pb.Capability {
	c.mu.Lock()
	defer c.mu.Unlock()
	var capabilities []*agentv1pb.Capability
	forward := c.servesForwardLocked(hello)
	for _, name := range agentcontrol.DataPlaneCapabilities {
		if !c.serves[name] || !agentcontrol.HasCapabilityVersion(hello.GetCapabilities(), name, agentcontrol.CapabilityVersionV1) {
			continue
		}
		if name == agentcontrol.CapabilityArtifacts && !certificate {
			continue
		}
		if !c.offersLocked(name, forward) {
			continue
		}
		capability := &agentv1pb.Capability{Name: name, Version: agentcontrol.CapabilityVersionV1}
		echo := []*agentv1pb.Capability{{Name: name, Version: agentcontrol.CapabilityVersionV1, Attributes: map[string]string{agentcontrol.ReportsAttributeTransientAck: agentcontrol.ReportsTransientAckV1}}}
		if name == agentcontrol.CapabilityReports && c.transientAcks && agentcontrol.TransientReportAcks(hello.GetCapabilities(), echo) {
			capability.Attributes = map[string]string{agentcontrol.ReportsAttributeTransientAck: agentcontrol.ReportsTransientAckV1}
		}
		capabilities = append(capabilities, capability)
	}
	return capabilities
}

// ControlStream implements AgentControlService.ControlStream.
func (c *Control) ControlStream(stream agentv1pb.AgentControlService_ControlStreamServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	c.mu.Lock()
	if c.refuseStreams {
		c.mu.Unlock()
		return status.Error(codes.Unavailable, "control is unavailable")
	}
	index := len(c.streams)
	c.streams = append(c.streams, StreamAuth{APIKey: metadataValue(ctx, agentcontrol.MetadataAPIKey) != ""})
	mode := c.mode
	c.mu.Unlock()
	update := func(change func(*StreamAuth)) {
		c.mu.Lock()
		change(&c.streams[index])
		c.mu.Unlock()
	}
	certificate := false
	if chain := peerChain(ctx); len(chain) > 0 && mode != ModeOff {
		leaf, err := c.verifyPeer(ctx, chain)
		if err != nil {
			return err
		}
		certificate = true
		update(func(record *StreamAuth) { record.CertificateSerial = hex.EncodeToString(leaf.SerialNumber.Bytes()) })
	} else {
		if c.node().Kind == agentcontrol.NodeKindForward {
			// A forward node's token never authenticates the stream.
			return status.Error(codes.Unauthenticated, "a forward node authenticates the stream with its client certificate")
		}
		if mode == ModeRequired {
			stream.SetTrailer(metadata.Pairs(agentcontrol.MetadataErrorCode, agentcontrol.ErrorCodeMTLSRequired))
			return status.Error(codes.Unauthenticated, agentcontrol.ErrorCodeMTLSRequired+": an agent client certificate is required (agent_control.mtls: required)")
		}
		if metadataValue(ctx, agentcontrol.MetadataAPIKey) != c.APIKey ||
			metadataValue(ctx, agentcontrol.MetadataNodeID) != strconv.FormatUint(uint64(c.NodeID), 10) {
			return status.Error(codes.Unauthenticated, "invalid node credentials")
		}
	}

	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil || first.NodeId != c.NodeID {
		return status.Error(codes.PermissionDenied, "hello node_id does not match authenticated node")
	}
	update(func(record *StreamAuth) { record.Accepted = true })
	serverCapabilities := c.serverCapabilities(hello, certificate)
	c.mu.Lock()
	c.sessionSeq++
	current := &session{
		id: "session-" + strconv.Itoa(c.sessionSeq), stream: stream, cancel: cancel,
		hello: proto.Clone(hello).(*agentv1pb.Hello), negotiated: map[string]bool{},
		transientAcks: agentcontrol.TransientReportAcks(hello.GetCapabilities(), serverCapabilities),
	}
	for _, capability := range serverCapabilities {
		if agentcontrol.HasCapabilityVersion(hello.Capabilities, capability.Name, capability.Version) {
			current.negotiated[capability.Name] = true
		}
	}
	if current.negotiated[agentcontrol.CapabilityConfig] {
		current.configRev = hello.GetConfigRevision()
	}
	heartbeat := c.recordForwardHelloLocked(current, hello)
	c.hellos = append(c.hellos, proto.Clone(hello).(*agentv1pb.Hello))
	c.sessions[current.id] = current
	desired := c.desired
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.sessions, current.id)
		c.mu.Unlock()
	}()

	if err := current.send(&agentv1pb.ControlToAgent{
		RequestId: first.RequestId, NodeId: c.NodeID,
		Payload: &agentv1pb.ControlToAgent_HelloAck{HelloAck: &agentv1pb.HelloAck{
			SessionId: current.id, HeartbeatIntervalSeconds: heartbeat, ServerCapabilities: serverCapabilities,
		}},
	}); err != nil {
		return err
	}
	if current.negotiated[agentcontrol.CapabilityConfig] && desired != nil {
		// Hello reconcile: the desired configuration unless the agent
		// reported its revision.
		if err := c.sendConfig(current, desired, false); err != nil {
			return err
		}
	}
	if current.negotiated[agentcontrol.CapabilityUsers] {
		if err := c.startUsers(current, hello.GetUsersCursor()); err != nil {
			return err
		}
	}
	if current.negotiated[agentcontrol.CapabilityAlive] {
		if err := c.sendAlive(current); err != nil {
			return err
		}
	}

	received := make(chan *agentv1pb.AgentToControl)
	receiveErr := make(chan error, 1)
	go func() {
		for {
			message, err := stream.Recv()
			if err != nil {
				receiveErr <- err
				return
			}
			select {
			case received <- message:
			case <-ctx.Done():
				return
			}
		}
	}()
	for {
		var message *agentv1pb.AgentToControl
		select {
		case <-ctx.Done():
			return status.Error(codes.Unavailable, "session dropped")
		case err := <-receiveErr:
			return err
		case message = <-received:
		}
		if message.NodeId != c.NodeID {
			return status.Error(codes.PermissionDenied, "message node_id does not match authenticated node")
		}
		c.mu.Lock()
		c.received = append(c.received, proto.Clone(message).(*agentv1pb.AgentToControl))
		c.mu.Unlock()
		if err := c.handle(current, message); err != nil {
			return err
		}
	}
}

// handle answers one message after Hello. An error ends the stream, as
// Control's InvalidArgument for an unnegotiated payload does.
func (c *Control) handle(current *session, message *agentv1pb.AgentToControl) error {
	switch payload := message.Payload.(type) {
	case *agentv1pb.AgentToControl_Heartbeat:
		return current.send(&agentv1pb.ControlToAgent{
			RequestId: message.RequestId, NodeId: c.NodeID,
			Payload: &agentv1pb.ControlToAgent_HeartbeatAck{HeartbeatAck: &agentv1pb.HeartbeatAck{SessionId: payload.Heartbeat.GetSessionId()}},
		})
	case *agentv1pb.AgentToControl_ConfigStatus:
		if !current.negotiated[agentcontrol.CapabilityConfig] {
			return status.Error(codes.InvalidArgument, "config_status needs capability config.v1")
		}
		if payload.ConfigStatus.GetConfigRevision() == 0 {
			return status.Error(codes.InvalidArgument, "config_status config_revision is required")
		}
		c.mu.Lock()
		c.statuses = append(c.statuses, proto.Clone(payload.ConfigStatus).(*agentv1pb.ConfigStatus))
		c.mu.Unlock()
	case *agentv1pb.AgentToControl_Traffic, *agentv1pb.AgentToControl_Logs:
		if !current.negotiated[agentcontrol.CapabilityReports] {
			return status.Error(codes.InvalidArgument, "report needs capability reports.v1")
		}
		return c.handleBatch(current, message)
	case *agentv1pb.AgentToControl_Status:
		if !current.negotiated[agentcontrol.CapabilityReports] {
			return status.Error(codes.InvalidArgument, "status needs capability reports.v1")
		}
		c.mu.Lock()
		c.nodeStatuses = append(c.nodeStatuses, proto.Clone(payload.Status).(*agentv1pb.NodeStatus))
		c.mu.Unlock()
	case *agentv1pb.AgentToControl_PackageReport:
		if !current.negotiated[agentcontrol.CapabilityPackageReports] {
			return status.Error(codes.InvalidArgument, "package_report needs capability package-reports.v1")
		}
		if wire.IsReport(payload.PackageReport) {
			c.handleForwardReport(current, payload.PackageReport)
			return nil
		}
		c.mu.Lock()
		c.packageReports = append(c.packageReports, proto.Clone(payload.PackageReport).(*agentv1pb.PackageReport))
		c.mu.Unlock()
	case *agentv1pb.AgentToControl_MaintenanceEvents:
		if !current.negotiated[agentcontrol.CapabilityMaintenance] {
			return status.Error(codes.InvalidArgument, agentcontrol.ErrorCodeCapabilityNotNegotiated+": maintenance_events needs capability maintenance.v1")
		}
		return c.handleMaintenance(current, message.RequestId, payload.MaintenanceEvents)
	case *agentv1pb.AgentToControl_OperationAck:
		c.recordOperationAck(payload.OperationAck)
	case *agentv1pb.AgentToControl_ObservedState:
		c.recordObserved(payload.ObservedState)
	default:
		return status.Error(codes.InvalidArgument, fmt.Sprintf("control message payload %T is not handled", payload))
	}
	return nil
}
