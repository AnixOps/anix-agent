// Package agenttest is an in-process Control for tests of the Agent control
// stream: the AgentControlService and AgentEnrollment of anix-control's
// agent listener over TLS, with the agent PKI (A2-1), the
// agent_control.mtls modes (A2-6) and the data plane (A2-3: configuration
// snapshots and ConfigStatus), modelled on anix-control's internal/grpc
// agent_control_server.go and agent_control_config.go.
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
	"strconv"
	"sync"
	"testing"
	"time"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
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

	NodeID  uint32
	APIKey  string
	Cluster string
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
	}
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

func (c *Control) verifyPeer(chain []*x509.Certificate) (*x509.Certificate, error) {
	roots := x509.NewCertPool()
	roots.AddCert(c.agentCACert)
	leaf := chain[0]
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, status.Error(codes.Unauthenticated, "the client certificate is not a valid agent certificate of this cluster")
	}
	identity, err := agentcontrol.AgentIdentityFromCertificate(leaf)
	if err != nil || identity.Cluster != c.Cluster || identity.Node.ID != c.NodeID {
		return nil, status.Error(codes.Unauthenticated, "the client certificate is not a valid agent certificate of this node")
	}
	return leaf, nil
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
	identity, err := agentcontrol.NewAgentIdentity(c.Cluster, agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: c.NodeID})
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
		return nil, status.Error(codes.Unauthenticated, "agent enrollment rejected")
	}
	if credential := request.EnrollmentCredential; credential != "" {
		c.mu.Lock()
		used, known := c.credentials[credential]
		if known && !used {
			c.credentials[credential] = true
		}
		c.mu.Unlock()
		if !known || used {
			return nil, status.Error(codes.Unauthenticated, "agent enrollment rejected")
		}
	} else {
		if mode == ModeRequired {
			_ = grpc.SetTrailer(ctx, metadata.Pairs(agentcontrol.MetadataErrorCode, agentcontrol.ErrorCodeMTLSRequired))
			return nil, status.Error(codes.Unauthenticated, agentcontrol.ErrorCodeMTLSRequired+": an enrollment credential is required (agent_control.mtls: required)")
		}
		if metadataValue(ctx, agentcontrol.MetadataAPIKey) != c.APIKey {
			return nil, status.Error(codes.Unauthenticated, "agent enrollment rejected")
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
		return nil, status.Error(codes.Unauthenticated, "renewal requires the current agent client certificate")
	}
	if _, err := c.verifyPeer(chain); err != nil {
		return nil, err
	}
	certificate, err := c.issue(request.CsrDer)
	if err != nil {
		return nil, err
	}
	return &agentv1pb.RenewAgentCertificateResponse{Certificate: certificate}, nil
}

// serverCapabilities lists what Control serves to an agent's Hello, as
// AgentControlGRPCServer.serverCapabilities: config, reports and
// package-reports when the agent lists them too, users always.
func (c *Control) serverCapabilities(hello *agentv1pb.Hello) []*agentv1pb.Capability {
	c.mu.Lock()
	defer c.mu.Unlock()
	var capabilities []*agentv1pb.Capability
	for _, name := range []string{agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers, agentcontrol.CapabilityReports, agentcontrol.CapabilityPackageReports} {
		if !c.serves[name] {
			continue
		}
		if name != agentcontrol.CapabilityUsers && !agentcontrol.HasCapabilityVersion(hello.GetCapabilities(), name, agentcontrol.CapabilityVersionV1) {
			continue
		}
		capabilities = append(capabilities, &agentv1pb.Capability{Name: name, Version: agentcontrol.CapabilityVersionV1})
	}
	return capabilities
}

// ControlStream implements AgentControlService.ControlStream.
func (c *Control) ControlStream(stream agentv1pb.AgentControlService_ControlStreamServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	c.mu.Lock()
	index := len(c.streams)
	c.streams = append(c.streams, StreamAuth{APIKey: metadataValue(ctx, agentcontrol.MetadataAPIKey) != ""})
	mode := c.mode
	c.mu.Unlock()
	update := func(change func(*StreamAuth)) {
		c.mu.Lock()
		change(&c.streams[index])
		c.mu.Unlock()
	}
	if chain := peerChain(ctx); len(chain) > 0 && mode != ModeOff {
		leaf, err := c.verifyPeer(chain)
		if err != nil {
			return err
		}
		update(func(record *StreamAuth) { record.CertificateSerial = hex.EncodeToString(leaf.SerialNumber.Bytes()) })
	} else {
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
	serverCapabilities := c.serverCapabilities(hello)
	c.mu.Lock()
	c.sessionSeq++
	current := &session{
		id: "session-" + strconv.Itoa(c.sessionSeq), stream: stream, cancel: cancel,
		hello: proto.Clone(hello).(*agentv1pb.Hello), negotiated: map[string]bool{},
	}
	for _, capability := range serverCapabilities {
		if agentcontrol.HasCapabilityVersion(hello.Capabilities, capability.Name, capability.Version) {
			current.negotiated[capability.Name] = true
		}
	}
	if current.negotiated[agentcontrol.CapabilityConfig] {
		current.configRev = hello.GetConfigRevision()
	}
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
			SessionId: current.id, HeartbeatIntervalSeconds: 1, ServerCapabilities: serverCapabilities,
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
	case *agentv1pb.AgentToControl_Traffic, *agentv1pb.AgentToControl_Logs, *agentv1pb.AgentToControl_Status:
		if !current.negotiated[agentcontrol.CapabilityReports] {
			return status.Error(codes.InvalidArgument, "report needs capability reports.v1")
		}
	case *agentv1pb.AgentToControl_PackageReport:
		if !current.negotiated[agentcontrol.CapabilityPackageReports] {
			return status.Error(codes.InvalidArgument, "package_report needs capability package-reports.v1")
		}
	case *agentv1pb.AgentToControl_OperationAck, *agentv1pb.AgentToControl_ObservedState:
	default:
		return status.Error(codes.InvalidArgument, fmt.Sprintf("control message payload %T is not handled", payload))
	}
	return nil
}
