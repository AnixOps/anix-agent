package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpccredentials "google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// fakeControl is an in-process Control agent listener with the A2-1 agent
// PKI and the A2-6 agent_control.mtls modes, modelled on anix-control's
// internal/grpc agent_auth.go and agent_enrollment_server.go.
type fakeControl struct {
	agentv1pb.UnimplementedAgentControlServiceServer
	agentv1pb.UnimplementedAgentEnrollmentServer

	t        *testing.T
	nodeID   uint32
	apiKey   string
	cluster  string
	serverCA *x509.CertPool
	address  string
	server   *grpc.Server

	agentCAKey  *ecdsa.PrivateKey
	agentCACert *x509.Certificate

	mu          sync.Mutex
	mode        string
	lifetime    time.Duration
	pkiEnabled  bool
	credentials map[string]bool // one-time credential -> used
	revoked     map[string]bool
	issued      []string
	enrolls     []fakeEnroll
	renews      []fakeRenew
	streams     []fakeStreamAuth
}

type fakeEnroll struct {
	apiKey     bool
	credential bool
	nodeKind   string
	err        codes.Code
}

type fakeRenew struct {
	serial string
	apiKey bool
	err    codes.Code
}

type fakeStreamAuth struct {
	certificateSerial string
	apiKey            bool
	accepted          bool
}

const (
	fakeModeOff       = "off"
	fakeModeOptional  = "optional"
	fakeModePreferred = "preferred"
	fakeModeRequired  = "required"
)

func newFakeControl(t *testing.T, mode string, enrollment bool) *fakeControl {
	t.Helper()
	fake := &fakeControl{
		t: t, nodeID: 12, apiKey: "node-api-key", cluster: "test-cluster", mode: mode,
		lifetime: 7 * 24 * time.Hour, pkiEnabled: true,
		credentials: map[string]bool{}, revoked: map[string]bool{},
	}
	serverCAKey, serverCACert := newTestCA(t, "control server CA")
	fake.serverCA = x509.NewCertPool()
	fake.serverCA.AddCert(serverCACert)
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "control.test"}, DNSNames: []string{"control.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, serverCACert, &serverKey.PublicKey, serverCAKey)
	require.NoError(t, err)
	serverCertificate := tls.Certificate{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}
	fake.agentCAKey, fake.agentCACert = newTestCA(t, "agent CA")

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			config := &tls.Config{Certificates: []tls.Certificate{serverCertificate}, MinVersion: tls.VersionTLS12}
			// As Control: a client certificate is requested, never required
			// in the handshake, unless the mode is off or the PKI disabled.
			if fake.requestsCertificates() {
				config.ClientAuth = tls.RequestClientCert
			}
			return config, nil
		},
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	fake.address = listener.Addr().String()
	fake.server = grpc.NewServer(grpc.Creds(grpccredentials.NewTLS(tlsConfig)))
	agentv1pb.RegisterAgentControlServiceServer(fake.server, fake)
	if enrollment {
		agentv1pb.RegisterAgentEnrollmentServer(fake.server, fake)
	}
	go func() { _ = fake.server.Serve(listener) }()
	t.Cleanup(fake.server.Stop)
	return fake
}

func newTestCA(t *testing.T, name string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, certificate
}

func (f *fakeControl) requestsCertificates() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mode != fakeModeOff && f.pkiEnabled
}

func (f *fakeControl) setMode(mode string) {
	f.mu.Lock()
	f.mode = mode
	f.mu.Unlock()
}

func (f *fakeControl) setLifetime(lifetime time.Duration) {
	f.mu.Lock()
	f.lifetime = lifetime
	f.mu.Unlock()
}

func (f *fakeControl) addCredential(credential string) {
	f.mu.Lock()
	f.credentials[credential] = false
	f.mu.Unlock()
}

func (f *fakeControl) revoke(serial string) {
	f.mu.Lock()
	f.revoked[serial] = true
	f.mu.Unlock()
}

func (f *fakeControl) records() (enrolls []fakeEnroll, renews []fakeRenew, streams []fakeStreamAuth, issued []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeEnroll(nil), f.enrolls...), append([]fakeRenew(nil), f.renews...),
		append([]fakeStreamAuth(nil), f.streams...), append([]string(nil), f.issued...)
}

// client returns an agent control client of this Control's node.
func (f *fakeControl) client(t *testing.T, identity *IdentityConfig) *Client {
	t.Helper()
	client, err := NewClient(Config{
		Target: f.address, NodeID: int(f.nodeID), APIKey: f.apiKey, UseTLS: true, ServerName: "control.test",
		RootCAs: f.serverCA, AgentVersion: "test-agent", InstanceID: "instance-1",
		Capabilities: []*agentv1pb.Capability{{Name: "agent.control", Version: "v1"}},
		Heartbeat:    time.Second, ReconnectMin: 10 * time.Millisecond, ReconnectMax: 50 * time.Millisecond,
		DialTimeout: 2 * time.Second, Identity: identity,
	})
	require.NoError(t, err)
	return client
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

// verifyPeer checks a presented certificate as agentpki.VerifyPeer does.
func (f *fakeControl) verifyPeer(chain []*x509.Certificate) (*x509.Certificate, error) {
	roots := x509.NewCertPool()
	roots.AddCert(f.agentCACert)
	leaf := chain[0]
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, status.Error(codes.Unauthenticated, "the client certificate is not a valid agent certificate of this cluster")
	}
	identity, err := agentcontrol.AgentIdentityFromCertificate(leaf)
	if err != nil || identity.Cluster != f.cluster {
		return nil, status.Error(codes.Unauthenticated, "the client certificate is not a valid agent certificate of this cluster")
	}
	f.mu.Lock()
	revoked := f.revoked[hex.EncodeToString(leaf.SerialNumber.Bytes())]
	f.mu.Unlock()
	if revoked {
		return nil, status.Error(codes.Unauthenticated, "agent client certificate revoked")
	}
	return leaf, nil
}

func (f *fakeControl) issue(csrDER []byte) (*agentv1pb.AgentCertificate, error) {
	request, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || request.CheckSignature() != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid CSR")
	}
	f.mu.Lock()
	lifetime := f.lifetime
	f.mu.Unlock()
	serialBytes := make([]byte, 16)
	_, _ = rand.Read(serialBytes)
	serialBytes[0] &= 0x7f
	serial := new(big.Int).SetBytes(serialBytes)
	now := time.Now()
	notAfter := now.Add(lifetime)
	identity, _ := agentcontrol.NewAgentIdentity(f.cluster, agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: f.nodeID})
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: identity.String()},
		NotBefore: now.Add(-time.Second), NotAfter: notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:        []*url.URL{identity.URL()}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, f.agentCACert, request.PublicKey, f.agentCAKey)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	serialHex := hex.EncodeToString(serial.Bytes())
	f.mu.Lock()
	f.issued = append(f.issued, serialHex)
	f.mu.Unlock()
	return &agentv1pb.AgentCertificate{
		CertificateDer: der, TrustBundleDer: [][]byte{f.agentCACert.Raw}, SpiffeId: identity.String(),
		Node: identity.Node.String(), Serial: serialHex, NotAfterUnix: notAfter.Unix(),
		RenewAfterUnix: now.Add(notAfter.Sub(now) * 2 / 3).Unix(),
	}, nil
}

func (f *fakeControl) Enroll(ctx context.Context, request *agentv1pb.EnrollAgentRequest) (*agentv1pb.EnrollAgentResponse, error) {
	record := fakeEnroll{apiKey: metadataValue(ctx, agentcontrol.MetadataAPIKey) != "", credential: request.EnrollmentCredential != "",
		nodeKind: metadataValue(ctx, agentcontrol.MetadataNodeKind)}
	response, err := f.enroll(ctx, request)
	record.err = status.Code(err)
	f.mu.Lock()
	f.enrolls = append(f.enrolls, record)
	f.mu.Unlock()
	return response, err
}

func (f *fakeControl) enroll(ctx context.Context, request *agentv1pb.EnrollAgentRequest) (*agentv1pb.EnrollAgentResponse, error) {
	f.mu.Lock()
	mode, pkiEnabled := f.mode, f.pkiEnabled
	f.mu.Unlock()
	if mode == fakeModeOff || !pkiEnabled {
		return nil, status.Error(codes.FailedPrecondition, "agent enrollment needs the built-in CA")
	}
	if metadataValue(ctx, agentcontrol.MetadataNodeID) != strconv.FormatUint(uint64(f.nodeID), 10) {
		return nil, status.Error(codes.Unauthenticated, "agent enrollment rejected")
	}
	if credential := request.EnrollmentCredential; credential != "" {
		f.mu.Lock()
		used, known := f.credentials[credential]
		if known && !used {
			f.credentials[credential] = true
		}
		f.mu.Unlock()
		if !known || used {
			return nil, status.Error(codes.Unauthenticated, "agent enrollment rejected")
		}
	} else {
		if mode == fakeModeRequired {
			_ = grpc.SetTrailer(ctx, metadata.Pairs(agentcontrol.MetadataErrorCode, agentcontrol.ErrorCodeMTLSRequired))
			return nil, status.Error(codes.Unauthenticated, agentcontrol.ErrorCodeMTLSRequired+": an enrollment credential is required (agent_control.mtls: required)")
		}
		if metadataValue(ctx, agentcontrol.MetadataAPIKey) != f.apiKey {
			return nil, status.Error(codes.Unauthenticated, "agent enrollment rejected")
		}
	}
	certificate, err := f.issue(request.CsrDer)
	if err != nil {
		return nil, err
	}
	return &agentv1pb.EnrollAgentResponse{Certificate: certificate}, nil
}

func (f *fakeControl) Renew(ctx context.Context, request *agentv1pb.RenewAgentCertificateRequest) (*agentv1pb.RenewAgentCertificateResponse, error) {
	record := fakeRenew{apiKey: metadataValue(ctx, agentcontrol.MetadataAPIKey) != ""}
	response, err := f.renew(ctx, request, &record)
	record.err = status.Code(err)
	f.mu.Lock()
	f.renews = append(f.renews, record)
	f.mu.Unlock()
	return response, err
}

func (f *fakeControl) renew(ctx context.Context, request *agentv1pb.RenewAgentCertificateRequest, record *fakeRenew) (*agentv1pb.RenewAgentCertificateResponse, error) {
	chain := peerChain(ctx)
	if len(chain) == 0 {
		return nil, status.Error(codes.Unauthenticated, "renewal requires the current agent client certificate")
	}
	record.serial = hex.EncodeToString(chain[0].SerialNumber.Bytes())
	if _, err := f.verifyPeer(chain); err != nil {
		if status.Convert(err).Message() == "agent client certificate revoked" {
			return nil, status.Error(codes.Unauthenticated, "agent certificate revoked")
		}
		return nil, err
	}
	certificate, err := f.issue(request.CsrDer)
	if err != nil {
		return nil, err
	}
	return &agentv1pb.RenewAgentCertificateResponse{Certificate: certificate}, nil
}

func (f *fakeControl) ControlStream(stream agentv1pb.AgentControlService_ControlStreamServer) error {
	ctx := stream.Context()
	f.mu.Lock()
	index := len(f.streams)
	f.streams = append(f.streams, fakeStreamAuth{apiKey: metadataValue(ctx, agentcontrol.MetadataAPIKey) != ""})
	f.mu.Unlock()
	update := func(change func(*fakeStreamAuth)) {
		f.mu.Lock()
		change(&f.streams[index])
		f.mu.Unlock()
	}
	var leaf *x509.Certificate
	if chain := peerChain(ctx); len(chain) > 0 {
		verified, err := f.verifyPeer(chain)
		if err != nil {
			return err
		}
		leaf = verified
		update(func(record *fakeStreamAuth) {
			record.certificateSerial = hex.EncodeToString(verified.SerialNumber.Bytes())
		})
		if id := metadataValue(ctx, agentcontrol.MetadataNodeID); id != "" && id != strconv.FormatUint(uint64(f.nodeID), 10) {
			return status.Error(codes.Unauthenticated, "x-node-id does not match the client certificate")
		}
	} else {
		f.mu.Lock()
		mode := f.mode
		f.mu.Unlock()
		if mode == fakeModeRequired {
			stream.SetTrailer(metadata.Pairs(agentcontrol.MetadataErrorCode, agentcontrol.ErrorCodeMTLSRequired,
				agentcontrol.MetadataAuthDeprecated, "node API key authentication is deprecated"))
			return status.Error(codes.Unauthenticated, agentcontrol.ErrorCodeMTLSRequired+": an agent client certificate is required (agent_control.mtls: required)")
		}
		if metadataValue(ctx, agentcontrol.MetadataAPIKey) != f.apiKey ||
			metadataValue(ctx, agentcontrol.MetadataNodeID) != strconv.FormatUint(uint64(f.nodeID), 10) {
			return status.Error(codes.Unauthenticated, "invalid node credentials")
		}
		if mode == fakeModePreferred {
			deprecation := metadata.Pairs(agentcontrol.MetadataAuthDeprecated, "node API key authentication is deprecated")
			if err := stream.SetHeader(deprecation); err != nil {
				return err
			}
		}
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if first.GetHello() == nil || first.NodeId != f.nodeID {
		return status.Error(codes.PermissionDenied, "hello node_id does not match authenticated node")
	}
	update(func(record *fakeStreamAuth) { record.accepted = true })
	if err := stream.Send(&agentv1pb.ControlToAgent{
		RequestId: first.RequestId, NodeId: f.nodeID,
		Payload: &agentv1pb.ControlToAgent_HelloAck{HelloAck: &agentv1pb.HelloAck{SessionId: "session-" + strconv.FormatInt(time.Now().UnixNano(), 10), HeartbeatIntervalSeconds: 1}},
	}); err != nil {
		return err
	}
	for {
		message, err := stream.Recv()
		if err != nil {
			return err
		}
		heartbeat := message.GetHeartbeat()
		if heartbeat == nil {
			continue
		}
		// As Control: a certificate revoked or expired while the stream is
		// open ends it at the next heartbeat.
		if leaf != nil {
			if !time.Now().Before(leaf.NotAfter) {
				return status.Error(codes.Unauthenticated, "agent client certificate expired")
			}
			f.mu.Lock()
			revoked := f.revoked[hex.EncodeToString(leaf.SerialNumber.Bytes())]
			f.mu.Unlock()
			if revoked {
				return status.Error(codes.Unauthenticated, "agent client certificate revoked")
			}
		}
		if err := stream.Send(&agentv1pb.ControlToAgent{
			RequestId: message.RequestId, NodeId: f.nodeID,
			Payload: &agentv1pb.ControlToAgent_HeartbeatAck{HeartbeatAck: &agentv1pb.HeartbeatAck{SessionId: heartbeat.SessionId}},
		}); err != nil {
			return err
		}
	}
}
