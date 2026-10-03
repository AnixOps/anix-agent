package agent

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// negotiationControlServer is a scripted A2 Control: it answers Hello with
// server capabilities and optional deprecation metadata, may refuse the
// API key as agent_control.mtls: required does, and can push extra
// messages after the HelloAck.
type negotiationControlServer struct {
	agentv1pb.UnimplementedAgentControlServiceServer
	nodeID             uint32
	serverCapabilities []*agentv1pb.Capability
	deprecation        metadata.MD
	refuseMTLSRequired bool
	// refusalCodeInTrailer and refusalCodeInMessage place the
	// agent_mtls_required code of a refusal.
	refusalCodeInTrailer bool
	refusalCodeInMessage bool
	afterHello           []*agentv1pb.ControlToAgent

	mu         sync.Mutex
	hellos     []*agentv1pb.Hello
	heartbeats []*agentv1pb.Heartbeat
	attempts   int
}

func (s *negotiationControlServer) ControlStream(stream agentv1pb.AgentControlService_ControlStreamServer) error {
	s.mu.Lock()
	s.attempts++
	s.mu.Unlock()
	if s.refuseMTLSRequired {
		trailer := metadata.Pairs(agentcontrol.MetadataAuthDeprecated, "node API key authentication is deprecated")
		if s.refusalCodeInTrailer {
			trailer.Set(agentcontrol.MetadataErrorCode, agentcontrol.ErrorCodeMTLSRequired)
		}
		stream.SetTrailer(trailer)
		message := "an agent client certificate is required (agent_control.mtls: required)"
		if s.refusalCodeInMessage {
			message = agentcontrol.ErrorCodeMTLSRequired + ": " + message
		}
		return status.Error(codes.Unauthenticated, message)
	}
	if s.deprecation != nil {
		if err := stream.SetHeader(s.deprecation); err != nil {
			return err
		}
		stream.SetTrailer(s.deprecation)
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.hellos = append(s.hellos, proto.Clone(first.GetHello()).(*agentv1pb.Hello))
	s.mu.Unlock()
	if err := stream.Send(&agentv1pb.ControlToAgent{
		RequestId: first.RequestId, NodeId: s.nodeID, SentAtUnixMs: time.Now().UnixMilli(),
		Payload: &agentv1pb.ControlToAgent_HelloAck{HelloAck: &agentv1pb.HelloAck{
			SessionId: "negotiation-session", HeartbeatIntervalSeconds: 1, ServerCapabilities: s.serverCapabilities,
		}},
	}); err != nil {
		return err
	}
	for _, message := range s.afterHello {
		if err := stream.Send(message); err != nil {
			return err
		}
	}
	for {
		message, err := stream.Recv()
		if err != nil {
			return err
		}
		if heartbeat := message.GetHeartbeat(); heartbeat != nil {
			s.mu.Lock()
			s.heartbeats = append(s.heartbeats, proto.Clone(heartbeat).(*agentv1pb.Heartbeat))
			s.mu.Unlock()
			if err := stream.Send(&agentv1pb.ControlToAgent{
				RequestId: message.RequestId, NodeId: s.nodeID,
				Payload: &agentv1pb.ControlToAgent_HeartbeatAck{HeartbeatAck: &agentv1pb.HeartbeatAck{SessionId: heartbeat.SessionId}},
			}); err != nil {
				return err
			}
		}
	}
}

func (s *negotiationControlServer) snapshot() (hellos []*agentv1pb.Hello, heartbeats []*agentv1pb.Heartbeat, attempts int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*agentv1pb.Hello(nil), s.hellos...), append([]*agentv1pb.Heartbeat(nil), s.heartbeats...), s.attempts
}

func startNegotiationServer(t *testing.T, server *negotiationControlServer) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	grpcServer := grpc.NewServer()
	agentv1pb.RegisterAgentControlServiceServer(grpcServer, server)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(grpcServer.Stop)
	return listener.Addr().String()
}

func newNegotiationClient(t *testing.T, target string) *Client {
	t.Helper()
	client, err := NewClient(Config{
		Target: target, NodeID: 7, APIKey: "node-key", AgentVersion: "test-agent",
		Capabilities: []*agentv1pb.Capability{{Name: "agent.control", Version: "v1"}},
		Heartbeat:    time.Second, ReconnectMin: 10 * time.Millisecond, ReconnectMax: 50 * time.Millisecond,
	})
	require.NoError(t, err)
	require.NoError(t, client.Start())
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func waitReady(t *testing.T, client *Client) {
	t.Helper()
	select {
	case <-client.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("agent control client did not become ready")
	}
}

func dataPlaneServerCapabilities() []*agentv1pb.Capability {
	return []*agentv1pb.Capability{
		{Name: agentcontrol.CapabilityConfig, Version: agentcontrol.CapabilityVersionV1},
		{Name: agentcontrol.CapabilityUsers, Version: agentcontrol.CapabilityVersionV1},
		{Name: agentcontrol.CapabilityReports, Version: agentcontrol.CapabilityVersionV1},
	}
}

func TestClientParsesServerCapabilitiesAndNegotiatesOnlyWhatItAdvertises(t *testing.T) {
	server := &negotiationControlServer{nodeID: 7, serverCapabilities: dataPlaneServerCapabilities()}
	client := newNegotiationClient(t, startNegotiationServer(t, server))
	waitReady(t, client)

	assert.ElementsMatch(t, []string{"config.v1", "reports.v1", "users.v1"}, capabilityNames(client.ServerCapabilities()))
	for _, name := range []string{agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers, agentcontrol.CapabilityReports} {
		assert.False(t, client.Negotiated(name), "%s must not be negotiated before the Agent implements it", name)
	}
	status := client.TransportStatus()
	assert.True(t, status.Connected)
	assert.Equal(t, "api-key", status.Authentication)
	assert.Equal(t, []string{"config.v1", "reports.v1", "users.v1"}, status.ServerCapabilities)
	assert.Empty(t, status.Negotiated)
	assert.Nil(t, status.Deprecation)

	hellos, _, _ := server.snapshot()
	require.Len(t, hellos, 1)
	assert.Equal(t, agentcontrol.ProtocolV1, hellos[0].Protocol)
	for _, name := range dataPlaneCapabilities {
		assert.False(t, agentcontrol.HasCapability(hellos[0].Capabilities, name), "Hello must not advertise %s", name)
	}
	assert.Zero(t, hellos[0].ConfigRevision)
	assert.Zero(t, hellos[0].UsersCursor)
}

func TestClientWorksWithControlThatAdvertisesNoServerCapabilities(t *testing.T) {
	server := &negotiationControlServer{nodeID: 7}
	client := newNegotiationClient(t, startNegotiationServer(t, server))
	waitReady(t, client)
	assert.Empty(t, client.ServerCapabilities())
	assert.False(t, client.Negotiated(agentcontrol.CapabilityUsers))
	assert.Empty(t, client.TransportStatus().ServerCapabilities)
}

func TestClientNegotiatedIsFalseWhileDisconnected(t *testing.T) {
	client, err := NewClient(Config{Target: "unused:1", NodeID: 1, APIKey: "key", AgentVersion: "test-agent"})
	require.NoError(t, err)
	client.mu.Lock()
	client.serverCapabilities = dataPlaneServerCapabilities()
	client.mu.Unlock()
	assert.Nil(t, client.ServerCapabilities())
	assert.False(t, client.Negotiated(agentcontrol.CapabilityConfig))
}

func TestNewClientRefusesUnimplementedDataPlaneCapabilities(t *testing.T) {
	for _, name := range dataPlaneCapabilities {
		_, err := NewClient(Config{
			Target: "unused:1", NodeID: 1, APIKey: "key", AgentVersion: "test-agent",
			Capabilities: []*agentv1pb.Capability{{Name: name, Version: agentcontrol.CapabilityVersionV1}},
		})
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), name+".v1")
	}
}

func TestClientRecordsDeprecationSignalAndReportsItInHeartbeats(t *testing.T) {
	server := &negotiationControlServer{nodeID: 7, deprecation: metadata.Pairs(
		agentcontrol.MetadataAuthDeprecated, "node API key authentication is deprecated",
		agentcontrol.MetadataAuthDeprecationLink, "https://example.test/upgrade",
		agentcontrol.MetadataAuthSunset, "Fri, 01 Jan 2027 00:00:00 GMT",
	)}
	client := newNegotiationClient(t, startNegotiationServer(t, server))
	waitReady(t, client)

	status := client.TransportStatus()
	require.NotNil(t, status.Deprecation)
	assert.Equal(t, "node API key authentication is deprecated", status.Deprecation.Message)
	assert.Equal(t, "https://example.test/upgrade", status.Deprecation.Link)
	assert.Equal(t, "Fri, 01 Jan 2027 00:00:00 GMT", status.Deprecation.Sunset)
	assert.True(t, client.counters.deprecationLogged.Load())

	require.Eventually(t, func() bool {
		_, heartbeats, _ := server.snapshot()
		return len(heartbeats) > 0
	}, 5*time.Second, 20*time.Millisecond)
	_, heartbeats, _ := server.snapshot()
	assert.Equal(t, float64(1), heartbeats[0].Metrics[MetricLegacyAuthDeprecated])
	assert.Equal(t, float64(0), heartbeats[0].Metrics[MetricMTLSRequiredRefusals])
}

func TestClientWithoutDeprecationSignalReportsZero(t *testing.T) {
	client, err := NewClient(Config{Target: "unused:1", NodeID: 1, APIKey: "key", AgentVersion: "test-agent"})
	require.NoError(t, err)
	client.setAuthentication(authenticationAPIKey)
	assert.Equal(t, float64(0), client.transportMetrics()[MetricLegacyAuthDeprecated])
}

func TestClientSurfacesMTLSRequiredRefusal(t *testing.T) {
	for _, tc := range []struct {
		name             string
		inTrailer, inMsg bool
		wantMTLSRequired bool
	}{
		{name: "code-in-trailer-and-message", inTrailer: true, inMsg: true, wantMTLSRequired: true},
		{name: "code-in-trailer-only", inTrailer: true, wantMTLSRequired: true},
		{name: "code-in-message-only", inMsg: true, wantMTLSRequired: true},
		{name: "no-code"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := &negotiationControlServer{nodeID: 7, refuseMTLSRequired: true, refusalCodeInTrailer: tc.inTrailer, refusalCodeInMessage: tc.inMsg}
			client := newNegotiationClient(t, startNegotiationServer(t, server))
			if !tc.wantMTLSRequired {
				// An Unauthenticated refusal without the code is an ordinary
				// stream error.
				require.Eventually(t, func() bool { return client.TransportStatus().LastError != "" }, 5*time.Second, 10*time.Millisecond)
				assert.Zero(t, client.TransportStatus().MTLSRequiredRefusals)
				assert.NotContains(t, client.TransportStatus().LastError, "must enroll")
				return
			}
			require.Eventually(t, func() bool { return client.TransportStatus().MTLSRequiredRefusals >= 2 }, 5*time.Second, 10*time.Millisecond)
			status := client.TransportStatus()
			assert.False(t, status.Connected)
			assert.Contains(t, status.LastError, agentcontrol.ErrorCodeMTLSRequired)
			assert.Contains(t, status.LastError, "must enroll")
			require.NotNil(t, status.Deprecation, "the refusal's trailer carries the deprecation signal")
		})
	}
}

func TestMTLSRequiredErrorClassification(t *testing.T) {
	refused := status.Error(codes.Unauthenticated, "agent_mtls_required: an agent client certificate is required")
	err := mtlsRequiredError("control stream", refused, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMTLSRequired))
	var typed *MTLSRequiredError
	require.True(t, errors.As(err, &typed))
	assert.Equal(t, "control stream", typed.Operation)

	coded := status.Error(codes.Unauthenticated, "refused")
	assert.True(t, errors.Is(mtlsRequiredError("enrollment", coded, metadata.Pairs(agentcontrol.MetadataErrorCode, agentcontrol.ErrorCodeMTLSRequired)), ErrMTLSRequired))

	wrapped := fmt.Errorf("receive hello ACK: %w", refused)
	assert.True(t, errors.Is(mtlsRequiredError("control stream", wrapped, nil), ErrMTLSRequired), "the code is read from the wrapped status")

	assert.Nil(t, mtlsRequiredError("control stream", status.Error(codes.Unauthenticated, "invalid API key"), nil))
	assert.Nil(t, mtlsRequiredError("control stream", status.Error(codes.PermissionDenied, "agent_mtls_required"), nil))
	assert.Nil(t, mtlsRequiredError("control stream", errors.New("agent_mtls_required"), nil))
	assert.Nil(t, mtlsRequiredError("control stream", nil, nil))
}

func TestClientDropsUnnegotiatedDataPlanePayloadsWithoutEndingTheStream(t *testing.T) {
	server := &negotiationControlServer{
		nodeID:             7,
		serverCapabilities: dataPlaneServerCapabilities(),
		afterHello: []*agentv1pb.ControlToAgent{
			{RequestId: "users-1", NodeId: 7, Payload: &agentv1pb.ControlToAgent_Users{Users: &agentv1pb.UserDelta{Cursor: 9, Full: true, LastPage: true}}},
			{RequestId: "config-1", NodeId: 7, Payload: &agentv1pb.ControlToAgent_Config{Config: &agentv1pb.ConfigSnapshot{ConfigRevision: 3}}},
			{RequestId: "ack-1", NodeId: 7, Payload: &agentv1pb.ControlToAgent_ReportAck{ReportAck: &agentv1pb.ReportAck{BatchId: "b"}}},
		},
	}
	client := newNegotiationClient(t, startNegotiationServer(t, server))
	waitReady(t, client)
	require.Eventually(t, func() bool { return client.TransportStatus().UnnegotiatedPayloads == 3 }, 5*time.Second, 10*time.Millisecond)

	// The session survives: heartbeats keep flowing on the first stream.
	require.Eventually(t, func() bool {
		_, heartbeats, _ := server.snapshot()
		return len(heartbeats) > 0
	}, 5*time.Second, 20*time.Millisecond)
	_, heartbeats, attempts := server.snapshot()
	assert.Equal(t, 1, attempts)
	assert.Equal(t, "negotiation-session", client.SessionID())
	assert.Equal(t, float64(3), heartbeats[0].Metrics[MetricUnnegotiatedPayloads])
}

func TestAuthDeprecationReadsMetadata(t *testing.T) {
	assert.Nil(t, authDeprecation(nil))
	assert.Nil(t, authDeprecation(metadata.Pairs("other", "x")))
	deprecation := authDeprecation(metadata.Pairs(agentcontrol.MetadataAuthDeprecated, " deprecated "))
	require.NotNil(t, deprecation)
	assert.Equal(t, "deprecated", deprecation.Message)
	assert.Empty(t, deprecation.Link)
	assert.Empty(t, deprecation.Sunset)
}

func TestNegotiatedNamesNeedsBothSides(t *testing.T) {
	agent := []*agentv1pb.Capability{{Name: agentcontrol.CapabilityUsers, Version: "v1"}, {Name: "agent.ping", Version: "v1"}}
	server := []*agentv1pb.Capability{{Name: agentcontrol.CapabilityUsers, Version: "v1"}, {Name: agentcontrol.CapabilityConfig, Version: "v1"}}
	assert.Equal(t, []string{"users.v1"}, negotiatedNames(agent, server))
	assert.Empty(t, negotiatedNames(agent, nil))
}
