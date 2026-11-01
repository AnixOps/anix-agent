package agent

import (
	"sync"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/agent/agenttest"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// negotiationControlServer is a scripted A2 Control: it answers Hello with
// server capabilities and can push extra messages after the HelloAck.
type negotiationControlServer struct {
	agentv1pb.UnimplementedAgentControlServiceServer
	nodeID             uint32
	serverCapabilities []*agentv1pb.Capability
	afterHello         []*agentv1pb.ControlToAgent

	mu         sync.Mutex
	hellos     []*agentv1pb.Hello
	heartbeats []*agentv1pb.Heartbeat
	attempts   int
}

func (s *negotiationControlServer) ControlStream(stream agentv1pb.AgentControlService_ControlStreamServer) error {
	s.mu.Lock()
	s.attempts++
	s.mu.Unlock()
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

func startNegotiationServer(t *testing.T, server *negotiationControlServer) *agenttest.Listener {
	t.Helper()
	listener := agenttest.NewListener(t, server.nodeID)
	agentv1pb.RegisterAgentControlServiceServer(listener.Server, server)
	listener.Serve()
	return listener
}

func newNegotiationClient(t *testing.T, listener *agenttest.Listener) *Client {
	t.Helper()
	client, err := NewClient(listenerConfig(t, listener, Config{
		NodeID: 7, AgentVersion: "test-agent",
		Capabilities: []*agentv1pb.Capability{{Name: "agent.control", Version: "v1"}},
		Heartbeat:    time.Second, ReconnectMin: 10 * time.Millisecond, ReconnectMax: 50 * time.Millisecond,
	}))
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
	assert.Equal(t, []string{"config.v1", "reports.v1", "users.v1"}, status.ServerCapabilities)
	assert.Empty(t, status.Negotiated)

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
	client, err := NewClient(Config{Target: "unused:1", NodeID: 1, UseTLS: true, Identity: testIdentity(t), AgentVersion: "test-agent"})
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
			Target: "unused:1", NodeID: 1, UseTLS: true, Identity: testIdentity(t), AgentVersion: "test-agent",
			Capabilities: []*agentv1pb.Capability{{Name: name, Version: agentcontrol.CapabilityVersionV1}},
		})
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), name+".v1")
	}
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

func TestNegotiatedNamesNeedsBothSides(t *testing.T) {
	agent := []*agentv1pb.Capability{{Name: agentcontrol.CapabilityUsers, Version: "v1"}, {Name: "agent.ping", Version: "v1"}}
	server := []*agentv1pb.Capability{{Name: agentcontrol.CapabilityUsers, Version: "v1"}, {Name: agentcontrol.CapabilityConfig, Version: "v1"}}
	assert.Equal(t, []string{"users.v1"}, negotiatedNames(agent, server))
	assert.Empty(t, negotiatedNames(agent, nil))
}
