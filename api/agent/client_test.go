package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	mathrand "math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type controlStreamResult struct {
	hello    *agentv1pb.Hello
	ack      *agentv1pb.OperationAck
	applying *agentv1pb.ObservedState
	terminal *agentv1pb.ObservedState
}

type recordingAgentClientStream struct {
	grpc.ClientStream
	mu   sync.Mutex
	sent []*agentv1pb.AgentToControl
}

func (s *recordingAgentClientStream) Send(message *agentv1pb.AgentToControl) error {
	s.mu.Lock()
	s.sent = append(s.sent, message)
	s.mu.Unlock()
	return nil
}

func (s *recordingAgentClientStream) Recv() (*agentv1pb.ControlToAgent, error) {
	return nil, io.EOF
}

func (s *recordingAgentClientStream) messages() []*agentv1pb.AgentToControl {
	s.mu.Lock()
	defer s.mu.Unlock()
	messages := make([]*agentv1pb.AgentToControl, 0, len(s.sent))
	for _, message := range s.sent {
		messages = append(messages, proto.Clone(message).(*agentv1pb.AgentToControl))
	}
	return messages
}

type testAgentControlServer struct {
	agentv1pb.UnimplementedAgentControlServiceServer
	nodeID    uint32
	apiKey    string
	operation *agentv1pb.DesiredOperation
	result    chan controlStreamResult
}

type cancellationControlResult struct {
	acks      []*agentv1pb.OperationAck
	applying  *agentv1pb.ObservedState
	terminals []*agentv1pb.ObservedState
}

type cancellationAgentControlServer struct {
	agentv1pb.UnimplementedAgentControlServiceServer
	nodeID    uint32
	apiKey    string
	operation *agentv1pb.DesiredOperation
	result    chan cancellationControlResult
}

func (s *cancellationAgentControlServer) ControlStream(stream agentv1pb.AgentControlService_ControlStreamServer) error {
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok || len(md.Get("x-api-key")) == 0 || md.Get("x-api-key")[0] != s.apiKey {
		return status.Error(codes.Unauthenticated, "missing agent API key")
	}
	if len(md.Get("x-node-id")) == 0 || md.Get("x-node-id")[0] != strconv.FormatUint(uint64(s.nodeID), 10) {
		return status.Error(codes.Unauthenticated, "missing agent node ID")
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if first.GetHello() == nil {
		return status.Error(codes.FailedPrecondition, "hello is required")
	}
	if err := stream.Send(&agentv1pb.ControlToAgent{
		RequestId: first.RequestId, NodeId: s.nodeID, SentAtUnixMs: time.Now().UnixMilli(),
		Payload: &agentv1pb.ControlToAgent_HelloAck{HelloAck: &agentv1pb.HelloAck{
			SessionId: "cancellation-session", HeartbeatIntervalSeconds: 30,
		}},
	}); err != nil {
		return err
	}
	if err := s.sendDesired(stream, "target-operation", s.operation); err != nil {
		return err
	}

	result := cancellationControlResult{}
	cancelSent := false
	repeatSent := false
	for {
		message, err := stream.Recv()
		if err != nil {
			return err
		}
		if ack := message.GetOperationAck(); ack != nil && ack.OperationId == s.operation.OperationId {
			result.acks = append(result.acks, proto.Clone(ack).(*agentv1pb.OperationAck))
		}
		if observed := message.GetObservedState(); observed != nil && observed.OperationId == s.operation.OperationId {
			switch observed.Phase {
			case agentv1pb.ObservedPhase_OBSERVED_PHASE_APPLYING:
				result.applying = proto.Clone(observed).(*agentv1pb.ObservedState)
				if !cancelSent {
					cancelSent = true
					if err := s.sendDesired(stream, "cancel-operation", &agentv1pb.DesiredOperation{
						OperationId: s.operation.OperationId, Kind: operationCancelKind, Revision: s.operation.Revision,
					}); err != nil {
						return err
					}
				}
			case agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED,
				agentv1pb.ObservedPhase_OBSERVED_PHASE_FAILED,
				agentv1pb.ObservedPhase_OBSERVED_PHASE_SUPERSEDED:
				result.terminals = append(result.terminals, proto.Clone(observed).(*agentv1pb.ObservedState))
				if !repeatSent {
					repeatSent = true
					if err := s.sendDesired(stream, "repeat-cancel-operation", &agentv1pb.DesiredOperation{
						OperationId: s.operation.OperationId, Kind: operationCancelKind, Revision: s.operation.Revision,
					}); err != nil {
						return err
					}
				}
			}
		}
		if result.applying != nil && len(result.terminals) >= 2 && repeatSent && len(result.acks) >= 3 {
			s.result <- result
			<-stream.Context().Done()
			return stream.Context().Err()
		}
	}
}

func (s *cancellationAgentControlServer) sendDesired(stream agentv1pb.AgentControlService_ControlStreamServer, requestID string, operation *agentv1pb.DesiredOperation) error {
	return stream.Send(&agentv1pb.ControlToAgent{
		RequestId: requestID, NodeId: s.nodeID, Revision: operation.Revision, SentAtUnixMs: time.Now().UnixMilli(),
		Payload: &agentv1pb.ControlToAgent_DesiredOperation{DesiredOperation: proto.Clone(operation).(*agentv1pb.DesiredOperation)},
	})
}

func (s *testAgentControlServer) ControlStream(stream agentv1pb.AgentControlService_ControlStreamServer) error {
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok || len(md.Get("x-api-key")) == 0 || md.Get("x-api-key")[0] != s.apiKey {
		return status.Error(codes.Unauthenticated, "missing agent API key")
	}
	if len(md.Get("x-node-id")) == 0 || md.Get("x-node-id")[0] != strconv.FormatUint(uint64(s.nodeID), 10) {
		return status.Error(codes.Unauthenticated, "missing agent node ID")
	}

	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil || hello.Protocol != ProtocolVersion {
		return status.Error(codes.FailedPrecondition, "invalid hello")
	}
	if err := stream.Send(&agentv1pb.ControlToAgent{
		RequestId:    first.RequestId,
		NodeId:       s.nodeID,
		SentAtUnixMs: time.Now().UnixMilli(),
		Payload: &agentv1pb.ControlToAgent_HelloAck{
			HelloAck: &agentv1pb.HelloAck{
				SessionId:                "test-session",
				ServerTimeUnixMs:         time.Now().UnixMilli(),
				HeartbeatIntervalSeconds: 30,
			},
		},
	}); err != nil {
		return err
	}
	if err := stream.Send(&agentv1pb.ControlToAgent{
		RequestId:    "desired-request",
		NodeId:       s.nodeID,
		Revision:     s.operation.Revision,
		SentAtUnixMs: time.Now().UnixMilli(),
		Payload: &agentv1pb.ControlToAgent_DesiredOperation{
			DesiredOperation: s.operation,
		},
	}); err != nil {
		return err
	}

	result := controlStreamResult{hello: hello}
	for result.ack == nil || result.applying == nil || result.terminal == nil {
		message, err := stream.Recv()
		if err != nil {
			return err
		}
		if ack := message.GetOperationAck(); ack != nil {
			result.ack = ack
		}
		if observed := message.GetObservedState(); observed != nil {
			switch observed.Phase {
			case agentv1pb.ObservedPhase_OBSERVED_PHASE_APPLYING:
				result.applying = observed
			case agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED,
				agentv1pb.ObservedPhase_OBSERVED_PHASE_FAILED:
				result.terminal = observed
			}
		}
	}
	s.result <- result
	<-stream.Context().Done()
	return stream.Context().Err()
}

func TestClientControlStreamOperationLifecycle(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	resultCh := make(chan controlStreamResult, 1)
	operation := &agentv1pb.DesiredOperation{
		OperationId: "operation-1",
		Kind:        "agent.ping",
		Revision:    7,
		PayloadJson: []byte(`{"message":"ping"}`),
	}
	agentv1pb.RegisterAgentControlServiceServer(server, &testAgentControlServer{
		nodeID:    42,
		apiKey:    "node-api-key",
		operation: operation,
		result:    resultCh,
	})
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(listener) }()

	handled := make(chan *agentv1pb.DesiredOperation, 1)
	handledSession := make(chan string, 1)
	client, err := NewClient(Config{
		Target:       listener.Addr().String(),
		NodeID:       42,
		APIKey:       "node-api-key",
		AgentVersion: "test-agent",
		InstanceID:   "instance-1",
		Capabilities: []*agentv1pb.Capability{{Name: "agent.ping", Version: "v1"}},
		Handler: OperationHandlerFunc(func(ctx context.Context, desired *agentv1pb.DesiredOperation) (json.RawMessage, error) {
			sessionID, _ := operationSessionFromContext(ctx)
			handledSession <- sessionID
			handled <- desired
			return json.RawMessage(`{"applied":true}`), nil
		}),
		ReconnectMin: 100 * time.Millisecond,
		ReconnectMax: time.Second,
	})
	require.NoError(t, err)
	require.NoError(t, client.Start())

	select {
	case <-client.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("agent control client did not become ready")
	}
	assert.True(t, client.IsConnected())
	assert.Equal(t, "test-session", client.SessionID())

	select {
	case desired := <-handled:
		assert.Equal(t, operation.OperationId, desired.OperationId)
		assert.Equal(t, operation.Revision, desired.Revision)
	case <-time.After(5 * time.Second):
		t.Fatal("desired operation was not handled")
	}
	assert.Equal(t, "test-session", <-handledSession)

	select {
	case result := <-resultCh:
		assert.Equal(t, "test-agent", result.hello.AgentVersion)
		require.NotNil(t, result.ack)
		assert.True(t, result.ack.Accepted)
		assert.Equal(t, "test-session", result.ack.SessionId)
		assert.Equal(t, operation.Revision, result.ack.Revision)
		require.NotNil(t, result.applying)
		assert.Equal(t, operation.Revision, result.applying.Revision)
		assert.Equal(t, "test-session", result.applying.SessionId)
		require.NotNil(t, result.terminal)
		assert.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED, result.terminal.Phase)
		assert.Equal(t, "test-session", result.terminal.SessionId)
		assert.JSONEq(t, `{"applied":true}`, string(result.terminal.StateJson))
	case <-time.After(5 * time.Second):
		t.Fatal("operation lifecycle was not reported")
	}

	require.NoError(t, client.Close())
	server.GracefulStop()
	err = <-serverErr
	if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		require.NoError(t, err)
	}
}

func TestCompletedOperationReplayResendsTerminalWithoutExecutingOldRevision(t *testing.T) {
	var handled atomic.Int32
	client, err := NewClient(Config{
		Target: "unused:1", NodeID: 1, APIKey: "key", AgentVersion: "test-agent",
		Handler: OperationHandlerFunc(func(context.Context, *agentv1pb.DesiredOperation) (json.RawMessage, error) {
			handled.Add(1)
			return json.RawMessage(`{"applied":true}`), nil
		}),
	})
	require.NoError(t, err)
	stream := &recordingAgentClientStream{}
	operations := newSessionOperationState()
	target := &agentv1pb.DesiredOperation{OperationId: "recovered-operation", Kind: "plugin.health", Revision: 7}
	client.executeOperation(context.Background(), stream, "session-before-control-restart", operations, target)
	require.Equal(t, int32(1), handled.Load())
	require.Equal(t, target.Revision, client.observedRevision.Load())

	queue := make(chan *agentv1pb.DesiredOperation, 1)
	require.NoError(t, client.acceptOperation(stream, "session-after-control-restart", queue, operations, target))
	require.Empty(t, queue)
	require.Equal(t, int32(1), handled.Load(), "exact recovery must return the cached terminal without running the handler again")

	different := &agentv1pb.DesiredOperation{OperationId: "different-operation", Kind: target.Kind, Revision: target.Revision}
	require.NoError(t, client.acceptOperation(stream, "session-after-control-restart", queue, operations, different))
	require.Empty(t, queue)
	require.Equal(t, int32(1), handled.Load(), "a different operation at an observed revision must not execute")

	messages := stream.messages()
	require.Len(t, messages, 6)
	replayedAck := messages[2].GetOperationAck()
	require.NotNil(t, replayedAck)
	require.True(t, replayedAck.Accepted)
	require.Equal(t, target.OperationId, replayedAck.OperationId)
	replayedTerminal := messages[3].GetObservedState()
	require.NotNil(t, replayedTerminal)
	require.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED, replayedTerminal.Phase)
	require.Equal(t, "session-after-control-restart", replayedTerminal.SessionId)
	require.JSONEq(t, `{"applied":true}`, string(replayedTerminal.StateJson))

	staleAck := messages[4].GetOperationAck()
	require.NotNil(t, staleAck)
	require.True(t, staleAck.Accepted)
	staleTerminal := messages[5].GetObservedState()
	require.NotNil(t, staleTerminal)
	require.Equal(t, different.OperationId, staleTerminal.OperationId)
	require.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUPERSEDED, staleTerminal.Phase)
	require.Equal(t, "operation revision is stale", staleTerminal.Message)
}

func TestClientControlStreamCancellationLifecycle(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	resultCh := make(chan cancellationControlResult, 1)
	operation := &agentv1pb.DesiredOperation{OperationId: "stream-cancel", Kind: "agent.ping", Revision: 12}
	agentv1pb.RegisterAgentControlServiceServer(server, &cancellationAgentControlServer{
		nodeID: 42, apiKey: "node-api-key", operation: operation, result: resultCh,
	})
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(listener) }()

	handlerCancelled := make(chan struct{})
	client, err := NewClient(Config{
		Target: listener.Addr().String(), NodeID: 42, APIKey: "node-api-key", AgentVersion: "test-agent",
		Capabilities: []*agentv1pb.Capability{{Name: "agent.ping", Version: "v1"}, {Name: operationCancelKind, Version: "v1"}},
		Handler: OperationHandlerFunc(func(ctx context.Context, _ *agentv1pb.DesiredOperation) (json.RawMessage, error) {
			<-ctx.Done()
			close(handlerCancelled)
			return nil, ctx.Err()
		}),
		ReconnectMin: 100 * time.Millisecond,
		ReconnectMax: time.Second,
	})
	require.NoError(t, err)
	require.NoError(t, client.Start())

	select {
	case result := <-resultCh:
		require.Len(t, result.acks, 3, "target ACK plus initial and repeated cancellation ACKs")
		for _, ack := range result.acks {
			assert.True(t, ack.Accepted)
			assert.Equal(t, operation.OperationId, ack.OperationId)
			assert.Equal(t, operation.Revision, ack.Revision)
		}
		require.NotNil(t, result.applying)
		require.Len(t, result.terminals, 2)
		assert.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUPERSEDED, result.terminals[0].Phase)
		assert.Equal(t, operationCancelledText, result.terminals[0].Message)
		assert.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUPERSEDED, result.terminals[1].Phase)
		assert.Equal(t, operationNotRunningText, result.terminals[1].Message)
	case <-time.After(5 * time.Second):
		t.Fatal("operation cancellation lifecycle was not reported")
	}
	select {
	case <-handlerCancelled:
	default:
		t.Fatal("operation handler context was not cancelled")
	}

	require.NoError(t, client.Close())
	server.GracefulStop()
	err = <-serverErr
	if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		require.NoError(t, err)
	}
}

func TestExecuteOperationSupersedesRevisionThatBecameStaleInQueue(t *testing.T) {
	var handled atomic.Int32
	client, err := NewClient(Config{
		Target:       "unused:1",
		NodeID:       1,
		APIKey:       "key",
		AgentVersion: "test-agent",
		Capabilities: []*agentv1pb.Capability{{Name: "agent.ping"}},
		Handler: OperationHandlerFunc(func(context.Context, *agentv1pb.DesiredOperation) (json.RawMessage, error) {
			handled.Add(1)
			return nil, nil
		}),
	})
	require.NoError(t, err)
	client.observedRevision.Store(10)
	stream := &recordingAgentClientStream{}

	client.executeOperation(context.Background(), stream, "current-session", newSessionOperationState(), &agentv1pb.DesiredOperation{
		OperationId: "stale-in-queue",
		Kind:        "agent.ping",
		Revision:    9,
	})

	assert.Zero(t, handled.Load())
	stream.mu.Lock()
	require.Len(t, stream.sent, 1)
	observed := stream.sent[0].GetObservedState()
	stream.mu.Unlock()
	require.NotNil(t, observed)
	assert.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUPERSEDED, observed.Phase)
	assert.Equal(t, "current-session", observed.SessionId)
	assert.Equal(t, uint64(9), observed.Revision)
	completed, ok := client.completedOperation("stale-in-queue")
	require.True(t, ok)
	assert.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUPERSEDED, completed.Phase)
}

func TestRunningOperationCancellationCancelsHandlerAndSupersedes(t *testing.T) {
	started := make(chan struct{})
	client, err := NewClient(Config{
		Target: "unused:1", NodeID: 1, APIKey: "key", AgentVersion: "test-agent",
		Handler: OperationHandlerFunc(func(ctx context.Context, _ *agentv1pb.DesiredOperation) (json.RawMessage, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		}),
	})
	require.NoError(t, err)
	stream := &recordingAgentClientStream{}
	operations := newSessionOperationState()
	target := &agentv1pb.DesiredOperation{OperationId: "cancel-running", Kind: "agent.ping", Revision: 7}
	done := make(chan struct{})
	go func() {
		defer close(done)
		client.executeOperation(context.Background(), stream, "session-1", operations, target)
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	require.NoError(t, client.cancelOperation(stream, "session-1", operations, &agentv1pb.DesiredOperation{
		OperationId: target.OperationId, Kind: operationCancelKind, Revision: target.Revision,
	}))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("running handler was not cancelled")
	}

	messages := stream.messages()
	require.Len(t, messages, 3)
	var ack *agentv1pb.OperationAck
	var applying, terminal *agentv1pb.ObservedState
	for _, message := range messages {
		if message.GetOperationAck() != nil {
			ack = message.GetOperationAck()
			continue
		}
		observed := message.GetObservedState()
		if observed != nil && observed.Phase == agentv1pb.ObservedPhase_OBSERVED_PHASE_APPLYING {
			applying = observed
		} else if observed != nil {
			terminal = observed
		}
	}
	require.NotNil(t, ack)
	assert.True(t, ack.Accepted)
	require.NotNil(t, applying)
	require.NotNil(t, terminal)
	assert.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUPERSEDED, terminal.Phase)
	assert.Equal(t, operationCancelledText, terminal.Message)
}

func TestQueuedOperationCancellationSkipsHandler(t *testing.T) {
	var handled atomic.Int32
	client, err := NewClient(Config{
		Target: "unused:1", NodeID: 1, APIKey: "key", AgentVersion: "test-agent",
		Handler: OperationHandlerFunc(func(context.Context, *agentv1pb.DesiredOperation) (json.RawMessage, error) {
			handled.Add(1)
			return nil, nil
		}),
	})
	require.NoError(t, err)
	stream := &recordingAgentClientStream{}
	operations := newSessionOperationState()
	queue := make(chan *agentv1pb.DesiredOperation, 1)
	target := &agentv1pb.DesiredOperation{OperationId: "cancel-queued", Kind: "agent.ping", Revision: 8}
	require.NoError(t, client.acceptOperation(stream, "session-1", queue, operations, target))
	queued := <-queue
	require.NoError(t, client.cancelOperation(stream, "session-1", operations, &agentv1pb.DesiredOperation{
		OperationId: target.OperationId, Kind: operationCancelKind, Revision: target.Revision,
	}))
	client.executeOperation(context.Background(), stream, "session-1", operations, queued)

	assert.Zero(t, handled.Load())
	messages := stream.messages()
	require.Len(t, messages, 3)
	assert.True(t, messages[0].GetOperationAck().Accepted)
	assert.True(t, messages[1].GetOperationAck().Accepted)
	terminal := messages[2].GetObservedState()
	require.NotNil(t, terminal)
	assert.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUPERSEDED, terminal.Phase)
	assert.Equal(t, operationCancelledText, terminal.Message)
}

func TestLateRepeatedCancellationAcknowledgesAndReplaysTerminal(t *testing.T) {
	client, err := NewClient(Config{
		Target: "unused:1", NodeID: 1, APIKey: "key", AgentVersion: "test-agent",
		Handler: OperationHandlerFunc(func(context.Context, *agentv1pb.DesiredOperation) (json.RawMessage, error) {
			return json.RawMessage(`{"done":true}`), nil
		}),
	})
	require.NoError(t, err)
	stream := &recordingAgentClientStream{}
	operations := newSessionOperationState()
	target := &agentv1pb.DesiredOperation{OperationId: "cancel-late", Kind: "agent.ping", Revision: 9}
	client.executeOperation(context.Background(), stream, "session-1", operations, target)
	for range 2 {
		require.NoError(t, client.cancelOperation(stream, "session-1", operations, &agentv1pb.DesiredOperation{
			OperationId: target.OperationId, Kind: operationCancelKind, Revision: target.Revision,
		}))
	}

	messages := stream.messages()
	require.Len(t, messages, 6)
	require.NotNil(t, messages[0].GetObservedState())
	terminal := messages[1].GetObservedState()
	require.NotNil(t, terminal)
	assert.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED, terminal.Phase)
	for index := 2; index < len(messages); index += 2 {
		ack := messages[index].GetOperationAck()
		require.NotNil(t, ack)
		assert.True(t, ack.Accepted)
		replayed := messages[index+1].GetObservedState()
		require.NotNil(t, replayed)
		assert.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUPERSEDED, replayed.Phase)
		assert.Equal(t, operationNotRunningText, replayed.Message)
	}
}

func TestUnknownOperationCancellationCompletesAndSuppressesLaterReplay(t *testing.T) {
	var handled atomic.Int32
	client, err := NewClient(Config{
		Target: "unused:1", NodeID: 1, APIKey: "key", AgentVersion: "test-agent",
		Handler: OperationHandlerFunc(func(context.Context, *agentv1pb.DesiredOperation) (json.RawMessage, error) {
			handled.Add(1)
			return nil, nil
		}),
	})
	require.NoError(t, err)
	stream := &recordingAgentClientStream{}
	operations := newSessionOperationState()
	cancelRequest := &agentv1pb.DesiredOperation{OperationId: "cancel-after-control-restart", Kind: operationCancelKind, Revision: 15}
	require.NoError(t, client.cancelOperation(stream, "session-2", operations, cancelRequest))

	messages := stream.messages()
	require.Len(t, messages, 2)
	require.True(t, messages[0].GetOperationAck().Accepted)
	terminal := messages[1].GetObservedState()
	require.NotNil(t, terminal)
	require.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUPERSEDED, terminal.Phase)
	require.Equal(t, operationNotRunningText, terminal.Message)

	queue := make(chan *agentv1pb.DesiredOperation, 1)
	laterReplay := &agentv1pb.DesiredOperation{OperationId: cancelRequest.OperationId, Kind: "plugin.enable", Revision: cancelRequest.Revision}
	require.NoError(t, client.acceptOperation(stream, "session-2", queue, operations, laterReplay))
	require.Empty(t, queue)
	require.Zero(t, handled.Load())
	messages = stream.messages()
	require.Len(t, messages, 4)
	replayed := messages[3].GetObservedState()
	require.NotNil(t, replayed)
	require.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUPERSEDED, replayed.Phase)
	require.Equal(t, operationNotRunningText, replayed.Message)
}

func TestExpiredOperationIsFailedWithoutInvokingHandler(t *testing.T) {
	var handled atomic.Int32
	client, err := NewClient(Config{
		Target: "unused:1", NodeID: 1, APIKey: "key", AgentVersion: "test-agent",
		Handler: OperationHandlerFunc(func(context.Context, *agentv1pb.DesiredOperation) (json.RawMessage, error) {
			handled.Add(1)
			return json.RawMessage(`{"unexpected":true}`), nil
		}),
	})
	require.NoError(t, err)
	stream := &recordingAgentClientStream{}
	operations := newSessionOperationState()
	target := &agentv1pb.DesiredOperation{
		OperationId: "deadline-before-accept", Kind: "agent.ping", Revision: 21,
		DeadlineUnixMs: time.Now().Add(-time.Second).UnixMilli(),
	}
	queue := make(chan *agentv1pb.DesiredOperation, 1)
	require.NoError(t, client.acceptOperation(stream, "session-1", queue, operations, target))
	require.Empty(t, queue)
	assert.Zero(t, handled.Load())
	messages := stream.messages()
	require.Len(t, messages, 2)
	require.True(t, messages[0].GetOperationAck().Accepted)
	terminal := messages[1].GetObservedState()
	require.NotNil(t, terminal)
	assert.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_FAILED, terminal.Phase)
	assert.Equal(t, operationDeadlineText, terminal.Message)

	// A reconnect/replay must return the same terminal state without invoking
	// the handler or changing the outcome.
	require.NoError(t, client.acceptOperation(stream, "session-2", queue, operations, target))
	assert.Zero(t, handled.Load())
	require.Len(t, stream.messages(), 4)
	replayed := stream.messages()[3].GetObservedState()
	require.NotNil(t, replayed)
	assert.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_FAILED, replayed.Phase)
}

func TestQueuedOperationThatExpiresSkipsHandlerAndFails(t *testing.T) {
	var handled atomic.Int32
	client, err := NewClient(Config{
		Target: "unused:1", NodeID: 1, APIKey: "key", AgentVersion: "test-agent",
		Handler: OperationHandlerFunc(func(context.Context, *agentv1pb.DesiredOperation) (json.RawMessage, error) {
			handled.Add(1)
			return nil, nil
		}),
	})
	require.NoError(t, err)
	stream := &recordingAgentClientStream{}
	operations := newSessionOperationState()
	queue := make(chan *agentv1pb.DesiredOperation, 1)
	target := &agentv1pb.DesiredOperation{
		OperationId: "deadline-in-queue", Kind: "agent.ping", Revision: 22,
		DeadlineUnixMs: time.Now().Add(40 * time.Millisecond).UnixMilli(),
	}
	require.NoError(t, client.acceptOperation(stream, "session-1", queue, operations, target))
	queued := <-queue
	time.Sleep(100 * time.Millisecond)
	client.executeOperation(context.Background(), stream, "session-1", operations, queued)

	assert.Zero(t, handled.Load())
	messages := stream.messages()
	require.Len(t, messages, 2)
	terminal := messages[1].GetObservedState()
	require.NotNil(t, terminal)
	assert.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_FAILED, terminal.Phase)
	assert.Equal(t, operationDeadlineText, terminal.Message)
}

func TestHandlerIgnoringDeadlineCannotReportSuccess(t *testing.T) {
	started := make(chan struct{})
	client, err := NewClient(Config{
		Target: "unused:1", NodeID: 1, APIKey: "key", AgentVersion: "test-agent",
		Handler: OperationHandlerFunc(func(context.Context, *agentv1pb.DesiredOperation) (json.RawMessage, error) {
			close(started)
			time.Sleep(100 * time.Millisecond)
			return json.RawMessage(`{"ignored":true}`), context.DeadlineExceeded
		}),
	})
	require.NoError(t, err)
	stream := &recordingAgentClientStream{}
	operations := newSessionOperationState()
	target := &agentv1pb.DesiredOperation{
		OperationId: "deadline-ignored-by-handler", Kind: "agent.ping", Revision: 23,
		DeadlineUnixMs: time.Now().Add(20 * time.Millisecond).UnixMilli(),
	}
	done := make(chan struct{})
	go func() {
		client.executeOperation(context.Background(), stream, "session-1", operations, target)
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("deadline operation did not finish")
	}
	messages := stream.messages()
	require.Len(t, messages, 2)
	terminal := messages[1].GetObservedState()
	require.NotNil(t, terminal)
	assert.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_FAILED, terminal.Phase)
	assert.Equal(t, operationDeadlineText, terminal.Message)
}

func TestHandlerIgnoringCancellationCannotReportSuccess(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	client, err := NewClient(Config{
		Target: "unused:1", NodeID: 1, APIKey: "key", AgentVersion: "test-agent",
		Handler: OperationHandlerFunc(func(context.Context, *agentv1pb.DesiredOperation) (json.RawMessage, error) {
			close(started)
			<-release
			return json.RawMessage(`{"ignored":true}`), nil
		}),
	})
	require.NoError(t, err)
	stream := &recordingAgentClientStream{}
	operations := newSessionOperationState()
	target := &agentv1pb.DesiredOperation{OperationId: "cancel-ignored-by-handler", Kind: "agent.ping", Revision: 24}
	done := make(chan struct{})
	go func() {
		client.executeOperation(context.Background(), stream, "session-1", operations, target)
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	require.NoError(t, client.cancelOperation(stream, "session-1", operations, &agentv1pb.DesiredOperation{
		OperationId: target.OperationId, Kind: operationCancelKind, Revision: target.Revision,
	}))
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled operation did not finish")
	}
	messages := stream.messages()
	require.Len(t, messages, 3)
	terminal := messages[2].GetObservedState()
	require.NotNil(t, terminal)
	assert.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUPERSEDED, terminal.Phase)
	assert.Equal(t, operationCancelledText, terminal.Message)
}

func TestSessionOperationStateCloseCancelsAndClearsSessionState(t *testing.T) {
	operations := newSessionOperationState()
	running := &agentv1pb.DesiredOperation{OperationId: "session-running", Revision: 1}
	require.False(t, operations.queue(running))
	runningCtx, cancel, alreadyCancelled := operations.begin(context.Background(), running)
	defer cancel()
	require.False(t, alreadyCancelled)
	queued := &agentv1pb.DesiredOperation{OperationId: "session-queued", Revision: 2}
	require.False(t, operations.queue(queued))
	accepted, notRunning, reason := operations.requestCancel(queued.OperationId, queued.Revision)
	require.True(t, accepted)
	require.False(t, notRunning)
	require.Empty(t, reason)

	operations.close()
	select {
	case <-runningCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("session teardown did not cancel running operation")
	}
	operations.mu.Lock()
	defer operations.mu.Unlock()
	require.True(t, operations.closed)
	require.Empty(t, operations.running)
	require.Empty(t, operations.queued)
	require.Empty(t, operations.cancelled)
	require.Empty(t, operations.expired)
}

func TestClientRetriesFailedDial(t *testing.T) {
	var attempts atomic.Int32
	client, err := NewClient(Config{
		Target:       "unused:1",
		NodeID:       1,
		APIKey:       "key",
		AgentVersion: "test-agent",
		Capabilities: []*agentv1pb.Capability{{Name: "agent.ping"}},
		ReconnectMin: 5 * time.Millisecond,
		ReconnectMax: 20 * time.Millisecond,
		DialTimeout:  5 * time.Millisecond,
		DialContext: func(context.Context, string, ...grpc.DialOption) (*grpc.ClientConn, error) {
			attempts.Add(1)
			return nil, errors.New("dial failed")
		},
	})
	require.NoError(t, err)
	require.NoError(t, client.Start())
	require.Eventually(t, func() bool { return attempts.Load() >= 3 }, time.Second, 5*time.Millisecond)
	require.NoError(t, client.Close())
}

func TestReconnectDelayUsesExponentialBackoffAndJitter(t *testing.T) {
	client, err := NewClient(Config{
		Target:       "unused:1",
		NodeID:       1,
		APIKey:       "key",
		AgentVersion: "test-agent",
		Capabilities: []*agentv1pb.Capability{{Name: "agent.ping"}},
		ReconnectMin: time.Second,
		ReconnectMax: 5 * time.Second,
		Rand:         mathrand.New(mathrand.NewSource(1)),
	})
	require.NoError(t, err)

	delay0 := client.reconnectDelay(0)
	delay1 := client.reconnectDelay(1)
	delay2 := client.reconnectDelay(2)
	delay9 := client.reconnectDelay(9)
	assert.GreaterOrEqual(t, delay0, 500*time.Millisecond)
	assert.LessOrEqual(t, delay0, time.Second)
	assert.GreaterOrEqual(t, delay1, time.Second)
	assert.LessOrEqual(t, delay1, 2*time.Second)
	assert.GreaterOrEqual(t, delay2, 2*time.Second)
	assert.LessOrEqual(t, delay2, 4*time.Second)
	assert.GreaterOrEqual(t, delay9, 2500*time.Millisecond)
	assert.LessOrEqual(t, delay9, 5*time.Second)
	assert.NotEqual(t, delay0, client.reconnectDelay(0), "jitter should vary retries at the same backoff step")
}

func TestSendHeartbeatMergesMetricsProviderAndFiltersInvalidValues(t *testing.T) {
	providerCalled := make(chan struct{}, 1)
	client, err := NewClient(Config{
		Target: "unused:1", NodeID: 1, APIKey: "key", AgentVersion: "test-agent",
		MetricsProvider: func(ctx context.Context) (map[string]float64, error) {
			select {
			case providerCalled <- struct{}{}:
			default:
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return map[string]float64{
				"cpu_usage_percent": 12.5,
				"invalid_nan":       math.NaN(),
				"invalid_inf":       math.Inf(1),
				" ":                 99,
			}, nil
		},
	})
	require.NoError(t, err)
	stream := &recordingAgentClientStream{}
	require.NoError(t, client.sendHeartbeat(stream, "metrics-session", time.Now()))
	select {
	case <-providerCalled:
	default:
		t.Fatal("metrics provider was not called")
	}
	messages := stream.messages()
	require.Len(t, messages, 1)
	heartbeat := messages[0].GetHeartbeat()
	require.NotNil(t, heartbeat)
	assert.Equal(t, 12.5, heartbeat.Metrics["cpu_usage_percent"])
	assert.Contains(t, heartbeat.Metrics, "go_goroutines")
	assert.NotContains(t, heartbeat.Metrics, "invalid_nan")
	assert.NotContains(t, heartbeat.Metrics, "invalid_inf")
	assert.NotContains(t, heartbeat.Metrics, " ")
}

func TestSendHeartbeatContinuesWhenMetricsProviderFails(t *testing.T) {
	client, err := NewClient(Config{
		Target: "unused:1", NodeID: 1, APIKey: "key", AgentVersion: "test-agent",
		MetricsProvider: func(context.Context) (map[string]float64, error) {
			return nil, errors.New("telemetry unavailable")
		},
	})
	require.NoError(t, err)
	stream := &recordingAgentClientStream{}
	require.NoError(t, client.sendHeartbeat(stream, "metrics-error-session", time.Now()))
	messages := stream.messages()
	require.Len(t, messages, 1)
	heartbeat := messages[0].GetHeartbeat()
	require.NotNil(t, heartbeat)
	assert.Contains(t, heartbeat.Metrics, "go_goroutines")
}

func TestSendHeartbeatKeepsPartialMetricsWhenProviderReportsError(t *testing.T) {
	client, err := NewClient(Config{
		Target: "unused:1", NodeID: 1, APIKey: "key", AgentVersion: "test-agent",
		MetricsProvider: func(context.Context) (map[string]float64, error) {
			return map[string]float64{"plugin.machine-telemetry.cpu_usage_percent": 7.25}, errors.New("one plugin is unhealthy")
		},
	})
	require.NoError(t, err)
	stream := &recordingAgentClientStream{}
	require.NoError(t, client.sendHeartbeat(stream, "metrics-partial-session", time.Now()))
	messages := stream.messages()
	require.Len(t, messages, 1)
	heartbeat := messages[0].GetHeartbeat()
	require.NotNil(t, heartbeat)
	assert.Equal(t, 7.25, heartbeat.Metrics["plugin.machine-telemetry.cpu_usage_percent"])
}

func TestSendHeartbeatKeepsUnhealthyPluginObservationWithoutLiveFingerprint(t *testing.T) {
	configHash := strings.Repeat("a", 64)
	client, err := NewClient(Config{
		Target: "unused:1", NodeID: 1, APIKey: "key", AgentVersion: "test-agent",
		PluginObservationsProvider: func(context.Context) ([]*agentv1pb.PluginObservedState, error) {
			return []*agentv1pb.PluginObservedState{
				{
					PluginId: "nftables-forward", Version: "1.2.0", DesiredRevision: 8, ObservedRevision: 8,
					ConfigHash: configHash, Health: "unhealthy", ObservedAtUnixMs: time.Now().UnixMilli(),
				},
				{
					PluginId: "missing-fingerprint", Version: "1.0.0", DesiredRevision: 1, ObservedRevision: 1,
					ConfigHash: configHash, Health: "healthy", ObservedAtUnixMs: time.Now().UnixMilli(),
				},
			}, nil
		},
	})
	require.NoError(t, err)
	stream := &recordingAgentClientStream{}
	require.NoError(t, client.sendHeartbeat(stream, "plugin-observation-session", time.Now()))

	messages := stream.messages()
	require.Len(t, messages, 1)
	observations := messages[0].GetHeartbeat().GetPluginObservations()
	require.Len(t, observations, 1)
	assert.Equal(t, "nftables-forward", observations[0].PluginId)
	assert.Equal(t, "unhealthy", observations[0].Health)
	assert.Empty(t, observations[0].RulesetSha256)
	assert.Empty(t, observations[0].RuleCounters)
	assert.Equal(t, configHash, observations[0].ConfigHash)
}
