package agent

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOperationProgressGoesOutBeforeTheTerminalAndAfterTerminalRunsLast(t *testing.T) {
	stream := &recordingAgentClientStream{}
	sentBeforeHook := make(chan int, 1)
	var hookPhase atomic.Int32
	client, err := NewClient(Config{
		Target: "unused:1", NodeID: 1, APIKey: "key", AgentVersion: "test-agent",
		Handler: OperationHandlerFunc(func(ctx context.Context, _ *agentv1pb.DesiredOperation) (json.RawMessage, error) {
			require.NoError(t, ReportProgress(ctx, []byte(`{"phase":"downloading"}`)))
			require.NoError(t, ReportProgress(ctx, []byte(`{"phase":"verifying"}`)))
			require.True(t, AfterTerminal(ctx, func(phase agentv1pb.ObservedPhase) {
				hookPhase.Store(int32(phase))
				sentBeforeHook <- len(stream.messages())
			}))
			return json.RawMessage(`{"phase":"handed_off"}`), nil
		}),
	})
	require.NoError(t, err)
	operation := &agentv1pb.DesiredOperation{OperationId: "upgrade-1", Kind: "agent.upgrade", Revision: 3}
	client.executeOperation(context.Background(), stream, "session-1", newSessionOperationState(), operation)

	messages := stream.messages()
	require.Len(t, messages, 4)
	phases := []agentv1pb.ObservedPhase{}
	for _, message := range messages {
		phases = append(phases, message.GetObservedState().GetPhase())
	}
	assert.Equal(t, []agentv1pb.ObservedPhase{
		agentv1pb.ObservedPhase_OBSERVED_PHASE_APPLYING, agentv1pb.ObservedPhase_OBSERVED_PHASE_APPLYING,
		agentv1pb.ObservedPhase_OBSERVED_PHASE_APPLYING, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED,
	}, phases)
	assert.JSONEq(t, `{"phase":"downloading"}`, string(messages[1].GetObservedState().GetStateJson()))
	assert.JSONEq(t, `{"phase":"verifying"}`, string(messages[2].GetObservedState().GetStateJson()))
	assert.Equal(t, "session-1", messages[2].GetObservedState().GetSessionId())
	select {
	case sent := <-sentBeforeHook:
		assert.Equal(t, 4, sent, "the hook runs after the terminal state was sent")
	default:
		t.Fatal("the AfterTerminal hook did not run")
	}
	assert.Equal(t, int32(agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED), hookPhase.Load())
}

func TestAfterTerminalSeesTheFailureADeadlineTurnsSuccessInto(t *testing.T) {
	stream := &recordingAgentClientStream{}
	var hookPhase atomic.Int32
	client, err := NewClient(Config{
		Target: "unused:1", NodeID: 1, APIKey: "key", AgentVersion: "test-agent",
		Handler: OperationHandlerFunc(func(ctx context.Context, _ *agentv1pb.DesiredOperation) (json.RawMessage, error) {
			AfterTerminal(ctx, func(phase agentv1pb.ObservedPhase) { hookPhase.Store(int32(phase)) })
			time.Sleep(60 * time.Millisecond)
			return json.RawMessage(`{"phase":"handed_off"}`), nil
		}),
	})
	require.NoError(t, err)
	operation := &agentv1pb.DesiredOperation{
		OperationId: "upgrade-late", Kind: "agent.upgrade", Revision: 4,
		DeadlineUnixMs: time.Now().Add(20 * time.Millisecond).UnixMilli(),
	}
	client.executeOperation(context.Background(), stream, "session-1", newSessionOperationState(), operation)
	assert.Equal(t, int32(agentv1pb.ObservedPhase_OBSERVED_PHASE_FAILED), hookPhase.Load())
}

func TestAdmitRefusesAnOperationBeforeItsAcknowledgement(t *testing.T) {
	var handled atomic.Int32
	client, err := NewClient(Config{
		Target: "unused:1", NodeID: 1, APIKey: "key", AgentVersion: "test-agent",
		Handler: OperationHandlerFunc(func(context.Context, *agentv1pb.DesiredOperation) (json.RawMessage, error) {
			handled.Add(1)
			return nil, nil
		}),
		Admit: func(operation *agentv1pb.DesiredOperation) error {
			if operation.GetKind() == "agent.upgrade" {
				return errors.New("upgrade_in_progress: another upgrade is in progress")
			}
			return nil
		},
	})
	require.NoError(t, err)
	stream := &recordingAgentClientStream{}
	queue := make(chan *agentv1pb.DesiredOperation, 1)
	operations := newSessionOperationState()
	require.NoError(t, client.acceptOperation(stream, "session-1", queue, operations,
		&agentv1pb.DesiredOperation{OperationId: "upgrade-2", Kind: "agent.upgrade", Revision: 5}))
	messages := stream.messages()
	require.Len(t, messages, 1)
	ack := messages[0].GetOperationAck()
	require.NotNil(t, ack)
	assert.False(t, ack.Accepted)
	assert.Equal(t, "upgrade_in_progress: another upgrade is in progress", ack.Error)
	assert.Empty(t, queue)

	require.NoError(t, client.acceptOperation(stream, "session-1", queue, operations,
		&agentv1pb.DesiredOperation{OperationId: "ping-1", Kind: "agent.ping", Revision: 6}))
	assert.True(t, stream.messages()[1].GetOperationAck().Accepted)
	assert.Len(t, queue, 1)
	assert.Zero(t, handled.Load())
}

func TestReportProgressOutsideAnOperation(t *testing.T) {
	assert.ErrorIs(t, ReportProgress(context.Background(), []byte(`{}`)), ErrNoOperationProgress)
	assert.False(t, AfterTerminal(context.Background(), func(agentv1pb.ObservedPhase) {}))
}
