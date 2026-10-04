package agent

import (
	"context"
	"errors"
	"sync"
	"time"

	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
)

// Operation hooks let a handler do what a single terminal answer cannot:
// report progress while it runs (APPLYING with state_json) and act only
// once its terminal state has been sent (the agent.upgrade hand-off, whose
// updater restarts the Agent, PROTOCOL.md "Agent upgrades").

// ErrNoOperationProgress reports that the context is not an operation's
// (ReportProgress outside Client.executeOperation).
var ErrNoOperationProgress = errors.New("agent control: no running operation to report progress for")

// operationHooks belong to one executing operation.
type operationHooks struct {
	progress func(stateJSON []byte) error

	mu    sync.Mutex
	after []func(agentv1pb.ObservedPhase)
}

type operationHooksContextKey struct{}

func withOperationHooks(ctx context.Context, hooks *operationHooks) context.Context {
	return context.WithValue(ctx, operationHooksContextKey{}, hooks)
}

func operationHooksFromContext(ctx context.Context) *operationHooks {
	if ctx == nil {
		return nil
	}
	hooks, _ := ctx.Value(operationHooksContextKey{}).(*operationHooks)
	return hooks
}

// ReportProgress sends an APPLYING ObservedState with stateJSON for the
// operation ctx belongs to, on the session it arrived on.
func ReportProgress(ctx context.Context, stateJSON []byte) error {
	hooks := operationHooksFromContext(ctx)
	if hooks == nil || hooks.progress == nil {
		return ErrNoOperationProgress
	}
	return hooks.progress(stateJSON)
}

// AfterTerminal registers fn to run once the operation's terminal state has
// been recorded and sent, with the phase actually sent: the client may turn
// a handler's success into FAILED (its deadline passed) or SUPERSEDED
// (cancelled). fn runs whether or not the send reached Control: the
// terminal is remembered and answered again on a replay, so a step that
// waits for it must not wait for a delivery that may never be confirmed.
// It reports whether ctx is an operation's.
func AfterTerminal(ctx context.Context, fn func(agentv1pb.ObservedPhase)) bool {
	hooks := operationHooksFromContext(ctx)
	if hooks == nil || fn == nil {
		return false
	}
	hooks.mu.Lock()
	hooks.after = append(hooks.after, fn)
	hooks.mu.Unlock()
	return true
}

func (h *operationHooks) runAfter(phase agentv1pb.ObservedPhase) {
	if h == nil {
		return
	}
	h.mu.Lock()
	after := h.after
	h.after = nil
	h.mu.Unlock()
	for _, fn := range after {
		fn(phase)
	}
}

// progressSender sends an operation's APPLYING progress on stream.
func (c *Client) progressSender(stream agentv1pb.AgentControlService_ControlStreamClient, sessionID string, operation *agentv1pb.DesiredOperation) func([]byte) error {
	return func(stateJSON []byte) error {
		return c.sendObserved(stream, sessionID, &agentv1pb.ObservedState{
			OperationId:      operation.OperationId,
			Revision:         operation.Revision,
			Phase:            agentv1pb.ObservedPhase_OBSERVED_PHASE_APPLYING,
			StateJson:        append([]byte(nil), stateJSON...),
			ObservedAtUnixMs: time.Now().UnixMilli(),
		})
	}
}

// NewOperationContext gives ctx the hooks of an operation for a handler
// run outside the client (tests, another runner): progress receives each
// ReportProgress, and finish runs the AfterTerminal callbacks with the
// terminal phase once the caller has recorded it.
func NewOperationContext(ctx context.Context, progress func(stateJSON []byte) error) (context.Context, func(agentv1pb.ObservedPhase)) {
	hooks := &operationHooks{progress: progress}
	return withOperationHooks(ctx, hooks), hooks.runAfter
}
