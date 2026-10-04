// Package diagnostic runs the agent.diagnostic operation of the Agent
// Control stream (anix-control sdk/api/agent/v1/PROTOCOL.md, "Diagnostic
// operation"): Control's whitelisted diagnostic tasks, which replace the
// WebSocket's task.assign.
//
//   - The generic actions of the administrator routes: service_status,
//     service_restart and log_tail, for the service "gost" only.
//   - The forward checks of Control's route diagnosis (forward.listen,
//     forward.port_conflict, forward.connect, forward.udp_probe), which the
//     forward component runs on the hop it holds.
//
// The payload is {"task": {"id", "type", "action", "params", "timeout"}}.
// The answer is the generic diagnostic state {"success", "output", "error",
// "duration_ms"}, plus "result" for a forward check. A task that ran is
// answered whatever it found; an error (FAILED) means it could not run: an
// unknown action or malformed parameters.
package diagnostic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
)

// Operation is the desired operation kind and the capability an Agent that
// runs it lists. An Agent that runs the forward checks also lists diag.v1
// (agentcontrol.CapabilityDiag, from DataPlaneConfig.Diagnostics).
const Operation = "agent.diagnostic"

// The generic actions.
const (
	ActionServiceStatus  = "service_status"
	ActionServiceRestart = "service_restart"
	ActionLogTail        = "log_tail"

	logTailDefault = 100
	logTailMax     = 1000
	// maxOutput bounds the output a task answers.
	maxOutput = 32 << 10
	// defaultTimeout bounds a generic task without its own.
	defaultTimeout = 30 * time.Second
)

// Task is the task Control sends.
type Task struct {
	ID      string         `json:"id"`
	Type    string         `json:"type"`
	Action  string         `json:"action"`
	Params  map[string]any `json:"params"`
	Timeout int            `json:"timeout"`
}

// State is the answer: the terminal state's state_json.
type State struct {
	Success    bool   `json:"success"`
	Output     string `json:"output"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Result     any    `json:"result,omitempty"`
}

// Checker runs the forward checks: the forward component.
type Checker interface {
	// IsCheck reports whether action is one of its checks.
	IsCheck(action string) bool
	// Check runs one; its result goes in State.Result, and its verdict
	// ("ok", "failed", "inconclusive", "skipped") decides success.
	Check(ctx context.Context, action string, params map[string]any) (result any, verdict string, summary string, err error)
}

// Executor runs agent.diagnostic tasks.
type Executor struct {
	// Forward runs the forward checks; nil refuses them.
	Forward Checker
	// Units maps a service to its systemd unit; a service not listed is
	// refused.
	Units map[string]string
	// NoRestart refuses service_restart of a service, with the reason (a
	// unit another component manages).
	NoRestart map[string]string
	// Run runs systemctl and journalctl; nil runs them.
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)
	// Now defaults to time.Now.
	Now func() time.Time
}

// Handle runs the task an agent.diagnostic operation carries and answers
// its state.
func (e *Executor) Handle(ctx context.Context, operation *agentv1pb.DesiredOperation) (json.RawMessage, error) {
	var payload struct {
		Task *Task `json:"task"`
	}
	if err := json.Unmarshal(operation.GetPayloadJson(), &payload); err != nil || payload.Task == nil {
		return nil, errors.New("agent.diagnostic: the payload is not {\"task\": ...}")
	}
	state, err := e.Run1(ctx, *payload.Task)
	if err != nil {
		return nil, err
	}
	return json.Marshal(state)
}

func (e *Executor) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Run1 runs one task.
func (e *Executor) Run1(ctx context.Context, task Task) (*State, error) {
	started := e.now()
	if e.Forward != nil && e.Forward.IsCheck(task.Action) {
		result, verdict, summary, err := e.Forward.Check(ctx, task.Action, task.Params)
		if err != nil {
			return nil, fmt.Errorf("agent.diagnostic %s: %w", task.Action, err)
		}
		state := &State{Success: verdict == "ok", Output: summary, Result: result, DurationMS: e.now().Sub(started).Milliseconds()}
		if !state.Success {
			state.Error = verdict
		}
		return state, nil
	}
	if strings.HasPrefix(task.Action, "forward.") {
		return nil, fmt.Errorf("agent.diagnostic: %q needs the forward component, which this Agent does not run", task.Action)
	}
	service, _ := task.Params["service"].(string)
	unit, ok := e.Units[service]
	if !ok {
		return nil, fmt.Errorf("agent.diagnostic: service %q is not allowed", service)
	}
	timeout := defaultTimeout
	if task.Timeout > 0 {
		timeout = time.Duration(task.Timeout) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var out []byte
	var err error
	switch task.Action {
	case ActionServiceStatus:
		out, err = e.run(ctx, "systemctl", "status", "--no-pager", "--lines=0", unit)
		// systemctl status exits 3 for an inactive unit: still an answer.
		if err != nil && len(out) > 0 {
			err = nil
		}
	case ActionServiceRestart:
		if reason, refused := e.NoRestart[service]; refused {
			return nil, fmt.Errorf("agent.diagnostic: %s cannot be restarted here: %s", service, reason)
		}
		out, err = e.run(ctx, "systemctl", "restart", unit)
	case ActionLogTail:
		lines := logTailDefault
		if n, ok := task.Params["lines"].(float64); ok && n > 0 {
			lines = min(int(n), logTailMax)
		}
		out, err = e.run(ctx, "journalctl", "-u", unit, "-n", strconv.Itoa(lines), "--no-pager", "-o", "short-iso")
	default:
		return nil, fmt.Errorf("agent.diagnostic: action %q is not in the diagnostic whitelist", task.Action)
	}
	state := &State{Success: err == nil, Output: clip(string(out)), DurationMS: e.now().Sub(started).Milliseconds()}
	if err != nil {
		state.Error = err.Error()
	}
	return state, nil
}

func (e *Executor) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if e.Run != nil {
		return e.Run(ctx, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- whitelisted commands; the unit comes from Units, never from Control.
	var combined bytes.Buffer
	cmd.Stdout, cmd.Stderr = &combined, &combined
	err := cmd.Run()
	return combined.Bytes(), err
}

func clip(s string) string {
	if len(s) > maxOutput {
		return s[len(s)-maxOutput:]
	}
	return s
}
