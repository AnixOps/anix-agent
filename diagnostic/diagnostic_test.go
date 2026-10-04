package diagnostic

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
)

type fakeChecker struct{ calls []string }

func (f *fakeChecker) IsCheck(action string) bool {
	return strings.HasPrefix(action, "forward.") && action != "forward.bogus"
}

func (f *fakeChecker) Check(_ context.Context, action string, params map[string]any) (any, string, string, error) {
	f.calls = append(f.calls, action)
	if params["route_id"] == nil {
		return nil, "", "", errors.New("route_id is required")
	}
	return map[string]any{"check": action, "status": "failed"}, "failed", "1 of 1 upstreams unreachable", nil
}

func operation(t *testing.T, action string, params map[string]any) *agentv1pb.DesiredOperation {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"task": Task{ID: "t1", Type: "diagnostic", Action: action, Params: params, Timeout: 5}})
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1pb.DesiredOperation{OperationId: "t1", Kind: Operation, PayloadJson: payload}
}

func TestGenericActions(t *testing.T) {
	var ran []string
	e := &Executor{
		Units:     map[string]string{"gost": "anixops-gost.service"},
		NoRestart: map[string]string{"gost": "managed by the forward component"},
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			ran = append(ran, name+" "+strings.Join(args, " "))
			if args[0] == "status" {
				return []byte("inactive (dead)"), errors.New("exit status 3")
			}
			return []byte("line"), nil
		},
	}
	out, err := e.Handle(context.Background(), operation(t, ActionServiceStatus, map[string]any{"service": "gost"}))
	if err != nil {
		t.Fatal(err)
	}
	var state State
	if err := json.Unmarshal(out, &state); err != nil {
		t.Fatal(err)
	}
	if !state.Success || state.Output != "inactive (dead)" {
		t.Fatalf("status: %+v", state)
	}
	if _, err := e.Handle(context.Background(), operation(t, ActionLogTail, map[string]any{"service": "gost", "lines": float64(5000)})); err != nil {
		t.Fatal(err)
	}
	want := []string{"systemctl status --no-pager --lines=0 anixops-gost.service", "journalctl -u anixops-gost.service -n 1000 --no-pager -o short-iso"}
	if strings.Join(ran, "|") != strings.Join(want, "|") {
		t.Fatalf("ran %q", ran)
	}
	for name, op := range map[string]*agentv1pb.DesiredOperation{
		"restart refused":   operation(t, ActionServiceRestart, map[string]any{"service": "gost"}),
		"unknown service":   operation(t, ActionServiceStatus, map[string]any{"service": "sshd"}),
		"unknown action":    operation(t, "shell", map[string]any{"service": "gost"}),
		"forward, no check": operation(t, "forward.connect", map[string]any{"route_id": "r"}),
		"no task":           {Kind: Operation, PayloadJson: []byte(`{"command":"id"}`)},
	} {
		if _, err := e.Handle(context.Background(), op); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if len(ran) != 2 {
		t.Fatalf("a refused task runs nothing: %q", ran)
	}
}

func TestForwardChecks(t *testing.T) {
	checker := &fakeChecker{}
	e := &Executor{Forward: checker}
	out, err := e.Handle(context.Background(), operation(t, "forward.connect", map[string]any{"route_id": "r1", "hop_index": float64(1)}))
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		Success bool           `json:"success"`
		Output  string         `json:"output"`
		Error   string         `json:"error"`
		Result  map[string]any `json:"result"`
	}
	if err := json.Unmarshal(out, &state); err != nil {
		t.Fatal(err)
	}
	if state.Success || state.Error != "failed" || state.Output != "1 of 1 upstreams unreachable" || state.Result["check"] != "forward.connect" {
		t.Fatalf("state %+v", state)
	}
	if _, err := e.Handle(context.Background(), operation(t, "forward.listen", map[string]any{})); err == nil {
		t.Fatal("a check that cannot run fails the operation")
	}
	if _, err := e.Handle(context.Background(), operation(t, "forward.bogus", map[string]any{})); err == nil {
		t.Fatal("an unknown forward action fails")
	}
}
