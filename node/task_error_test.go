package node

import (
	"errors"
	"testing"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	"github.com/AnixOps/anix-agent/v5/limiter"
)

var _ vCore.Core = (*errorTestCore)(nil)

type errorTestCore struct {
	addNodeErr   error
	delNodeErr   error
	delUsersErr  error
	delNodeCalls int
}

func (f *errorTestCore) Start() error                                         { return nil }
func (f *errorTestCore) Close() error                                         { return nil }
func (f *errorTestCore) AddNode(string, *panel.NodeInfo, *conf.Options) error { return f.addNodeErr }
func (f *errorTestCore) DelNode(string) error {
	f.delNodeCalls++
	return f.delNodeErr
}
func (f *errorTestCore) AddUsers(*vCore.AddUsersParams) (int, error) { return 0, nil }
func (f *errorTestCore) GetUserTrafficSlice(string, bool) ([]panel.UserTraffic, error) {
	return nil, nil
}
func (f *errorTestCore) DelUsers([]panel.UserInfo, string, *panel.NodeInfo) error {
	return f.delUsersErr
}
func (f *errorTestCore) Protocols() []string { return nil }
func (f *errorTestCore) Type() string        { return "test" }

// reconcile runs one reconciliation, as a snapshot or a user delta does.
func reconcile(controller *Controller, newN *panel.NodeInfo, newU []panel.UserInfo) error {
	controller.reconcileMu.Lock()
	defer controller.reconcileMu.Unlock()
	return controller.reconcileLocked(newN, newU, nil)
}

func TestControllerReloadFailureDoesNotDeleteMissingCoreNodeTwice(t *testing.T) {
	limiter.Init()
	addErr := errors.New("replacement add failed")
	core := &errorTestCore{addNodeErr: addErr}
	controller := &Controller{
		nodeID: 1, apiHost: "https://control.test",
		server:    core,
		tag:       "fixed-tag",
		Options:   &conf.Options{Name: "fixed-tag"},
		nodeAdded: true,
		userList:  []panel.UserInfo{},
		aliveMap:  map[int]int{},
	}
	controller.limiter = limiter.AddLimiter(controller.tag, &controller.LimitConfig, controller.userList, controller.aliveMap)
	controller.limiterAdded = true

	err := reconcile(controller, &panel.NodeInfo{Id: 1, Type: "vless"}, nil)
	if !errors.Is(err, addErr) {
		t.Fatalf("reconcile() error = %v, want %v", err, addErr)
	}
	if core.delNodeCalls != 1 {
		t.Fatalf("DelNode calls after reload failure = %d, want 1", core.delNodeCalls)
	}
	if err := controller.Close(); err != nil {
		t.Fatal(err)
	}
	if core.delNodeCalls != 1 {
		t.Fatalf("DelNode calls after Close = %d, want still 1", core.delNodeCalls)
	}
}

func TestReconcileReturnsDeleteErrorWithoutPanic(t *testing.T) {
	delErr := errors.New("delete failed")
	controller := &Controller{
		nodeID: 1, apiHost: "https://control.test",
		server:    &errorTestCore{delNodeErr: delErr},
		tag:       "test-node",
		Options:   &conf.Options{},
		nodeAdded: true,
		info:      &panel.NodeInfo{Id: 1, Type: "vmess"},
	}

	if err := reconcile(controller, &panel.NodeInfo{Id: 1, Type: "vless"}, nil); !errors.Is(err, delErr) {
		t.Fatalf("reconcile() error = %v, want wrapping %v", err, delErr)
	}
}

func TestReconcileReturnsDeleteUsersError(t *testing.T) {
	delErr := errors.New("delete users failed")
	controller := &Controller{
		nodeID: 1, apiHost: "https://control.test",
		server:   &errorTestCore{delUsersErr: delErr},
		tag:      "test-node",
		info:     &panel.NodeInfo{Id: 1, Type: "vless"},
		userList: []panel.UserInfo{{Id: 7, Uuid: "removed-user"}},
		Options:  &conf.Options{},
	}

	if err := reconcile(controller, nil, []panel.UserInfo{}); !errors.Is(err, delErr) {
		t.Fatalf("reconcile() error = %v, want wrapping %v", err, delErr)
	}
}
