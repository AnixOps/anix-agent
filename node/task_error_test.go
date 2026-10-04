package node

import (
	"context"
	"errors"
	"strings"
	"testing"

	apiclient "github.com/AnixOps/anix-agent/v4/api/client"
	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/common/monitor"
	"github.com/AnixOps/anix-agent/v4/conf"
	vCore "github.com/AnixOps/anix-agent/v4/core"
	"github.com/AnixOps/anix-agent/v4/limiter"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
)

var _ apiclient.NodeAPI = (*errorTestNodeAPI)(nil)
var _ vCore.Core = (*errorTestCore)(nil)

type errorTestNodeAPI struct {
	node     *panel.NodeInfo
	users    []panel.UserInfo
	alive    map[int]int
	nodeErr  error
	usersErr error
	aliveErr error
	nodeType string
}

func (f *errorTestNodeAPI) GetNodeInfo() (*panel.NodeInfo, error)         { return f.node, f.nodeErr }
func (f *errorTestNodeAPI) GetUserList() ([]panel.UserInfo, error)        { return f.users, f.usersErr }
func (f *errorTestNodeAPI) GetUserAlive() (map[int]int, error)            { return f.alive, f.aliveErr }
func (f *errorTestNodeAPI) ReportUserTraffic([]panel.UserTraffic) error   { return nil }
func (f *errorTestNodeAPI) ReportNodeOnlineUsers(*map[int][]string) error { return nil }
func (f *errorTestNodeAPI) ReportNodeStatus(*monitor.SystemInfo, int, int64, int64) error {
	return nil
}
func (f *errorTestNodeAPI) ReportNodeLogs([]panel.NodeLogEntry) error { return nil }
func (f *errorTestNodeAPI) GetNodeID() int                            { return 1 }
func (f *errorTestNodeAPI) GetAPIHost() string                        { return "http://127.0.0.1" }
func (f *errorTestNodeAPI) GetAPIKey() string                         { return "test-key" }
func (f *errorTestNodeAPI) GetSecret() string                         { return "" }
func (f *errorTestNodeAPI) IsSignEnabled() bool                       { return false }
func (f *errorTestNodeAPI) SetNodeType(nodeType string)               { f.nodeType = nodeType }
func (f *errorTestNodeAPI) SupportsSync() bool                        { return false }
func (f *errorTestNodeAPI) Close() error                              { return nil }

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

func TestNodeInfoMonitorReturnsFetchErrors(t *testing.T) {
	nodeErr := errors.New("node fetch failed")
	usersErr := errors.New("users fetch failed")
	aliveErr := errors.New("alive fetch failed")

	tests := []struct {
		name string
		api  *errorTestNodeAPI
		want error
	}{
		{name: "node info", api: &errorTestNodeAPI{nodeErr: nodeErr}, want: nodeErr},
		{name: "user list", api: &errorTestNodeAPI{usersErr: usersErr}, want: usersErr},
		{name: "alive list", api: &errorTestNodeAPI{aliveErr: aliveErr}, want: aliveErr},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := &Controller{
				apiClient: tt.api,
				server:    &errorTestCore{},
				Options:   &conf.Options{},
			}
			if err := controller.nodeInfoMonitor(); !errors.Is(err, tt.want) {
				t.Fatalf("nodeInfoMonitor() error = %v, want wrapping %v", err, tt.want)
			}
		})
	}
}

func TestControllerEarlyStartFailureClosesWithoutDeletingMissingCoreNode(t *testing.T) {
	fetchErr := errors.New("node fetch failed")
	controller := &Controller{
		apiClient: &errorTestNodeAPI{nodeErr: fetchErr},
		server:    &errorTestCore{delNodeErr: errors.New("DelNode must not run")},
		Options:   &conf.Options{},
	}

	if err := controller.Start(); err == nil || !strings.Contains(err.Error(), fetchErr.Error()) {
		t.Fatalf("Controller.Start() error = %v, want containing %v", err, fetchErr)
	}
	if err := controller.Close(); err != nil {
		t.Fatalf("Controller.Close() after early failure = %v, want nil", err)
	}
}

func TestControllerReloadFailureDoesNotDeleteMissingCoreNodeTwice(t *testing.T) {
	limiter.Init()
	addErr := errors.New("replacement add failed")
	core := &errorTestCore{addNodeErr: addErr}
	api := &errorTestNodeAPI{node: &panel.NodeInfo{Id: 1, Type: "vless"}, alive: map[int]int{}}
	controller := &Controller{
		apiClient: api,
		server:    core,
		tag:       "fixed-tag",
		Options:   &conf.Options{Name: "fixed-tag"},
		nodeAdded: true,
		userList:  []panel.UserInfo{},
		aliveMap:  map[int]int{},
	}
	controller.limiter = limiter.AddLimiter(controller.tag, &controller.LimitConfig, controller.userList, controller.aliveMap)
	controller.limiterAdded = true

	err := controller.reloadNode(&panel.NodeInfo{Id: 1, Type: "vless"})
	if !errors.Is(err, addErr) {
		t.Fatalf("reloadNode() error = %v, want %v", err, addErr)
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

func TestNodeInfoMonitorReturnsDeleteErrorWithoutPanic(t *testing.T) {
	delErr := errors.New("delete failed")
	controller := &Controller{
		apiClient: &errorTestNodeAPI{
			node:  &panel.NodeInfo{Id: 1, Type: "vless"},
			alive: map[int]int{},
		},
		server:    &errorTestCore{delNodeErr: delErr},
		tag:       "test-node",
		Options:   &conf.Options{},
		nodeAdded: true,
	}

	if err := controller.nodeInfoMonitor(); !errors.Is(err, delErr) {
		t.Fatalf("nodeInfoMonitor() error = %v, want wrapping %v", err, delErr)
	}
}

func TestNodeInfoMonitorReturnsDeleteUsersError(t *testing.T) {
	delErr := errors.New("delete users failed")
	controller := &Controller{
		apiClient: &errorTestNodeAPI{
			users: []panel.UserInfo{},
		},
		server:   &errorTestCore{delUsersErr: delErr},
		tag:      "test-node",
		info:     &panel.NodeInfo{Id: 1, Type: "vless"},
		userList: []panel.UserInfo{{Id: 7, Uuid: "removed-user"}},
		Options:  &conf.Options{},
	}

	if err := controller.nodeInfoMonitor(); !errors.Is(err, delErr) {
		t.Fatalf("nodeInfoMonitor() error = %v, want wrapping %v", err, delErr)
	}
}

func TestAgentReloadOperationReportsReconcileFailure(t *testing.T) {
	fetchErr := errors.New("control reload fetch failed")
	controller := &Controller{
		apiClient: &errorTestNodeAPI{nodeErr: fetchErr},
		server:    &errorTestCore{},
		Options:   &conf.Options{},
	}
	controller.started.Store(true)

	_, err := controller.handleAgentOperation(context.Background(), &agentv1pb.DesiredOperation{
		Kind: "node.reload",
	})
	if !errors.Is(err, fetchErr) {
		t.Fatalf("handleAgentOperation() error = %v, want wrapping %v", err, fetchErr)
	}
}
