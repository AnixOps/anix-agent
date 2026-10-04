package node

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/conf"
	vCore "github.com/AnixOps/anix-agent/v4/core"
	"github.com/AnixOps/anix-agent/v4/limiter"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
)

// reloadCore is a core that runs nodes the way the Selector does: a node it
// does not run cannot be deleted (ErrNodeNotFound), a tag it runs cannot be
// added again, and addErr can fail an add.
type reloadCore struct {
	*recordingCore
	addErr   func(info *panel.NodeInfo) error
	addCalls []int // the port of each AddNode attempt
	delCalls int
}

func newReloadCore() *reloadCore { return &reloadCore{recordingCore: newRecordingCore()} }

func (c *reloadCore) AddNode(tag string, info *panel.NodeInfo, options *conf.Options) error {
	c.addCalls = append(c.addCalls, info.Common.ServerPort)
	if _, ok := c.nodes[tag]; ok {
		return errors.New("existing tag found: " + tag)
	}
	if c.addErr != nil {
		if err := c.addErr(info); err != nil {
			return err
		}
	}
	return c.recordingCore.AddNode(tag, info, options)
}

func (c *reloadCore) DelNode(tag string) error {
	c.delCalls++
	if _, ok := c.nodes[tag]; !ok {
		return vCore.ErrNodeNotFound
	}
	return c.recordingCore.DelNode(tag)
}

func (c *reloadCore) runningPort(t *testing.T, tag string) int {
	t.Helper()
	info, ok := c.nodes[tag]
	if !ok {
		return 0
	}
	return info.Common.ServerPort
}

func vlessNode(port int) *panel.NodeInfo {
	body, _ := json.Marshal(uniProxyAnswer(port))
	info, _, err := panel.ParseNodeInfo(body, 1)
	if err != nil {
		panic(err)
	}
	return info
}

// errAddrInUse is what Xray reports when the port of the inbound removed
// a moment before is still held.
var errAddrInUse = errors.New("add inbound error: failed to listen TCP on 8443 > listen tcp 0.0.0.0:8443: bind: address already in use")

func failPort(port int, err error) func(*panel.NodeInfo) error {
	return func(info *panel.NodeInfo) error {
		if info.Common.ServerPort == port {
			return err
		}
		return nil
	}
}

// runningController is a controller whose node runs info in core.
func runningController(t *testing.T, core vCore.Core, info *panel.NodeInfo) *Controller {
	t.Helper()
	limiter.Init()
	previous := nodeAddRetryDelays
	nodeAddRetryDelays = []time.Duration{0, 0}
	t.Cleanup(func() { nodeAddRetryDelays = previous })
	controller := &Controller{
		apiClient: &errorTestNodeAPI{alive: map[int]int{}},
		server:    core,
		tag:       "fixed-tag",
		Options:   &conf.Options{Name: "fixed-tag"},
		userList:  []panel.UserInfo{{Id: 1, Uuid: "user-1"}},
		aliveMap:  map[int]int{},
	}
	controller.limiter = limiter.AddLimiter(controller.tag, &controller.LimitConfig, controller.userList, controller.aliveMap)
	controller.limiterAdded = true
	t.Cleanup(func() { limiter.DeleteLimiter(controller.tag) })
	if err := core.AddNode(controller.tag, info, controller.Options); err != nil {
		t.Fatal(err)
	}
	controller.nodeAdded, controller.info = true, info
	controller.started.Store(true)
	return controller
}

func TestReloadFailureRestoresThePreviousNode(t *testing.T) {
	core := newReloadCore()
	controller := runningController(t, core, vlessNode(443))
	core.addErr = failPort(8443, errAddrInUse)
	core.addCalls = nil

	err := controller.reconcileLocked(vlessNode(8443), nil, nil)
	if !errors.Is(err, errAddrInUse) || !strings.Contains(err.Error(), "restored") {
		t.Fatalf("reconcile error = %v, want the add failure, previous configuration restored", err)
	}
	// Three attempts on the busy port (the retries), then the old node.
	if want := []int{8443, 8443, 8443, 443}; !equalInts(core.addCalls, want) {
		t.Fatalf("AddNode attempts = %v, want %v", core.addCalls, want)
	}
	if port := core.runningPort(t, "fixed-tag"); port != 443 {
		t.Fatalf("running port = %d, want the previous 443", port)
	}
	if _, ok := core.users["fixed-tag"]["user-1"]; !ok {
		t.Fatal("the restored node has not got its users back")
	}
	if !controller.nodeAdded || controller.info.Common.ServerPort != 443 {
		t.Fatalf("controller state nodeAdded=%v port=%d, want the previous node", controller.nodeAdded, controller.info.Common.ServerPort)
	}

	// The port is free again: the next snapshot applies.
	core.addErr = nil
	if err := controller.reconcileLocked(vlessNode(8443), nil, nil); err != nil {
		t.Fatalf("next reconcile = %v, want nil", err)
	}
	if port := core.runningPort(t, "fixed-tag"); port != 8443 {
		t.Fatalf("running port = %d, want 8443", port)
	}
}

func TestReloadFailureWithoutRestoreRecoversOnTheNextSnapshot(t *testing.T) {
	core := newReloadCore()
	controller := runningController(t, core, vlessNode(443))
	core.addErr = func(*panel.NodeInfo) error { return errAddrInUse }

	err := controller.reconcileLocked(vlessNode(8443), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "restore the previous configuration") {
		t.Fatalf("reconcile error = %v, want the add and the restore failure", err)
	}
	if controller.nodeAdded {
		t.Fatal("nodeAdded after a failed restore, want false")
	}
	if _, ok := core.nodes["fixed-tag"]; ok {
		t.Fatal("the core runs a node after both adds failed")
	}

	core.addErr = nil
	delCalls := core.delCalls
	if err := controller.reconcileLocked(vlessNode(8443), nil, nil); err != nil {
		t.Fatalf("next reconcile = %v, want nil (no delete of the absent node)", err)
	}
	if core.delCalls != delCalls {
		t.Fatalf("DelNode called %d times for the absent node", core.delCalls-delCalls)
	}
	if port := core.runningPort(t, "fixed-tag"); port != 8443 || !controller.nodeAdded {
		t.Fatalf("running port = %d nodeAdded=%v, want 8443 and true", port, controller.nodeAdded)
	}
}

func TestReloadTakesAnAbsentNodeAsDeleted(t *testing.T) {
	core := newReloadCore()
	controller := runningController(t, core, vlessNode(443))
	// The core lost the node behind the controller's back.
	delete(core.nodes, "fixed-tag")

	if err := controller.reconcileLocked(vlessNode(8443), nil, nil); err != nil {
		t.Fatalf("reconcile = %v, want nil: a node that is not there is deleted already", err)
	}
	if port := core.runningPort(t, "fixed-tag"); port != 8443 {
		t.Fatalf("running port = %d, want 8443", port)
	}
}

// snapshotWith is a configuration snapshot of a vless node on port whose
// forwarding member carries plan; revision moves with either.
func snapshotWith(t *testing.T, revision uint64, port int, plan string) *agentv1pb.ConfigSnapshot {
	t.Helper()
	document := proxyDocument(port)
	document["forward"] = map[string]any{"plan": plan, "rules": []any{map[string]any{"listen": 30000, "target": plan}}}
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1pb.ConfigSnapshot{ConfigRevision: revision, ConfigJson: body}
}

func TestSnapshotReloadsOnlyWhenTheNodeConfigurationChanged(t *testing.T) {
	core := newReloadCore()
	controller := runningController(t, core, vlessNode(8443))
	adds, dels := len(core.addCalls), core.delCalls

	// A forwarding plan change: a new revision, the same proxy inbound.
	for revision, plan := range []string{"10.0.0.2:443", "10.0.0.3:443", "10.0.0.4:8443"} {
		if err := controller.applySnapshot(snapshotWith(t, uint64(revision+2), 8443, plan)); err != nil {
			t.Fatalf("applySnapshot(revision %d) = %v", revision+2, err)
		}
	}
	if len(core.addCalls) != adds || core.delCalls != dels {
		t.Fatalf("forward-only snapshots reloaded the core: %d adds, %d deletes", len(core.addCalls)-adds, core.delCalls-dels)
	}

	// The inbound itself changes: one reload.
	if err := controller.applySnapshot(snapshotWith(t, 9, 9443, "10.0.0.4:8443")); err != nil {
		t.Fatalf("applySnapshot(port change) = %v", err)
	}
	if len(core.addCalls) != adds+1 || core.delCalls != dels+1 {
		t.Fatalf("an inbound change made %d adds, %d deletes, want 1 and 1", len(core.addCalls)-adds, core.delCalls-dels)
	}
	if port := core.runningPort(t, controller.tag); port != 9443 {
		t.Fatalf("running port = %d, want 9443", port)
	}
}

func TestNodeConfigEqualSeesFieldsKeptOutOfJSON(t *testing.T) {
	a, b := vlessNode(443), vlessNode(443)
	if !nodeConfigEqual(a, b) {
		t.Fatal("two parses of one answer differ")
	}
	b.VAllss.RealityConfig.MaxTimeDiff = "rotated"
	if nodeConfigEqual(a, b) {
		t.Fatal("a Reality key change (json:\"-\") is judged unchanged")
	}
	if nodeConfigEqual(nil, a) {
		t.Fatal("no running configuration is judged equal")
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestReloadFailureRestoresTheDerivedTagAndLimiter(t *testing.T) {
	core := newReloadCore()
	controller := runningController(t, core, vlessNode(443))
	// The default: the tag (and the limiter's key) follows the node.
	delete(core.nodes, "fixed-tag")
	limiter.DeleteLimiter("fixed-tag")
	controller.Options.Name = ""
	controller.tag = controller.buildNodeTag(controller.info)
	controller.limiter = limiter.AddLimiter(controller.tag, &controller.LimitConfig, controller.userList, controller.aliveMap)
	t.Cleanup(func() { limiter.DeleteLimiter(controller.tag) })
	if err := core.AddNode(controller.tag, controller.info, controller.Options); err != nil {
		t.Fatal(err)
	}
	oldTag := controller.tag
	core.addErr = failPort(8443, errAddrInUse)

	if err := controller.reconcileLocked(vlessNode(8443), nil, nil); !errors.Is(err, errAddrInUse) {
		t.Fatalf("reconcile error = %v, want the add failure", err)
	}
	if controller.tag != oldTag || core.runningPort(t, oldTag) != 443 || !controller.nodeAdded {
		t.Fatalf("tag %q port %d nodeAdded=%v, want %q on 443", controller.tag, core.runningPort(t, oldTag), controller.nodeAdded, oldTag)
	}
	if l, err := limiter.GetLimiter(oldTag); err != nil || l != controller.limiter {
		t.Fatalf("limiter under %q = %v (%v), want the controller's", oldTag, l, err)
	}
}
