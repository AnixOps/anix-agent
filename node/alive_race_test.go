package node

import (
	"fmt"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/conf"
	"github.com/AnixOps/anix-agent/v4/limiter"
)

// gateCore is a core whose AddNode runs a hook first: a test stops a node
// start half way (after its limiter exists, before it is started).
type gateCore struct {
	*recordingCore
	onAddNode func()
}

func (c *gateCore) AddNode(tag string, info *panel.NodeInfo, options *conf.Options) error {
	if c.onAddNode != nil {
		c.onAddNode()
	}
	return c.recordingCore.AddNode(tag, info, options)
}

// startingController is a controller that has not started: startWith runs
// its node (an unencrypted vless node with a long pull and push interval,
// so no periodic task fires).
func startingController(t *testing.T, name string, core *gateCore) (*Controller, *panel.NodeInfo) {
	t.Helper()
	limiter.Init()
	controller := &Controller{
		apiClient: &errorTestNodeAPI{alive: map[int]int{}},
		server:    core,
		Options:   &conf.Options{Name: name},
	}
	t.Cleanup(func() { _ = controller.Close() })
	info := vlessNode(443)
	info.PullInterval, info.PushInterval = time.Hour, time.Hour
	return controller, info
}

// assertAlive fails unless both the controller and its limiter hold want.
func assertAlive(t *testing.T, controller *Controller, want map[int]int) {
	t.Helper()
	controller.reconcileMu.Lock()
	defer controller.reconcileMu.Unlock()
	if !maps.Equal(controller.aliveMap, want) {
		t.Errorf("controller alive list = %v, want %v", controller.aliveMap, want)
	}
	if controller.limiter == nil {
		t.Fatal("the node has no limiter")
	}
	if !maps.Equal(controller.limiter.AliveList, want) {
		t.Errorf("limiter alive list = %v, want %v", controller.limiter.AliveList, want)
	}
}

// An alive list from the control stream that arrives while the node is
// starting (its limiter exists, the node is not started yet) is not lost: it
// reaches the limiter the node runs with.
func TestStreamAliveDuringStartReachesTheLimiter(t *testing.T) {
	inAddNode, release := make(chan struct{}), make(chan struct{})
	core := &gateCore{recordingCore: newRecordingCore(), onAddNode: func() {
		close(inAddNode)
		<-release
	}}
	controller, info := startingController(t, "alive-during-start", core)

	started := make(chan error, 1)
	go func() {
		started <- controller.startWith(info, []panel.UserInfo{{Id: 1, Uuid: "user-1"}}, map[int]int{1: 1})
	}()
	<-inAddNode
	fresh := map[int]int{1: 2, 9: 1}
	controller.applyStreamAlive(fresh)
	close(release)
	if err := <-started; err != nil {
		t.Fatalf("startWith() = %v", err)
	}
	assertAlive(t, controller, fresh)
}

// An alive list the stream delivered before the node started is newer than
// the list the start read from the stream earlier: the start keeps it.
func TestStreamAliveBeforeStartIsNotOverwrittenByTheStartupList(t *testing.T) {
	controller, info := startingController(t, "alive-before-start", &gateCore{recordingCore: newRecordingCore()})
	fresh := map[int]int{1: 2, 9: 1}
	controller.applyStreamAlive(fresh)
	if err := controller.startWith(info, []panel.UserInfo{{Id: 1, Uuid: "user-1"}}, map[int]int{1: 1}); err != nil {
		t.Fatalf("startWith() = %v", err)
	}
	assertAlive(t, controller, fresh)

	// A start without a stream list takes the one it was given.
	other, info := startingController(t, "alive-legacy-start", &gateCore{recordingCore: newRecordingCore()})
	legacy := map[int]int{3: 1}
	if err := other.startWith(info, nil, legacy); err != nil {
		t.Fatalf("startWith() = %v", err)
	}
	assertAlive(t, other, legacy)
}

// startWith and applyStreamAlive run on different goroutines when a node
// starts on the control stream: the alive list arrives while the
// configuration is applied. Both write the alive list and the limiter, so
// this is a data race unless startWith holds the reconcile lock for them
// (go test -race), and whichever goes first, the stream's list wins.
func TestStartWithAndStreamAliveDoNotRace(t *testing.T) {
	for i := range 20 {
		controller, info := startingController(t, fmt.Sprintf("alive-race-%d", i), &gateCore{recordingCore: newRecordingCore()})
		fresh := map[int]int{1: 2, 9: 1}
		var wg sync.WaitGroup
		gate := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-gate
			if err := controller.startWith(info, []panel.UserInfo{{Id: 1, Uuid: "user-1"}}, map[int]int{1: 1}); err != nil {
				t.Errorf("startWith() = %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			<-gate
			controller.applyStreamAlive(fresh)
		}()
		close(gate)
		wg.Wait()
		assertAlive(t, controller, fresh)
		if t.Failed() {
			return
		}
	}
}
