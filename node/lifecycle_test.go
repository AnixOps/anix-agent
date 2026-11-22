package node

import (
	"errors"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildNodeTag(t *testing.T) {
	info := &panel.NodeInfo{Id: 12, Type: "vless"}
	controller := &Controller{apiHost: "https://control.test", Options: &conf.Options{}}
	assert.Equal(t, "[https://control.test]-vless:12", controller.buildNodeTag(info))
	controller.protocolID = 101
	assert.Equal(t, "[https://control.test]-vless:12#101", controller.buildNodeTag(info))
	controller.Name = "named"
	assert.Equal(t, "named#101", controller.buildNodeTag(info))
	controller.protocolID = 0
	assert.Equal(t, "named", controller.buildNodeTag(info))
}

func TestStartWithAndClose(t *testing.T) {
	core := newRecordingCore()
	controller := &Controller{nodeID: 1, apiHost: "https://control.test", server: core,
		Options: &conf.Options{LimitConfig: conf.LimitConfig{SpeedLimit: 8}}}
	info := vlessNode(443)
	info.PushInterval = time.Hour
	users := []panel.UserInfo{{Id: 1, Uuid: "user-1"}}
	require.NoError(t, controller.startWith(info, users, nil))
	assert.True(t, controller.isStarted())
	assert.Equal(t, "[https://control.test]-vless:1", controller.tag)
	assert.ElementsMatch(t, []string{"user-1"}, core.userUUIDs(controller.tag))
	assert.Equal(t, map[int]int{}, controller.aliveMap, "never nil")
	assert.Equal(t, 1_000_000, controller.rates.rate("user-1"))
	assert.Same(t, info, controller.info)
	require.NotNil(t, controller.reportJob)
	assert.Equal(t, time.Hour, controller.reportJob.interval)
	assert.NotNil(t, controller.logHook)

	require.NoError(t, controller.Close())
	require.NoError(t, controller.Close())
	_, dels := core.counts()
	assert.Equal(t, 1, dels, "the node is deleted once")
	assert.Nil(t, controller.logHook)
	assert.False(t, controller.nodeAdded)
}

func TestCloseReturnsTheDeleteError(t *testing.T) {
	delErr := errors.New("delete failed")
	controller := &Controller{server: &errorTestCore{delNodeErr: delErr}, tag: "t", nodeAdded: true, Options: &conf.Options{}}
	assert.ErrorIs(t, controller.Close(), delErr)
	assert.True(t, controller.nodeAdded)
}

// usersFailCore fails adding users, and deleting a node with delErr.
type usersFailCore struct {
	*reloadCore
	delErr error
}

func (c *usersFailCore) AddUsers(string, *panel.NodeInfo, []panel.UserInfo) (int, error) {
	return 0, errors.New("add users failed")
}

func (c *usersFailCore) DelNode(tag string) error {
	if c.delErr != nil {
		return c.delErr
	}
	return c.reloadCore.DelNode(tag)
}

func TestStartNodeDeletesTheNodeWhenItsUsersFail(t *testing.T) {
	for _, tc := range []struct {
		delErr    error
		nodeAdded bool
	}{
		{nil, false},
		{vCore.ErrNodeNotFound, false},
		{errors.New("core busy"), true}, // the next reconciliation deletes first
	} {
		core := &usersFailCore{reloadCore: newReloadCore(), delErr: tc.delErr}
		controller := &Controller{server: core, tag: "t", Options: &conf.Options{Name: "t"}}
		err := controller.startNodeLocked(vlessNode(443))
		assert.ErrorContains(t, err, "add users failed")
		assert.Equal(t, tc.nodeAdded, controller.nodeAdded, "%v", tc.delErr)
	}
}

func TestReconcileTakesNewUsersAndAliveWithANewNode(t *testing.T) {
	core := newReloadCore()
	controller := runningController(t, core, vlessNode(443))
	users := []panel.UserInfo{{Id: 2, Uuid: "user-2", SpeedLimit: 8}}
	alive := map[int]int{2: 1}
	controller.reconcileMu.Lock()
	err := controller.reconcileLocked(vlessNode(8443), users, alive)
	controller.reconcileMu.Unlock()
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"user-2"}, core.userUUIDs("fixed-tag"))
	assert.Equal(t, alive, controller.aliveMap)
	assert.Equal(t, 1_000_000, controller.rates.rate("user-2"))

	// The same node: only the alive list changes.
	adds := len(core.addCalls)
	controller.reconcileMu.Lock()
	err = controller.reconcileLocked(vlessNode(8443), nil, map[int]int{2: 2})
	controller.reconcileMu.Unlock()
	require.NoError(t, err)
	assert.Equal(t, adds, len(core.addCalls))
	assert.Equal(t, map[int]int{2: 2}, controller.aliveMap)
}
