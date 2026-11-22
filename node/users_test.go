package node

import (
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiffUsers(t *testing.T) {
	same := panel.UserInfo{Id: 1, Uuid: "same", Extra: map[string]string{"other": "x"}}
	gone := panel.UserInfo{Id: 2, Uuid: "gone"}
	running := []panel.UserInfo{same, gone, gone}
	changes := map[string]func(*panel.UserInfo){
		"SpeedLimit":            func(u *panel.UserInfo) { u.SpeedLimit = 5 },
		"DeviceLimit":           func(u *panel.UserInfo) { u.DeviceLimit = 2 },
		"WireGuardPeerIP":       func(u *panel.UserInfo) { u.WireGuardPeerIP = "10.0.0.2" },
		"WireGuardPublicKey":    func(u *panel.UserInfo) { u.WireGuardPublicKey = "pub" },
		"WireGuardPresharedKey": func(u *panel.UserInfo) { u.WireGuardPresharedKey = "psk" },
		"ss2022_key":            func(u *panel.UserInfo) { u.Extra = map[string]string{"ss2022_key": "k"} },
	}
	for name, change := range changes {
		changed := same
		change(&changed)
		removed, added := diffUsers(running, []panel.UserInfo{changed})
		assert.ElementsMatch(t, []panel.UserInfo{same, gone}, removed, name)
		assert.Equal(t, []panel.UserInfo{changed}, added, name)
	}

	// The id and other extras do not matter; added keeps wanted's order
	// and duplicates count once.
	renumbered := panel.UserInfo{Id: 9, Uuid: "same"}
	a, b := panel.UserInfo{Id: 3, Uuid: "a"}, panel.UserInfo{Id: 4, Uuid: "b"}
	removed, added := diffUsers(running, []panel.UserInfo{b, renumbered, a, b})
	assert.Equal(t, []panel.UserInfo{gone}, removed)
	assert.Equal(t, []panel.UserInfo{b, a}, added)

	removed, added = diffUsers(running, running)
	assert.Empty(t, removed)
	assert.Empty(t, added)
}

func TestApplyUserDiffUpdatesTheCoreAndTheRateLimits(t *testing.T) {
	core := newRecordingCore()
	users := []panel.UserInfo{{Id: 1, Uuid: "kept"}, {Id: 2, Uuid: "removed"}, {Id: 3, Uuid: "changed"}}
	require.NoError(t, core.AddNode("diff-tag", vlessNode(443), nil))
	_, _ = core.AddUsers("diff-tag", nil, users)
	controller := &Controller{
		server: core, tag: "diff-tag", userList: users, Options: &conf.Options{},
		rates:   newRateLimits(0, users),
		traffic: map[string]int64{"kept": 1, "removed": 2, "changed": 3},
	}
	controller.rates.penalize("changed", 1, time.Now().Add(time.Hour))
	wanted := []panel.UserInfo{{Id: 1, Uuid: "kept"}, {Id: 3, Uuid: "changed", SpeedLimit: 16}, {Id: 4, Uuid: "new", SpeedLimit: 8}}

	require.NoError(t, reconcile(controller, nil, wanted))
	assert.ElementsMatch(t, []string{"kept", "changed", "new"}, core.userUUIDs("diff-tag"))
	assert.Equal(t, wanted, controller.userList)
	assert.Equal(t, map[string]int64{"kept": 1}, controller.traffic)
	assert.Equal(t, 2_000_000, controller.rates.rate("changed"), "a re-added user has no penalty")
	assert.Equal(t, 1_000_000, controller.rates.rate("new"))

	// No change: the core is not called.
	adds, dels := core.userCalls()
	require.NoError(t, reconcile(controller, nil, wanted))
	adds2, dels2 := core.userCalls()
	assert.Equal(t, [2]int{adds, dels}, [2]int{adds2, dels2})
}
