package node

import (
	"errors"
	"testing"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOnlineToReportLeavesOutPings(t *testing.T) {
	core := newRecordingCore()
	core.online = []panel.OnlineUser{
		{UID: 1, IP: "198.51.100.1"}, {UID: 1, IP: "198.51.100.1"}, {UID: 1, IP: "198.51.100.2"},
		{UID: 2, IP: "198.51.100.3"}, // below the minimum: a ping
		{UID: 3, IP: "198.51.100.4"}, // no traffic entry: kept
		{UID: 0, IP: "198.51.100.5"},
	}
	controller := &Controller{server: core, tag: "online-tag", Options: &conf.Options{DeviceOnlineMinTraffic: 2}}
	online, total := controller.onlineToReport([]panel.UserTraffic{
		{UID: 1, Upload: 1000, Download: 1000}, {UID: 2, Upload: 1000, Download: 999},
	})
	assert.Equal(t, map[int][]string{1: {"198.51.100.1", "198.51.100.2"}, 3: {"198.51.100.4"}}, online)
	assert.Equal(t, 4, total, "the merged devices before the filter")
}

// failingCore fails reading the window and the online devices.
type failingCore struct{ *recordingCore }

func (failingCore) UserTraffic(string, bool) ([]panel.UserTraffic, error) {
	return nil, errors.New("no window")
}
func (failingCore) GetOnlineDevice(string) ([]panel.OnlineUser, error) {
	return nil, errors.New("no devices")
}

func TestReportWithoutStreamKeepsTheWindow(t *testing.T) {
	core := &rateCore{recordingCore: newRecordingCore(), rates: map[string]int{}}
	controller := dynamicController(core)
	controller.traffic = map[string]int64{"heavy": 100}
	core.setWindow([]panel.UserTraffic{{UID: 1, Upload: 300, Download: 200}, {UID: 9, Upload: 1}}, nil)

	// No stream: the submit fails and the window is kept, counted once by
	// the speed counter (AG-002: no core has to give it back).
	require.NoError(t, controller.reportUserTrafficTask())
	assert.Equal(t, []panel.UserTraffic{{UID: 1, Upload: 300, Download: 200}, {UID: 9, Upload: 1}}, controller.unsent)
	assert.Equal(t, int64(600), controller.traffic["heavy"])
	rate, ok := core.rate("light")
	assert.True(t, ok, "the rate limits are synced either way")
	assert.Equal(t, 1_000_000, rate)

	// The next window adds to what was kept.
	core.setWindow([]panel.UserTraffic{{UID: 1, Upload: 1}, {UID: 2, Download: 4}}, nil)
	require.NoError(t, controller.reportUserTrafficTask())
	assert.Equal(t, []panel.UserTraffic{{UID: 1, Upload: 301, Download: 200}, {UID: 9, Upload: 1}, {UID: 2, Download: 4}}, controller.unsent)

	// Read errors give an empty window, and the run still succeeds.
	broken := &Controller{server: failingCore{newRecordingCore()}, tag: "broken", Options: &conf.Options{}}
	assert.NoError(t, broken.reportUserTrafficTask())
}

func TestCountTrafficKeysByUUID(t *testing.T) {
	controller := &Controller{userList: []panel.UserInfo{{Id: 1, Uuid: "a"}, {Id: 2, Uuid: "b"}}}
	controller.countTraffic([]panel.UserTraffic{{UID: 1, Upload: 1, Download: 2}, {UID: 1, Upload: 4}, {UID: 7, Download: 9}})
	assert.Equal(t, map[string]int64{"a": 7}, controller.traffic)
}
