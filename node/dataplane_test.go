package node

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/agent/agenttest"
	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	"github.com/AnixOps/anix-agent/v5/limiter"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingCore is a core that records what the node asks of it.
type recordingCore struct {
	mu       sync.Mutex
	nodes    map[string]*panel.NodeInfo
	users    map[string]map[string]panel.UserInfo
	addNodes []string
	delNodes []string
	addUsers int
	delUsers int
	// traffic is the next window GetUserTrafficSlice returns; online the
	// online devices.
	traffic    []panel.UserTraffic
	online     []panel.OnlineUser
	rolledBack int
}

func newRecordingCore() *recordingCore {
	return &recordingCore{nodes: map[string]*panel.NodeInfo{}, users: map[string]map[string]panel.UserInfo{}}
}

func (c *recordingCore) Start() error { return nil }
func (c *recordingCore) Close() error { return nil }
func (c *recordingCore) AddNode(tag string, info *panel.NodeInfo, _ *conf.Options) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nodes[tag] = info
	c.users[tag] = map[string]panel.UserInfo{}
	c.addNodes = append(c.addNodes, tag)
	return nil
}
func (c *recordingCore) DelNode(tag string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.nodes, tag)
	delete(c.users, tag)
	c.delNodes = append(c.delNodes, tag)
	return nil
}
func (c *recordingCore) AddUsers(params *vCore.AddUsersParams) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.users[params.Tag] == nil {
		c.users[params.Tag] = map[string]panel.UserInfo{}
	}
	for _, user := range params.Users {
		c.users[params.Tag][user.Uuid] = user
	}
	c.addUsers++
	return len(params.Users), nil
}
func (c *recordingCore) GetUserTrafficSlice(string, bool) ([]panel.UserTraffic, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	traffic := c.traffic
	c.traffic = nil
	return traffic, nil
}
func (c *recordingCore) GetOnlineDevice(string) ([]panel.OnlineUser, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]panel.OnlineUser(nil), c.online...), nil
}
func (c *recordingCore) RollbackUserTrafficSlice(string, []panel.UserTraffic) error {
	c.mu.Lock()
	c.rolledBack++
	c.mu.Unlock()
	return nil
}
func (c *recordingCore) setWindow(traffic []panel.UserTraffic, online []panel.OnlineUser) {
	c.mu.Lock()
	c.traffic, c.online = traffic, online
	c.mu.Unlock()
}
func (c *recordingCore) DelUsers(users []panel.UserInfo, tag string, _ *panel.NodeInfo) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, user := range users {
		delete(c.users[tag], user.Uuid)
	}
	c.delUsers++
	return nil
}
func (c *recordingCore) Protocols() []string { return []string{"vless", "vmess"} }
func (c *recordingCore) Type() string        { return "test" }

func (c *recordingCore) node() (string, *panel.NodeInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for tag, info := range c.nodes {
		return tag, info
	}
	return "", nil
}

func (c *recordingCore) userUUIDs(tag string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	uuids := make([]string, 0, len(c.users[tag]))
	for uuid := range c.users[tag] {
		uuids = append(uuids, uuid)
	}
	return uuids
}

func (c *recordingCore) userCalls() (adds, dels int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.addUsers, c.delUsers
}

func (c *recordingCore) counts() (addNodes, delNodes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.addNodes), len(c.delNodes)
}

// runtimeAnswer is a node configuration answer of a vless node.
func runtimeAnswer(port int) map[string]any {
	return map[string]any{
		"node_type": "vless", "type": "vless", "server_port": port, "network": "tcp", "tls": 0,
		"base_config": map[string]any{"push_interval": 60, "pull_interval": 60},
	}
}

// proxyDocument is an anixops.nodeconfig/v1 document whose runtime answers
// vless on port.
func proxyDocument(port int) map[string]any {
	return map[string]any{
		"kind": "proxy",
		"node": map[string]any{"id": 12, "name": "stream-node"},
		"runtime": map[string]any{
			"default": runtimeAnswer(port),
			"types":   map[string]any{"vless": runtimeAnswer(port)},
		},
	}
}

type streamNodeFixture struct {
	control    *agenttest.Control
	core       *recordingCore
	pkiDir     string
	stateDir   string
	credential string
}

func newStreamNodeFixture(t *testing.T, mode string, serves ...string) *streamNodeFixture {
	t.Helper()
	limiter.Init()
	control := agenttest.New(t, mode, serves...)
	previous := agentControlRootCAs
	agentControlRootCAs = control.ServerCAs
	t.Cleanup(func() { agentControlRootCAs = previous })
	fixture := &streamNodeFixture{
		control: control, core: newRecordingCore(),
		pkiDir: filepath.Join(t.TempDir(), "pki"), stateDir: filepath.Join(t.TempDir(), "stream"),
	}
	fixture.credential = filepath.Join(t.TempDir(), "enroll.token")
	control.AddCredential("anixagt_test_credential")
	require.NoError(t, os.WriteFile(fixture.credential, []byte("anixagt_test_credential\n"), 0o600))
	return fixture
}

func (f *streamNodeFixture) nodeConfig(t *testing.T) conf.NodeConfig {
	t.Helper()
	return conf.NodeConfig{
		ApiConfig: conf.ApiConfig{
			APIHost: "https://control.test", NodeID: int(f.control.NodeID),
			GRPCHost: f.control.Address, GRPCUseTLS: true, GRPCServerName: f.control.ServerName,
			AgentIdentity: conf.AgentIdentityConfig{CertDir: f.pkiDir, EnrollCredentialFile: f.credential, Cluster: f.control.Cluster},
			AgentStream:   conf.AgentStreamConfig{StateDir: f.stateDir},
		},
		Options: conf.Options{ListenIP: "0.0.0.0", SendIP: "0.0.0.0", CertConfig: conf.NewCertConfig()},
	}
}

func (f *streamNodeFixture) start(t *testing.T, configs ...conf.NodeConfig) *Node {
	t.Helper()
	if len(configs) == 0 {
		configs = []conf.NodeConfig{f.nodeConfig(t)}
	}
	node := New()
	require.NoError(t, node.Start(configs, f.core))
	t.Cleanup(node.Close)
	return node
}

func lastStatus(control *agenttest.Control) *agentv1pb.ConfigStatus {
	statuses := control.ConfigStatuses()
	if len(statuses) == 0 {
		return nil
	}
	return statuses[len(statuses)-1]
}

func TestStreamConfigurationStartsTheNode(t *testing.T) {
	fixture := newStreamNodeFixture(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers)
	fixture.control.SetDesiredConfig(agenttest.Snapshot(3, proxyDocument(443)), false)
	fixture.control.UpsertUsers(&agentv1pb.NodeUser{UserId: 1, Uuid: "user-1"})
	node := fixture.start(t)

	tag, info := fixture.core.node()
	require.NotNil(t, info, "the node runs the snapshot")
	assert.Equal(t, "vless", info.Type)
	require.NotNil(t, info.VAllss)
	assert.Equal(t, 443, info.VAllss.ServerPort)
	assert.Equal(t, 60*time.Second, info.PullInterval)
	assert.Contains(t, tag, "vless:12")

	require.Eventually(t, func() bool { return lastStatus(fixture.control) != nil }, 5*time.Second, 10*time.Millisecond)
	status := lastStatus(fixture.control)
	assert.True(t, status.Applied)
	assert.Equal(t, uint64(3), status.ConfigRevision)

	// mTLS only: the stream that carried the configuration presented the
	// enrolled certificate and no API key.
	streams := fixture.control.Streams()
	accepted := streams[len(streams)-1]
	assert.True(t, accepted.Accepted)
	assert.NotEmpty(t, accepted.CertificateSerial)
	assert.False(t, accepted.APIKey)
	hello := fixture.control.Hellos()[0]
	assert.True(t, agentcontrol.HasCapabilityVersion(hello.Capabilities, agentcontrol.CapabilityConfig, "v1"))

	// node.reload answers from the running node.
	controller := node.controllers[0]
	_, err := controller.handleAgentOperation(t.Context(), &agentv1pb.DesiredOperation{Kind: "node.reload", Revision: 1, OperationId: "reload-1"})
	require.NoError(t, err)
}

func TestStreamConfigurationReloadsTheNodeOnANewSnapshot(t *testing.T) {
	fixture := newStreamNodeFixture(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers)
	fixture.control.SetDesiredConfig(agenttest.Snapshot(3, proxyDocument(443)), false)
	fixture.start(t)
	require.Eventually(t, func() bool { return lastStatus(fixture.control) != nil }, 5*time.Second, 10*time.Millisecond)

	fixture.control.SetDesiredConfig(agenttest.Snapshot(4, proxyDocument(8443)), true)
	require.Eventually(t, func() bool {
		status := lastStatus(fixture.control)
		return status != nil && status.ConfigRevision == 4
	}, 5*time.Second, 10*time.Millisecond)
	assert.True(t, lastStatus(fixture.control).Applied)
	_, info := fixture.core.node()
	require.NotNil(t, info)
	assert.Equal(t, 8443, info.VAllss.ServerPort)
	addNodes, delNodes := fixture.core.counts()
	assert.Equal(t, 2, addNodes, "the node restarted once")
	assert.Equal(t, 1, delNodes)

	// A snapshot the node cannot run is answered applied: false, and the
	// node keeps running the previous configuration.
	broken := proxyDocument(8443)
	broken["runtime"] = map[string]any{"types": map[string]any{}}
	fixture.control.SetDesiredConfig(agenttest.Snapshot(5, broken), true)
	require.Eventually(t, func() bool {
		status := lastStatus(fixture.control)
		return status != nil && status.ConfigRevision == 5
	}, 5*time.Second, 10*time.Millisecond)
	assert.False(t, lastStatus(fixture.control).Applied)
	assert.Contains(t, lastStatus(fixture.control).Error, "runtime.default")
	_, info = fixture.core.node()
	require.NotNil(t, info)
	assert.Equal(t, 8443, info.VAllss.ServerPort)
}

func TestStreamConfigurationRestartRunsTheStoredSnapshotWhileControlIsDown(t *testing.T) {
	fixture := newStreamNodeFixture(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers)
	fixture.control.SetDesiredConfig(agenttest.Snapshot(7, proxyDocument(443)), false)
	fixture.control.UpsertUsers(&agentv1pb.NodeUser{UserId: 1, Uuid: "stream-user-1"}, &agentv1pb.NodeUser{UserId: 2, Uuid: "stream-user-2"})
	first := New()
	require.NoError(t, first.Start([]conf.NodeConfig{fixture.nodeConfig(t)}, fixture.core))
	require.Eventually(t, func() bool { return lastStatus(fixture.control) != nil }, 5*time.Second, 10*time.Millisecond)
	first.Close()

	// Control goes away; the Agent restarts on what it last applied.
	fixture.control.Close()
	restarted := newRecordingCore()
	fixture.core = restarted
	began := time.Now()
	node := fixture.start(t)
	assert.Less(t, time.Since(began), streamStartupWait, "a stored snapshot needs no wait for Control")
	tag, info := restarted.node()
	require.NotNil(t, info)
	assert.Equal(t, 443, info.VAllss.ServerPort)
	assert.ElementsMatch(t, []string{"stream-user-1", "stream-user-2"}, restarted.userUUIDs(tag))

	// The stream carried config.v1 and users.v1 before the restart: they
	// count as pending for the grace period.
	controller := node.controllers[0]
	assert.Equal(t, "pending", controller.stream.mode(agentcontrol.CapabilityConfig).String())
	assert.Equal(t, "pending", controller.stream.mode(agentcontrol.CapabilityUsers).String())
}

func TestStreamStartFailsWhenControlDoesNotServeTheNode(t *testing.T) {
	fixture := newStreamNodeFixture(t, agenttest.ModeOptional)
	node := New()
	err := node.Start([]conf.NodeConfig{fixture.nodeConfig(t)}, fixture.core)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "upgrade Control")
	_, info := fixture.core.node()
	assert.Nil(t, info, "the node runs nothing Control did not send")
	hello := fixture.control.Hellos()[0]
	assert.True(t, agentcontrol.HasCapabilityVersion(hello.Capabilities, agentcontrol.CapabilityConfig, "v1"))
}

func TestNodeInfoFromSnapshotPicksTheControllersNodeType(t *testing.T) {
	document := proxyDocument(443)
	document["runtime"].(map[string]any)["types"].(map[string]any)["vmess"] = map[string]any{
		"node_type": "vmess", "type": "vmess", "server_port": 10086, "network": "tcp",
		"base_config": map[string]any{"push_interval": 30, "pull_interval": 30},
	}
	snapshot := agenttest.Snapshot(1, document)

	info, err := nodeInfoFromSnapshot(snapshot, "", 0, 12)
	require.NoError(t, err)
	assert.Equal(t, "vless", info.Type)
	assert.Equal(t, 12, info.Id)
	info, err = nodeInfoFromSnapshot(snapshot, "V2Ray", 0, 12)
	require.NoError(t, err)
	assert.Equal(t, "vmess", info.Type)
	assert.Equal(t, 10086, info.VAllss.ServerPort)

	_, err = nodeInfoFromSnapshot(snapshot, "trojan", 0, 12)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"trojan"`)

	forward := agenttest.Snapshot(1, map[string]any{"kind": "forward", "legacy_rules": []any{}})
	_, err = nodeInfoFromSnapshot(forward, "", 0, 12)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forward")

	// A malformed answer is an error, never a panic, and never echoes the
	// configuration (it holds the node's secrets).
	secret := proxyDocument(443)
	secret["runtime"].(map[string]any)["default"] = map[string]any{"private_key": "do-not-log", "routes": []any{map[string]any{"id": 1, "match": 7, "action": "block"}}, "node_type": "vless"}
	_, err = nodeInfoFromSnapshot(agenttest.Snapshot(2, secret), "", 0, 12)
	require.Error(t, err)
	assert.False(t, strings.Contains(err.Error(), "do-not-log"))

	// A document that names the answers legacy_pull (their earlier name)
	// still runs.
	older := proxyDocument(443)
	older["legacy_pull"] = older["runtime"]
	delete(older, "runtime")
	info, err = nodeInfoFromSnapshot(agenttest.Snapshot(3, older), "", 0, 12)
	require.NoError(t, err)
	assert.Equal(t, 443, info.VAllss.ServerPort)
}

func TestStreamUsersStartTheNodeAndApplyDeltasWithoutARestart(t *testing.T) {
	fixture := newStreamNodeFixture(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers)
	fixture.control.SetDesiredConfig(agenttest.Snapshot(3, proxyDocument(443)), false)
	fixture.control.SetUserPageSize(1)
	fixture.control.UpsertUsers(
		&agentv1pb.NodeUser{UserId: 1, Uuid: "user-1"},
		&agentv1pb.NodeUser{UserId: 2, Uuid: "user-2", SpeedLimitMbps: 100, DeviceLimit: 3},
	)
	node := fixture.start(t)
	tag, info := fixture.core.node()
	require.NotNil(t, info)
	assert.ElementsMatch(t, []string{"user-1", "user-2"}, fixture.core.userUUIDs(tag))
	controller := node.controllers[0]
	assert.Len(t, controller.userList, 2)
	assert.Equal(t, 100, controller.userList[1].SpeedLimit)
	assert.Equal(t, 3, controller.userList[1].DeviceLimit)
	assert.Zero(t, fixture.control.Hellos()[0].GetUsersCursor(), "the first Hello has no cursor")

	// A ban, a new user and a changed limit apply in place.
	fixture.control.RemoveUsers(1)
	fixture.control.UpsertUsers(&agentv1pb.NodeUser{UserId: 3, Uuid: "user-3"}, &agentv1pb.NodeUser{UserId: 2, Uuid: "user-2", SpeedLimitMbps: 10})
	require.Eventually(t, func() bool {
		uuids := fixture.core.userUUIDs(tag)
		return len(uuids) == 2 && controller.stream.client.TransportStatus().DataPlane.UsersCursor == 5
	}, 5*time.Second, 10*time.Millisecond)
	assert.ElementsMatch(t, []string{"user-2", "user-3"}, fixture.core.userUUIDs(tag))
	addNodes, delNodes := fixture.core.counts()
	assert.Equal(t, 1, addNodes, "users change without restarting the node")
	assert.Zero(t, delNodes)
	require.Eventually(t, func() bool {
		controller.reconcileMu.Lock()
		defer controller.reconcileMu.Unlock()
		return len(controller.userList) == 2 && controller.userList[0].SpeedLimit == 10
	}, 5*time.Second, 10*time.Millisecond)

	_, err := controller.handleAgentOperation(t.Context(), &agentv1pb.DesiredOperation{Kind: "users.reload", Revision: 1, OperationId: "reload-users"})
	require.NoError(t, err)
}

func TestPanelUsersCarryTheWireGuardPeerFields(t *testing.T) {
	users := panelUsers([]*agentv1pb.NodeUser{
		{UserId: 7, Uuid: "wg-user", SpeedLimitMbps: 20, DeviceLimit: 2, ExtraJson: []byte(`{"wireguard_peer_ip":"10.8.0.7","wireguard_peer_public_key":"pub","wireguard_preshared_key":"psk","wireguard_protocol_id":"3"}`)},
		{UserId: 8, Uuid: "plain"},
	})
	require.Len(t, users, 2)
	assert.Equal(t, panel.UserInfo{
		Id: 7, Uuid: "wg-user", SpeedLimit: 20, DeviceLimit: 2,
		WireGuardPeerIP: "10.8.0.7", WireGuardPublicKey: "pub", WireGuardPresharedKey: "psk",
		Extra: map[string]string{"wireguard_peer_ip": "10.8.0.7", "wireguard_peer_public_key": "pub", "wireguard_preshared_key": "psk", "wireguard_protocol_id": "3"},
	}, users[0])
	assert.Equal(t, panel.UserInfo{Id: 8, Uuid: "plain"}, users[1])
}

// healthReportingCore is a recordingCore with a supervised runtime that
// reports itself unhealthy (as WireGuard's relay can).
type healthReportingCore struct{ *recordingCore }

func (healthReportingCore) RuntimeHealth(string) (bool, string) { return false, "relay process exited" }

func TestStreamReportsTrafficOnlineLogsAndStatus(t *testing.T) {
	previousInterval := logBatchInterval
	logBatchInterval = 100 * time.Millisecond
	t.Cleanup(func() { logBatchInterval = previousInterval })
	fixture := newStreamNodeFixture(t, agenttest.ModeRequired,
		agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers, agentcontrol.CapabilityReports, agentcontrol.CapabilityPackageReports)
	fixture.control.SetDesiredConfig(agenttest.Snapshot(3, proxyDocument(443)), false)
	fixture.control.UpsertUsers(&agentv1pb.NodeUser{UserId: 1, Uuid: "user-1"}, &agentv1pb.NodeUser{UserId: 2, Uuid: "user-2"})
	// The core supervises a runtime.
	node := New()
	require.NoError(t, node.Start([]conf.NodeConfig{fixture.nodeConfig(t)}, healthReportingCore{fixture.core}))
	t.Cleanup(node.Close)
	controller := node.controllers[0]

	// Status at the session start: the machine's usage and the runtime
	// health, on the stream.
	require.Eventually(t, func() bool { return len(fixture.control.NodeStatuses()) > 0 }, 5*time.Second, 10*time.Millisecond)
	status := fixture.control.NodeStatuses()[0]
	assert.False(t, status.RuntimeHealthy)
	assert.Equal(t, "relay process exited", status.RuntimeError)
	assert.Positive(t, status.ObservedAtUnixMs)

	// A traffic window with online devices.
	fixture.core.setWindow(
		[]panel.UserTraffic{{UID: 1, Upload: 1500, Download: 9000}, {UID: 2, Upload: 0, Download: 0}},
		[]panel.OnlineUser{{UID: 1, IP: "198.51.100.4"}, {UID: 1, IP: "198.51.100.5"}},
	)
	require.NoError(t, controller.reportUserTrafficTask())
	require.Eventually(t, func() bool { return len(fixture.control.Batches()) >= 1 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, map[uint64][2]uint64{1: {1500, 9000}}, fixture.control.Traffic())
	online := fixture.control.Online()
	require.Len(t, online, 1)
	assert.Equal(t, []string{"198.51.100.4", "198.51.100.5"}, online[0].Ips)

	// The next window has nobody online: one report clears the alive set,
	// and then nothing is sent for empty windows.
	fixture.core.setWindow(nil, nil)
	require.NoError(t, controller.reportUserTrafficTask())
	require.Eventually(t, func() bool { return len(fixture.control.Batches()) == 2 }, 5*time.Second, 10*time.Millisecond)
	assert.Empty(t, fixture.control.Online())
	require.NoError(t, controller.reportUserTrafficTask())
	time.Sleep(200 * time.Millisecond)
	assert.Len(t, fixture.control.Batches(), 2)

	// The controller's logs go out as LogBatch.
	log.WithField("tag", controller.tag).Info("stream log line")
	require.Eventually(t, func() bool {
		for _, entry := range fixture.control.LogEntries() {
			if entry.Message == "stream log line" {
				return entry.Level == "info"
			}
		}
		return false
	}, 5*time.Second, 20*time.Millisecond)

	// Every report went on the mTLS stream.
	streams := fixture.control.Streams()
	for _, stream := range streams {
		assert.False(t, stream.APIKey)
	}
}

func TestStreamReportsWaitInTheSpoolDuringAnOutageAndCountOnce(t *testing.T) {
	previousGrace := streamPendingGrace
	streamPendingGrace = time.Minute
	t.Cleanup(func() { streamPendingGrace = previousGrace })
	fixture := newStreamNodeFixture(t, agenttest.ModeRequired,
		agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers, agentcontrol.CapabilityReports)
	fixture.control.SetDesiredConfig(agenttest.Snapshot(3, proxyDocument(443)), false)
	node := fixture.start(t)
	controller := node.controllers[0]

	fixture.control.RefuseStreams(true)
	require.Eventually(t, func() bool { return !controller.stream.client.IsConnected() }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, "pending", controller.stream.mode(agentcontrol.CapabilityReports).String())
	for window := int64(1); window <= 3; window++ {
		fixture.core.setWindow([]panel.UserTraffic{{UID: 7, Upload: window, Download: 10 * window}}, nil)
		require.NoError(t, controller.reportUserTrafficTask())
	}
	report := controller.stream.client.TransportStatus().DataPlane.Reports
	require.NotNil(t, report)
	assert.Equal(t, 3, report.Spooled)

	fixture.control.RefuseStreams(false)
	require.Eventually(t, func() bool { return len(fixture.control.Batches()) == 3 }, 10*time.Second, 20*time.Millisecond)
	assert.Equal(t, map[uint64][2]uint64{7: {6, 60}}, fixture.control.Traffic(), "each window counted once")
	require.Eventually(t, func() bool { return controller.stream.client.TransportStatus().DataPlane.Reports.Spooled == 0 }, 5*time.Second, 10*time.Millisecond)
	fixture.core.mu.Lock()
	assert.Zero(t, fixture.core.rolledBack)
	fixture.core.mu.Unlock()
}

func TestStreamReportsStayInTheSpoolAfterTheGracePeriod(t *testing.T) {
	previousGrace := streamPendingGrace
	streamPendingGrace = 200 * time.Millisecond
	t.Cleanup(func() { streamPendingGrace = previousGrace })
	fixture := newStreamNodeFixture(t, agenttest.ModeRequired,
		agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers, agentcontrol.CapabilityReports)
	fixture.control.SetDesiredConfig(agenttest.Snapshot(3, proxyDocument(443)), false)
	node := fixture.start(t)
	controller := node.controllers[0]

	fixture.control.RefuseStreams(true)
	require.Eventually(t, func() bool { return controller.stream.mode(agentcontrol.CapabilityReports).String() == "off" }, 5*time.Second, 20*time.Millisecond)
	fixture.core.setWindow([]panel.UserTraffic{{UID: 7, Upload: 1, Download: 2}}, nil)
	require.NoError(t, controller.reportUserTrafficTask())
	assert.Equal(t, 1, controller.stream.client.TransportStatus().DataPlane.Reports.Spooled, "a long outage keeps the window for the next session")

	fixture.control.RefuseStreams(false)
	require.Eventually(t, func() bool { return len(fixture.control.Batches()) == 1 }, 10*time.Second, 20*time.Millisecond)
	assert.Equal(t, map[uint64][2]uint64{7: {1, 2}}, fixture.control.Traffic())
}
