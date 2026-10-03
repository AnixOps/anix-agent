package node

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v4/api/agent/agenttest"
	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/conf"
	vCore "github.com/AnixOps/anix-agent/v4/core"
	"github.com/AnixOps/anix-agent/v4/limiter"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
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
	return nil, nil
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

func (c *recordingCore) counts() (addNodes, delNodes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.addNodes), len(c.delNodes)
}

// legacyPanel is the legacy REST side of Control (UniProxy, the node
// routes, the WebSocket) and records every request. The node and agent
// channels answer 403 agent_mtls_required, as agent_control.mtls: required
// does.
type legacyPanel struct {
	server *httptest.Server
	config map[string]any
	mu     sync.Mutex
	paths  []string
}

func newLegacyPanel(t *testing.T, config map[string]any) *legacyPanel {
	t.Helper()
	legacy := &legacyPanel{config: config}
	legacy.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		legacy.mu.Lock()
		legacy.paths = append(legacy.paths, r.URL.Path)
		legacy.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/server/UniProxy/config":
			_ = json.NewEncoder(w).Encode(legacy.config)
		case "/api/v2/server/UniProxy/user":
			_ = json.NewEncoder(w).Encode(map[string]any{"users": []map[string]any{{"id": 1, "uuid": "legacy-user"}}})
		case "/api/v2/server/UniProxy/alivelist":
			_ = json.NewEncoder(w).Encode(map[string]any{"alive": map[string]int{}})
		case "/api/v2/server/UniProxy/push", "/api/v2/server/UniProxy/alive":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": true})
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"code":"agent_mtls_required"}`))
		}
	}))
	t.Cleanup(legacy.server.Close)
	return legacy
}

func (l *legacyPanel) requests() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.paths...)
}

func (l *legacyPanel) count(path string) int {
	count := 0
	for _, requested := range l.requests() {
		if requested == path {
			count++
		}
	}
	return count
}

// uniProxyAnswer is a UniProxy configuration answer of a vless node.
func uniProxyAnswer(port int) map[string]any {
	return map[string]any{
		"node_type": "vless", "type": "vless", "server_port": port, "network": "tcp", "tls": 0,
		"base_config": map[string]any{"push_interval": 60, "pull_interval": 60},
	}
}

// proxyDocument is an anixops.nodeconfig/v1 document whose legacy_pull
// answers vless on port.
func proxyDocument(port int) map[string]any {
	return map[string]any{
		"kind": "proxy",
		"node": map[string]any{"id": 12, "name": "stream-node"},
		"legacy_pull": map[string]any{
			"default": uniProxyAnswer(port),
			"types":   map[string]any{"vless": uniProxyAnswer(port)},
		},
	}
}

type streamNodeFixture struct {
	control    *agenttest.Control
	legacy     *legacyPanel
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
		control: control, legacy: newLegacyPanel(t, uniProxyAnswer(8443)), core: newRecordingCore(),
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
			APIHost: f.legacy.server.URL, Transport: "http", NodeID: int(f.control.NodeID), Key: f.control.APIKey, Timeout: 5,
			GRPCHost: f.control.Address, GRPCUseTLS: true, GRPCServerName: f.control.ServerName,
			AgentControlEnabled: true,
			AgentIdentity:       conf.AgentIdentityConfig{CertDir: f.pkiDir, EnrollCredentialFile: f.credential, Cluster: f.control.Cluster},
			AgentStream:         conf.AgentStreamConfig{StateDir: f.stateDir},
			CredentialFile:      filepath.Join(t.TempDir(), "credential.json"),
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

func TestStreamConfigurationStartsTheNodeWithoutTheLegacyConfigPull(t *testing.T) {
	fixture := newStreamNodeFixture(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig)
	fixture.control.SetDesiredConfig(agenttest.Snapshot(3, proxyDocument(443)), false)
	node := fixture.start(t)

	tag, info := fixture.core.node()
	require.NotNil(t, info, "the node runs the snapshot")
	assert.Equal(t, "vless", info.Type)
	require.NotNil(t, info.VAllss)
	assert.Equal(t, 443, info.VAllss.ServerPort)
	assert.Equal(t, 60*time.Second, info.PullInterval)
	assert.Contains(t, tag, "vless:12")
	assert.Zero(t, fixture.legacy.count("/api/v2/server/UniProxy/config"), "no legacy configuration pull: %v", fixture.legacy.requests())

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

	// node.reload no longer re-pulls over the legacy transport.
	controller := node.controllers[0]
	_, err := controller.handleAgentOperation(t.Context(), &agentv1pb.DesiredOperation{Kind: "node.reload", Revision: 1, OperationId: "reload-1"})
	require.NoError(t, err)
	assert.Zero(t, fixture.legacy.count("/api/v2/server/UniProxy/config"))
}

func TestStreamConfigurationReloadsTheNodeOnANewSnapshot(t *testing.T) {
	fixture := newStreamNodeFixture(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig)
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
	broken["legacy_pull"] = map[string]any{"types": map[string]any{}}
	fixture.control.SetDesiredConfig(agenttest.Snapshot(5, broken), true)
	require.Eventually(t, func() bool {
		status := lastStatus(fixture.control)
		return status != nil && status.ConfigRevision == 5
	}, 5*time.Second, 10*time.Millisecond)
	assert.False(t, lastStatus(fixture.control).Applied)
	assert.Contains(t, lastStatus(fixture.control).Error, "legacy_pull.default")
	_, info = fixture.core.node()
	require.NotNil(t, info)
	assert.Equal(t, 8443, info.VAllss.ServerPort)
	assert.Zero(t, fixture.legacy.count("/api/v2/server/UniProxy/config"))
}

func TestStreamConfigurationRestartRunsTheStoredSnapshotWhileControlIsDown(t *testing.T) {
	fixture := newStreamNodeFixture(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig)
	fixture.control.SetDesiredConfig(agenttest.Snapshot(7, proxyDocument(443)), false)
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
	_, info := restarted.node()
	require.NotNil(t, info)
	assert.Equal(t, 443, info.VAllss.ServerPort)
	assert.Zero(t, fixture.legacy.count("/api/v2/server/UniProxy/config"))

	// The stream carried config.v1 before the restart: the legacy pull
	// stays off for the grace period.
	controller := node.controllers[0]
	assert.Equal(t, "pending", controller.stream.mode(agentcontrol.CapabilityConfig).String())
	require.NoError(t, controller.nodeInfoMonitor())
	assert.Zero(t, fixture.legacy.count("/api/v2/server/UniProxy/config"))
}

func TestStreamConfigurationFallsBackToTheLegacyPullWhenControlDoesNotServeIt(t *testing.T) {
	fixture := newStreamNodeFixture(t, agenttest.ModeOptional)
	fixture.start(t)
	_, info := fixture.core.node()
	require.NotNil(t, info)
	assert.Equal(t, 8443, info.VAllss.ServerPort, "the legacy answer runs")
	assert.Equal(t, 1, fixture.legacy.count("/api/v2/server/UniProxy/config"))
	assert.Empty(t, fixture.control.ConfigStatuses())
	hello := fixture.control.Hellos()[0]
	assert.True(t, agentcontrol.HasCapabilityVersion(hello.Capabilities, agentcontrol.CapabilityConfig, "v1"))
}

func TestStreamDataPlaneOffKeepsTheLegacyTransports(t *testing.T) {
	fixture := newStreamNodeFixture(t, agenttest.ModeOptional, agentcontrol.CapabilityConfig)
	fixture.control.SetDesiredConfig(agenttest.Snapshot(3, proxyDocument(443)), false)
	config := fixture.nodeConfig(t)
	config.ApiConfig.AgentStream.DataPlane = conf.AgentStreamDataPlaneOff
	fixture.start(t, config)
	_, info := fixture.core.node()
	require.NotNil(t, info)
	assert.Equal(t, 8443, info.VAllss.ServerPort)
	require.Eventually(t, func() bool { return len(fixture.control.Hellos()) > 0 }, 5*time.Second, 10*time.Millisecond)
	hello := fixture.control.Hellos()[0]
	assert.False(t, agentcontrol.HasCapability(hello.Capabilities, agentcontrol.CapabilityConfig))
	assert.Empty(t, fixture.control.SentConfigs())
}

func TestNodeInfoFromSnapshotPicksTheControllersNodeType(t *testing.T) {
	document := proxyDocument(443)
	document["legacy_pull"].(map[string]any)["types"].(map[string]any)["vmess"] = map[string]any{
		"node_type": "vmess", "type": "vmess", "server_port": 10086, "network": "tcp",
		"base_config": map[string]any{"push_interval": 30, "pull_interval": 30},
	}
	snapshot := agenttest.Snapshot(1, document)

	info, err := nodeInfoFromSnapshot(snapshot, "", 12)
	require.NoError(t, err)
	assert.Equal(t, "vless", info.Type)
	assert.Equal(t, 12, info.Id)
	info, err = nodeInfoFromSnapshot(snapshot, "V2Ray", 12)
	require.NoError(t, err)
	assert.Equal(t, "vmess", info.Type)
	assert.Equal(t, 10086, info.VAllss.ServerPort)

	_, err = nodeInfoFromSnapshot(snapshot, "trojan", 12)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"trojan"`)

	forward := agenttest.Snapshot(1, map[string]any{"kind": "forward", "legacy_rules": []any{}})
	_, err = nodeInfoFromSnapshot(forward, "", 12)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forward")

	// A malformed answer is an error, never a panic, and never echoes the
	// configuration (it holds the node's secrets).
	secret := proxyDocument(443)
	secret["legacy_pull"].(map[string]any)["default"] = map[string]any{"private_key": "do-not-log", "routes": []any{map[string]any{"id": 1, "match": 7, "action": "block"}}, "node_type": "vless"}
	_, err = nodeInfoFromSnapshot(agenttest.Snapshot(2, secret), "", 12)
	require.Error(t, err)
	assert.False(t, strings.Contains(err.Error(), "do-not-log"))
}
