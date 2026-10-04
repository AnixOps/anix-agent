package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	"github.com/AnixOps/anix-agent/v4/api/agent/agenttest"
	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/common/maintenance"
	"github.com/AnixOps/anix-agent/v4/conf"
	"github.com/AnixOps/anix-agent/v4/plugin"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signedRelease is an official plugin release signed by a test trust root.
type signedRelease struct {
	publicKey ed25519.PublicKey
	release   agenttest.Release
}

func newSignedRelease(t *testing.T, pluginID, version string, artifact []byte) signedRelease {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	digest := sha256.Sum256(artifact)
	canonical, err := plugin.CanonicalManifest(plugin.Manifest{
		ID: pluginID, Name: pluginID, Version: version, APIVersion: "v1", Publisher: "AnixOps",
		Targets: []string{"agent"}, ArtifactSHA256: hex.EncodeToString(digest[:]),
	})
	require.NoError(t, err)
	keyDigest := sha256.Sum256(publicKey)
	return signedRelease{publicKey: publicKey, release: agenttest.Release{
		PluginID: pluginID, Version: version, Manifest: canonical, Artifact: artifact,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)),
		Publisher: "AnixOps", KeyID: hex.EncodeToString(keyDigest[:])[:16], APIVersion: "v1",
	}}
}

// installConfig is the agent.plugin.install configuration of the release:
// its content addresses, unchanged by artifacts.v1.
func (r signedRelease) installConfig() []byte {
	asset := func(kind string, document []byte) map[string]any {
		digest := sha256.Sum256(document)
		sum := hex.EncodeToString(digest[:])
		return map[string]any{
			"url":    fmt.Sprintf("/api/v3/agent/plugin-releases/%s/%s/%s?sha256=%s&size=%d", r.release.PluginID, r.release.Version, kind, sum, len(document)),
			"sha256": sum, "size": len(document),
		}
	}
	manifest := asset("manifest", r.release.Manifest)
	manifest["signature"], manifest["publisher"], manifest["key_id"], manifest["api_version"] = r.release.Signature, "AnixOps", r.release.KeyID, "v1"
	encoded, err := json.Marshal(map[string]any{
		"api_version": plugin.PluginInstallAPIVersion, "plugin_id": r.release.PluginID, "version": r.release.Version,
		"artifact": asset("artifact", r.release.Artifact), "manifest": manifest,
	})
	if err != nil {
		panic(err)
	}
	return encoded
}

func observedPhase(control *agenttest.Control, operationID string) (agentv1pb.ObservedPhase, string) {
	phase, message := agentv1pb.ObservedPhase_OBSERVED_PHASE_UNSPECIFIED, ""
	for _, observed := range control.ObservedStates() {
		if observed.GetOperationId() == operationID {
			phase, message = observed.GetPhase(), observed.GetMessage()
		}
	}
	return phase, message
}

// TestEnrolledAgentUnderRequiredNeedsNoLegacyPath runs an enrolled Agent
// with the plugin supervisor against a Control in agent_control.mtls:
// required that serves the whole data plane: configuration, users, reports,
// the maintenance outbox, the alive list and a plugin install all ride the
// mTLS stream (and AgentArtifacts), and the legacy side sees not one
// request: no UniProxy, no node or agent WebSocket (also none for the
// maintenance outbox), no HTTP plugin download.
func TestEnrolledAgentUnderRequiredNeedsNoLegacyPath(t *testing.T) {
	previousInterval := streamMaintenanceInterval
	streamMaintenanceInterval = 100 * time.Millisecond
	t.Cleanup(func() { streamMaintenanceInterval = previousInterval })
	fixture := newStreamNodeFixture(t, agenttest.ModeRequired,
		agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers, agentcontrol.CapabilityReports, agentcontrol.CapabilityPackageReports,
		agentcontrol.CapabilityMaintenance, agentcontrol.CapabilityAlive, agentcontrol.CapabilityArtifacts)
	control := fixture.control
	control.SetDesiredConfig(agenttest.Snapshot(3, proxyDocument(443)), false)
	control.UpsertUsers(&agentv1pb.NodeUser{UserId: 1, Uuid: "user-1", DeviceLimit: 2}, &agentv1pb.NodeUser{UserId: 2, Uuid: "user-2"})
	control.SetAlive(map[uint64]uint32{1: 2, 9: 1})
	release := newSignedRelease(t, "wireguard", "4.0.0", []byte("plugin release over mTLS"))
	control.AddRelease(release.release)

	config := fixture.nodeConfig(t)
	config.ApiConfig.PluginSupervisorEnabled = true
	config.ApiConfig.PluginRoot = filepath.Join(t.TempDir(), "plugins")
	config.ApiConfig.PluginOfficialPublicKey = base64.StdEncoding.EncodeToString(release.publicKey)
	node := fixture.start(t, config)
	controller := node.controllers[0]
	require.NotNil(t, controller.pluginSupervisor)
	client := controller.stream.client
	require.Eventually(t, func() bool { return client.IsConnected() }, 5*time.Second, 10*time.Millisecond)
	for _, capability := range []string{agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers, agentcontrol.CapabilityReports,
		agentcontrol.CapabilityMaintenance, agentcontrol.CapabilityAlive, agentcontrol.CapabilityArtifacts} {
		assert.True(t, client.Negotiated(capability), capability)
	}

	// The alive list from the stream: the limiter counts it, and the next
	// list replaces it.
	require.Eventually(t, func() bool {
		controller.reconcileMu.Lock()
		defer controller.reconcileMu.Unlock()
		return controller.limiter != nil && controller.limiter.AliveList[1] == 2 && controller.limiter.AliveList[9] == 1
	}, 5*time.Second, 10*time.Millisecond)
	control.SetAlive(map[uint64]uint32{2: 1})
	require.Eventually(t, func() bool {
		controller.reconcileMu.Lock()
		defer controller.reconcileMu.Unlock()
		alive := controller.limiter.AliveList
		return len(alive) == 1 && alive[2] == 1
	}, 5*time.Second, 10*time.Millisecond)

	// A maintenance incident drains on the stream (maintenance.v1).
	store := controller.pluginSupervisor.MaintenanceStore()
	require.NotNil(t, store)
	failed := time.Now().Add(-3 * time.Minute).UTC()
	require.NoError(t, store.Queue(maintenance.Event{
		SchemaVersion: 1, EventID: "incident-1", OccurredAt: time.Now().Add(-time.Minute).UTC(), Environment: "development",
		Source: "agent", NodeID: strconv.Itoa(int(control.NodeID)), AgentVersion: panel.Version, PluginID: "machine-telemetry",
		PluginVersion: "1.0.0", InstanceID: "machine-telemetry", ErrorCode: "PLUGIN_HEALTH_FAILED", Severity: "P2", Status: "open",
		FirstFailedAt: &failed, ConsecutiveFailures: 2,
	}))
	require.Eventually(t, func() bool {
		pending, err := store.Pending(maintenance.MaxBatchSize)
		return err == nil && len(pending) == 0 && len(control.MaintenanceEvents()) == 1
	}, 5*time.Second, 20*time.Millisecond)
	assert.Equal(t, "incident-1", control.MaintenanceEvents()[0].EventID)

	// A plugin install downloads from AgentArtifacts by the certificate.
	operationID := control.SendOperation("plugin.install", func(sessionID, operationID string, revision uint64) []byte {
		return e2eOperationEnvelope(operationID, operationID, sessionID, revision, "wireguard", "4.0.0", release.installConfig())
	})
	require.Eventually(t, func() bool {
		phase, _ := observedPhase(control, operationID)
		return phase == agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED || phase == agentv1pb.ObservedPhase_OBSERVED_PHASE_FAILED
	}, 10*time.Second, 20*time.Millisecond)
	phase, message := observedPhase(control, operationID)
	require.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED, phase, message)
	assert.Equal(t, []string{"manifest:wireguard", "artifact:wireguard"}, control.ArtifactCalls())

	// Traffic and status on the stream too.
	fixture.core.setWindow([]panel.UserTraffic{{UID: 1, Upload: 10, Download: 20}}, []panel.OnlineUser{{UID: 1, IP: "198.51.100.9"}})
	require.NoError(t, controller.reportUserTrafficTask())
	require.Eventually(t, func() bool { return len(control.Batches()) >= 1 && len(control.NodeStatuses()) >= 1 }, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, controller.nodeInfoMonitor())

	// Not one legacy request: no UniProxy, no /api/v2/node/ws or
	// /api/v2/agent/ws (maintenance included), no
	// /api/v3/agent/plugin-releases download, no heartbeat or runtime
	// health route.
	assert.Empty(t, fixture.legacy.requests())
	controller.syncMu.Lock()
	assert.Nil(t, controller.syncManager, "no WebSocket, not even for maintenance")
	controller.syncMu.Unlock()
	for _, stream := range control.Streams() {
		assert.False(t, stream.APIKey, "never the node API key")
	}
}

// switchableHealthCore is a recordingCore whose runtime health a test sets.
type switchableHealthCore struct {
	*recordingCore
	healthy atomic.Bool
}

func (c *switchableHealthCore) RuntimeHealth(string) (bool, string) {
	if c.healthy.Load() {
		return true, ""
	}
	return false, "relay process exited"
}

func TestRuntimeHealthChangeSendsAStatusWithTheSystemUsage(t *testing.T) {
	fixture := newStreamNodeFixture(t, agenttest.ModeRequired,
		agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers, agentcontrol.CapabilityReports)
	fixture.control.SetDesiredConfig(agenttest.Snapshot(3, proxyDocument(443)), false)
	core := &switchableHealthCore{recordingCore: fixture.core}
	core.healthy.Store(true)
	node := New()
	require.NoError(t, node.Start([]conf.NodeConfig{fixture.nodeConfig(t)}, core))
	t.Cleanup(node.Close)
	controller := node.controllers[0]
	require.Eventually(t, func() bool { return len(fixture.control.NodeStatuses()) == 1 }, 5*time.Second, 10*time.Millisecond)
	assert.True(t, fixture.control.NodeStatuses()[0].RuntimeHealthy)

	// The runtime fails between two system samples (the status interval is
	// a minute): a NodeStatus goes out at once, with the usage too.
	core.healthy.Store(false)
	require.NoError(t, controller.nodeInfoMonitor())
	require.Eventually(t, func() bool { return len(fixture.control.NodeStatuses()) == 2 }, 5*time.Second, 10*time.Millisecond)
	status := fixture.control.NodeStatuses()[1]
	assert.False(t, status.RuntimeHealthy)
	assert.Equal(t, "relay process exited", status.RuntimeError)
	assert.Positive(t, status.MemoryUsagePercent, "the system usage, not zeros")
	assert.Positive(t, status.UptimeSeconds+1)

	// No change: nothing more before the interval.
	require.NoError(t, controller.nodeInfoMonitor())
	time.Sleep(300 * time.Millisecond)
	assert.Len(t, fixture.control.NodeStatuses(), 2)
	assert.Empty(t, fixture.legacy.requests())
}

func TestMaintenanceWebSocketStopsWhenALaterSessionNegotiatesMaintenance(t *testing.T) {
	fixture := newStreamNodeFixture(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers)
	fixture.control.SetDesiredConfig(agenttest.Snapshot(3, proxyDocument(443)), false)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	config := fixture.nodeConfig(t)
	config.ApiConfig.PluginSupervisorEnabled = true
	config.ApiConfig.PluginRoot = filepath.Join(t.TempDir(), "plugins")
	config.ApiConfig.PluginOfficialPublicKey = base64.StdEncoding.EncodeToString(publicKey)
	node := fixture.start(t, config)
	controller := node.controllers[0]
	controller.syncMu.Lock()
	running := controller.syncManager
	controller.syncMu.Unlock()
	require.NotNil(t, running, "Control without maintenance.v1: the maintenance WebSocket runs")
	assert.True(t, running.config.MaintenanceOnly)

	fixture.control.Serve(agentcontrol.CapabilityMaintenance, true)
	fixture.control.DropSessions()
	client := controller.stream.client
	require.Eventually(t, func() bool { return client.Negotiated(agentcontrol.CapabilityMaintenance) }, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, controller.nodeInfoMonitor())
	require.Eventually(t, func() bool {
		controller.syncMu.Lock()
		defer controller.syncMu.Unlock()
		return controller.syncManager == nil
	}, 5*time.Second, 10*time.Millisecond)
}

// An enrolled Agent whose Control predates AgentArtifacts (4.1.x, the
// v4.2 upgrade runs the new Agent first) installs plugins over the HTTP
// download with the node API key; a Control that refuses the key there
// (agent_mtls_required) is named in the failure.
func TestEnrolledAgentWithoutArtifactsFallsBackToTheHTTPDownload(t *testing.T) {
	fixture := newStreamNodeFixture(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers)
	control := fixture.control
	control.SetDesiredConfig(agenttest.Snapshot(3, proxyDocument(443)), false)
	release := newSignedRelease(t, "wireguard", "4.0.0", []byte("plugin release over HTTP"))
	var refuse atomic.Bool
	var keys []string
	var keysMu sync.Mutex
	fixture.legacy.mu.Lock()
	fixture.legacy.extra = func(w http.ResponseWriter, r *http.Request) bool {
		prefix := "/api/v3/agent/plugin-releases/wireguard/4.0.0/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			return false
		}
		keysMu.Lock()
		keys = append(keys, r.Header.Get("X-API-Key"))
		keysMu.Unlock()
		if refuse.Load() {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"code":"agent_mtls_required"}`))
			return true
		}
		if strings.HasSuffix(r.URL.Path, "/manifest") {
			_, _ = w.Write(release.release.Manifest)
		} else {
			_, _ = w.Write(release.release.Artifact)
		}
		return true
	}
	fixture.legacy.mu.Unlock()
	config := fixture.nodeConfig(t)
	config.ApiConfig.PluginSupervisorEnabled = true
	config.ApiConfig.PluginRoot = filepath.Join(t.TempDir(), "plugins")
	config.ApiConfig.PluginOfficialPublicKey = base64.StdEncoding.EncodeToString(release.publicKey)
	node := fixture.start(t, config)
	controller := node.controllers[0]
	client := controller.stream.client
	require.Eventually(t, func() bool { return client.IsConnected() }, 5*time.Second, 10*time.Millisecond)
	require.True(t, client.TransportStatus().Identity.Enrolled)
	require.False(t, client.Negotiated(agentcontrol.CapabilityArtifacts))
	assert.Equal(t, agentapi.PluginDownloadHTTP, client.PluginDownload())

	install := func() (agentv1pb.ObservedPhase, string) {
		operationID := control.SendOperation("plugin.install", func(sessionID, operationID string, revision uint64) []byte {
			return e2eOperationEnvelope(operationID, operationID, sessionID, revision, "wireguard", "4.0.0", release.installConfig())
		})
		require.Eventually(t, func() bool {
			phase, _ := observedPhase(control, operationID)
			return phase == agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED || phase == agentv1pb.ObservedPhase_OBSERVED_PHASE_FAILED
		}, 10*time.Second, 20*time.Millisecond)
		return observedPhase(control, operationID)
	}

	// A Control that refuses the key names agent_mtls_required.
	refuse.Store(true)
	phase, message := install()
	assert.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_FAILED, phase)
	assert.Contains(t, message, "agent_mtls_required")

	// A 4.1.x Control serves the HTTP download with the key.
	refuse.Store(false)
	phase, message = install()
	require.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED, phase, message)
	assert.Empty(t, control.ArtifactCalls())
	keysMu.Lock()
	defer keysMu.Unlock()
	require.NotEmpty(t, keys)
	for _, key := range keys {
		assert.Equal(t, control.APIKey, key)
	}
}
