package agent_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	"github.com/AnixOps/anix-agent/v4/api/agent/agenttest"
	"github.com/AnixOps/anix-agent/v4/api/agent/state"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// recordingApplier records the snapshots it applies; err, when set, fails
// them, and block holds each apply until released.
type recordingApplier struct {
	mu      sync.Mutex
	applied []*agentv1pb.ConfigSnapshot
	err     error
	block   chan struct{}
	entered chan struct{}
}

func (a *recordingApplier) ApplyConfig(ctx context.Context, snapshot *agentv1pb.ConfigSnapshot) error {
	if a.entered != nil {
		select {
		case a.entered <- struct{}{}:
		default:
		}
	}
	if a.block != nil {
		select {
		case <-a.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.applied = append(a.applied, proto.Clone(snapshot).(*agentv1pb.ConfigSnapshot))
	return a.err
}

func (a *recordingApplier) revisions() []uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	var revisions []uint64
	for _, snapshot := range a.applied {
		revisions = append(revisions, snapshot.GetConfigRevision())
	}
	return revisions
}

func (a *recordingApplier) setErr(err error) {
	a.mu.Lock()
	a.err = err
	a.mu.Unlock()
}

func configDocument(name string) map[string]any {
	return map[string]any{"kind": "proxy", "node": map[string]any{"id": 12, "name": name}, "legacy_pull": map[string]any{"default": map[string]any{"node_type": "vless"}}}
}

func openState(t *testing.T, root string) *state.Store {
	t.Helper()
	store, err := state.Open(root, agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: 12})
	require.NoError(t, err)
	return store
}

func newDataPlaneClient(t *testing.T, control *agenttest.Control, root string, applier agentapi.ConfigApplier, grace time.Duration) *agentapi.Client {
	t.Helper()
	client, err := agentapi.NewClient(agentapi.Config{
		Target: control.Address, NodeID: int(control.NodeID), APIKey: control.APIKey, UseTLS: true, ServerName: control.ServerName,
		RootCAs: control.ServerCAs, AgentVersion: "test-agent", InstanceID: "instance-1",
		Capabilities: []*agentv1pb.Capability{{Name: "agent.control", Version: "v1"}},
		Heartbeat:    time.Second, ReconnectMin: 10 * time.Millisecond, ReconnectMax: 50 * time.Millisecond,
		DialTimeout: 2 * time.Second,
		DataPlane:   &agentapi.DataPlaneConfig{State: openState(t, root), Config: applier, LegacyGrace: grace},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func waitSession(t *testing.T, client *agentapi.Client) agentapi.DataPlaneSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := client.DataPlane().WaitSession(ctx)
	require.NoError(t, err)
	return session
}

func statusesOf(control *agenttest.Control) []*agentv1pb.ConfigStatus {
	return control.ConfigStatuses()
}

func TestDataPlaneAdvertisesConfigAndAppliesTheHelloSnapshot(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeOptional, agentcontrol.CapabilityConfig)
	desired := agenttest.Snapshot(3, configDocument("a"))
	control.SetDesiredConfig(desired, false)
	root := t.TempDir()
	applier := &recordingApplier{}
	client := newDataPlaneClient(t, control, root, applier, time.Minute)
	require.NoError(t, client.Start())
	session := waitSession(t, client)
	assert.True(t, session.Has(agentcontrol.CapabilityConfig))
	client.DataPlane().Activate()

	require.Eventually(t, func() bool { return len(statusesOf(control)) == 1 }, 5*time.Second, 10*time.Millisecond)
	status := statusesOf(control)[0]
	assert.Equal(t, uint64(3), status.ConfigRevision)
	assert.Equal(t, desired.ConfigHash, status.ConfigHash)
	assert.True(t, status.Applied)
	assert.Empty(t, status.Error)
	assert.Equal(t, []uint64{3}, applier.revisions())

	hellos := control.Hellos()
	require.Len(t, hellos, 1)
	assert.True(t, agentcontrol.HasCapabilityVersion(hellos[0].Capabilities, agentcontrol.CapabilityConfig, "v1"))
	assert.Zero(t, hellos[0].ConfigRevision)
	assert.Equal(t, agentapi.DataPlaneStream, client.DataPlane().Mode(agentcontrol.CapabilityConfig))

	// The applied snapshot is kept, private to the Agent.
	info, err := os.Stat(filepath.Join(root, "proxy-12", "config.pb"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	dirInfo, err := os.Stat(filepath.Join(root, "proxy-12"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())
	stored, err := openState(t, root).LoadConfig()
	require.NoError(t, err)
	assert.True(t, proto.Equal(desired, stored))
	assert.Equal(t, uint64(3), client.TransportStatus().DataPlane.ConfigRevision)
}

func TestDataPlaneRestartReportsTheStoredRevisionAndIsNotSentItAgain(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeOptional, agentcontrol.CapabilityConfig)
	desired := agenttest.Snapshot(5, configDocument("a"))
	control.SetDesiredConfig(desired, false)
	root := t.TempDir()

	first := newDataPlaneClient(t, control, root, &recordingApplier{}, time.Minute)
	require.NoError(t, first.Start())
	waitSession(t, first)
	first.DataPlane().Activate()
	require.Eventually(t, func() bool { return len(statusesOf(control)) == 1 }, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, first.Close())

	// Restart: the stored snapshot runs without Control, and Hello reports
	// its revision.
	applier := &recordingApplier{}
	second := newDataPlaneClient(t, control, root, applier, time.Minute)
	persisted := second.DataPlane().PersistedConfig()
	require.NotNil(t, persisted)
	assert.True(t, proto.Equal(desired, persisted))
	second.DataPlane().RestoreConfig(persisted)
	require.NoError(t, second.Start())
	waitSession(t, second)
	second.DataPlane().Activate()

	time.Sleep(200 * time.Millisecond)
	hellos := control.Hellos()
	require.Len(t, hellos, 2)
	assert.Equal(t, uint64(5), hellos[1].ConfigRevision)
	assert.Len(t, control.SentConfigs(), 1, "Control sends nothing for the revision the Agent reports")
	assert.Empty(t, applier.revisions())

	// A newer desired configuration is pushed and applied.
	newer := agenttest.Snapshot(6, configDocument("b"))
	control.SetDesiredConfig(newer, true)
	require.Eventually(t, func() bool { return len(statusesOf(control)) == 2 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, []uint64{6}, applier.revisions())
	assert.True(t, statusesOf(control)[1].Applied)
}

func TestDataPlaneRefusesASnapshotThatDoesNotVerify(t *testing.T) {
	codes := map[string]string{"hash": agentcontrol.ConfigErrorCodeHashMismatch, "format": agentcontrol.ConfigErrorCodeFormatUnsupported}
	for name, mutate := range map[string]func(*agentv1pb.ConfigSnapshot){
		"hash":   func(snapshot *agentv1pb.ConfigSnapshot) { snapshot.ConfigHash = "00" },
		"format": func(snapshot *agentv1pb.ConfigSnapshot) { snapshot.Format = "anixops.nodeconfig/v2" },
	} {
		t.Run(name, func(t *testing.T) {
			control := agenttest.New(t, agenttest.ModeOptional, agentcontrol.CapabilityConfig)
			snapshot := agenttest.Snapshot(4, configDocument("a"))
			mutate(snapshot)
			control.SetDesiredConfig(snapshot, false)
			applier := &recordingApplier{}
			client := newDataPlaneClient(t, control, t.TempDir(), applier, time.Minute)
			require.NoError(t, client.Start())
			waitSession(t, client)
			client.DataPlane().Activate()

			require.Eventually(t, func() bool { return len(statusesOf(control)) == 1 }, 5*time.Second, 10*time.Millisecond)
			status := statusesOf(control)[0]
			assert.Equal(t, uint64(4), status.ConfigRevision)
			assert.False(t, status.Applied)
			assert.NotEmpty(t, status.Error)
			assert.Equal(t, codes[name], status.ErrorCode)
			assert.Empty(t, applier.revisions())
			assert.Nil(t, client.DataPlane().PersistedConfig())
			assert.Equal(t, float64(1), heartbeatMetric(t, control, agentapi.MetricConfigApplyFailures))
		})
	}
}

func TestDataPlaneReportsApplyErrorsAndKeepsTheRunningRevision(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeOptional, agentcontrol.CapabilityConfig)
	good := agenttest.Snapshot(2, configDocument("a"))
	control.SetDesiredConfig(good, false)
	root := t.TempDir()
	applier := &recordingApplier{}
	client := newDataPlaneClient(t, control, root, applier, time.Minute)
	require.NoError(t, client.Start())
	waitSession(t, client)
	client.DataPlane().Activate()
	require.Eventually(t, func() bool { return len(statusesOf(control)) == 1 }, 5*time.Second, 10*time.Millisecond)

	applier.setErr(errors.New("core refused the inbound"))
	control.SetDesiredConfig(agenttest.Snapshot(3, configDocument("b")), true)
	require.Eventually(t, func() bool { return len(statusesOf(control)) == 2 }, 5*time.Second, 10*time.Millisecond)
	failed := statusesOf(control)[1]
	assert.Equal(t, uint64(3), failed.ConfigRevision)
	assert.False(t, failed.Applied)
	assert.Contains(t, failed.Error, "core refused the inbound")
	assert.Equal(t, agentcontrol.ConfigErrorCodeApplyFailed, failed.ErrorCode)
	assert.Empty(t, statusesOf(control)[0].ErrorCode, "no code when applied")

	// A document the node cannot read is config_invalid.
	applier.setErr(agentapi.InvalidConfig(errors.New("no legacy_pull")))
	control.SetDesiredConfig(agenttest.Snapshot(4, configDocument("c")), true)
	require.Eventually(t, func() bool { return len(statusesOf(control)) == 3 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, agentcontrol.ConfigErrorCodeInvalid, statusesOf(control)[2].ErrorCode)
	assert.Equal(t, "no legacy_pull", statusesOf(control)[2].Error)

	// The node still runs revision 2: that is what is stored and what the
	// next Hello reports, so Control sends the desired revision again.
	stored, err := openState(t, root).LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, uint64(2), stored.ConfigRevision)
	applier.setErr(nil)
	control.DropSessions()
	require.Eventually(t, func() bool { return len(control.Hellos()) == 2 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, uint64(2), control.Hellos()[1].ConfigRevision)
	require.Eventually(t, func() bool { return len(statusesOf(control)) == 4 }, 5*time.Second, 10*time.Millisecond)
	assert.True(t, statusesOf(control)[3].Applied)
	assert.Equal(t, uint64(4), statusesOf(control)[3].ConfigRevision)
}

func TestDataPlaneDeliversAStatusAfterReconnectingWhenTheSessionEndedDuringTheApply(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeOptional, agentcontrol.CapabilityConfig)
	control.SetDesiredConfig(agenttest.Snapshot(7, configDocument("a")), false)
	applier := &recordingApplier{block: make(chan struct{}), entered: make(chan struct{}, 1)}
	client := newDataPlaneClient(t, control, t.TempDir(), applier, time.Minute)
	require.NoError(t, client.Start())
	waitSession(t, client)
	client.DataPlane().Activate()
	select {
	case <-applier.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the snapshot was not applied")
	}
	// The session ends while the node applies; Control then stops serving
	// config.v1 while the Agent reconnects, so the status waits.
	control.Serve(agentcontrol.CapabilityConfig, false)
	control.DropSessions()
	require.Eventually(t, func() bool { return len(control.Hellos()) == 2 }, 5*time.Second, 10*time.Millisecond)
	close(applier.block)
	time.Sleep(200 * time.Millisecond)
	assert.Empty(t, statusesOf(control), "a status is sent only on a session that negotiated config.v1")

	control.Serve(agentcontrol.CapabilityConfig, true)
	control.DropSessions()
	require.Eventually(t, func() bool { return len(statusesOf(control)) == 1 }, 5*time.Second, 10*time.Millisecond)
	status := statusesOf(control)[0]
	assert.True(t, status.Applied)
	assert.Equal(t, uint64(7), status.ConfigRevision)
	hellos := control.Hellos()
	assert.Equal(t, uint64(7), hellos[len(hellos)-1].ConfigRevision)
}

func TestDataPlaneAppliesOnlyTheNewestOfSnapshotsThatArriveDuringAnApply(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeOptional, agentcontrol.CapabilityConfig)
	control.SetDesiredConfig(agenttest.Snapshot(1, configDocument("a")), false)
	applier := &recordingApplier{block: make(chan struct{}), entered: make(chan struct{}, 1)}
	client := newDataPlaneClient(t, control, t.TempDir(), applier, time.Minute)
	require.NoError(t, client.Start())
	waitSession(t, client)
	client.DataPlane().Activate()
	<-applier.entered
	control.SetDesiredConfig(agenttest.Snapshot(2, configDocument("b")), true)
	control.SetDesiredConfig(agenttest.Snapshot(3, configDocument("c")), true)
	time.Sleep(100 * time.Millisecond)
	close(applier.block)
	require.Eventually(t, func() bool { return len(statusesOf(control)) == 2 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, []uint64{1, 3}, applier.revisions())
}

func TestDataPlaneWithoutConfigServedKeepsTheLegacyTransport(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeOptional)
	applier := &recordingApplier{}
	client := newDataPlaneClient(t, control, t.TempDir(), applier, time.Minute)
	require.NoError(t, client.Start())
	session := waitSession(t, client)
	assert.False(t, session.Has(agentcontrol.CapabilityConfig))
	assert.Equal(t, agentapi.DataPlaneLegacy, client.DataPlane().Mode(agentcontrol.CapabilityConfig))
	assert.False(t, client.Negotiated(agentcontrol.CapabilityConfig))
	hellos := control.Hellos()
	require.Len(t, hellos, 1)
	assert.True(t, agentcontrol.HasCapabilityVersion(hellos[0].Capabilities, agentcontrol.CapabilityConfig, "v1"), "the Agent advertises config.v1; Control decides")
}

func TestDataPlaneModeIsPendingWithinTheGraceAndLegacyAfter(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeOptional, agentcontrol.CapabilityConfig)
	client := newDataPlaneClient(t, control, t.TempDir(), &recordingApplier{}, 300*time.Millisecond)
	require.NoError(t, client.Start())
	waitSession(t, client)
	plane := client.DataPlane()
	assert.Equal(t, agentapi.DataPlaneStream, plane.Mode(agentcontrol.CapabilityConfig))

	control.SetMode(agenttest.ModeRequired) // the API key is refused from now on
	control.DropSessions()
	require.Eventually(t, func() bool { return !client.IsConnected() }, 5*time.Second, 5*time.Millisecond)
	assert.Equal(t, agentapi.DataPlanePending, plane.Mode(agentcontrol.CapabilityConfig))
	require.Eventually(t, func() bool { return plane.Mode(agentcontrol.CapabilityConfig) == agentapi.DataPlaneLegacy }, 5*time.Second, 20*time.Millisecond)
}

func TestDataPlaneStartsPendingAfterARestartWhenTheLastSessionCarriedConfig(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeOptional, agentcontrol.CapabilityConfig)
	root := t.TempDir()
	first := newDataPlaneClient(t, control, root, &recordingApplier{}, time.Minute)
	require.NoError(t, first.Start())
	waitSession(t, first)
	require.NoError(t, first.Close())

	second := newDataPlaneClient(t, control, root, &recordingApplier{}, time.Minute)
	assert.Equal(t, agentapi.DataPlanePending, second.DataPlane().Mode(agentcontrol.CapabilityConfig))

	// State of another Control is not trusted.
	other, err := agentapi.NewClient(agentapi.Config{
		Target: "other-control.test:50051", NodeID: 12, APIKey: "key", AgentVersion: "test-agent",
		DataPlane: &agentapi.DataPlaneConfig{State: openState(t, root), Config: &recordingApplier{}},
	})
	require.NoError(t, err)
	assert.Equal(t, agentapi.DataPlaneLegacy, other.DataPlane().Mode(agentcontrol.CapabilityConfig))
	assert.Nil(t, other.DataPlane().PersistedConfig())
}

func TestNewClientRefusesDataPlaneCapabilitiesWithoutAHandler(t *testing.T) {
	_, err := agentapi.NewClient(agentapi.Config{
		Target: "unused:1", NodeID: 1, APIKey: "key", AgentVersion: "test-agent",
		Capabilities: []*agentv1pb.Capability{{Name: agentcontrol.CapabilityConfig, Version: "v1"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config.v1 needs a DataPlane handler")
}

// heartbeatMetric waits for a heartbeat carrying metric and returns it.
func heartbeatMetric(t *testing.T, control *agenttest.Control, metric string) float64 {
	t.Helper()
	var value float64
	require.Eventually(t, func() bool {
		messages := control.Received()
		for index := len(messages) - 1; index >= 0; index-- {
			if heartbeat := messages[index].GetHeartbeat(); heartbeat != nil {
				if got, ok := heartbeat.Metrics[metric]; ok {
					value = got
					return true
				}
			}
		}
		return false
	}, 5*time.Second, 20*time.Millisecond)
	return value
}
