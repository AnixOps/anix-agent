package plugin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/agent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPluginObservationsBindPrivateRuntimeEvidenceToSupervisorState(t *testing.T) {
	supervisor, now, configure := newObservedStateTestSupervisor(t, []string{"plugin.runtime-state", observedStateCapability})
	t.Cleanup(func() { require.NoError(t, supervisor.Close(context.Background())) })

	writeObservedStateForTest(t, supervisor.runtimeObservedStatePath("nftables-forward"), runtimeObservedState{
		Version: observedStateSchemaVersion, PluginID: "nftables-forward", PluginVersion: "1.2.0",
		Health: "healthy", ObservedAtUnixMs: now.UnixMilli(), RulesetSHA256: strings.Repeat("a", 64),
		RuleCounters: []runtimeObservedCounter{
			{RuleID: "udp-443", Packets: 11, Bytes: 1200},
			{RuleID: "tcp-443", Packets: 7, Bytes: 800},
		},
	})

	observations, err := supervisor.PluginObservations(context.Background())
	require.NoError(t, err)
	require.Len(t, observations, 1)
	observation := observations[0]
	assert.Equal(t, "nftables-forward", observation.PluginId)
	assert.Equal(t, "1.2.0", observation.Version)
	assert.Equal(t, uint64(8), observation.DesiredRevision)
	assert.Equal(t, uint64(8), observation.ObservedRevision)
	assert.Equal(t, configure.ConfigHash, observation.ConfigHash, "config_hash must be injected from Supervisor state")
	assert.Equal(t, "healthy", observation.Health)
	assert.Equal(t, strings.Repeat("a", 64), observation.RulesetSha256)
	require.Len(t, observation.RuleCounters, 2)
	assert.Equal(t, "tcp-443", observation.RuleCounters[0].RuleId, "counters are normalized before transport")
	assert.Equal(t, uint64(7), observation.RuleCounters[0].Packets)
	assert.Equal(t, "udp-443", observation.RuleCounters[1].RuleId)
}

func TestPluginObservationsOnlyReadExplicitlyCapablePlugins(t *testing.T) {
	supervisor, now, _ := newObservedStateTestSupervisor(t, []string{"plugin.runtime-state"})
	t.Cleanup(func() { require.NoError(t, supervisor.Close(context.Background())) })
	writeObservedStateForTest(t, supervisor.runtimeObservedStatePath("nftables-forward"), runtimeObservedState{
		Version: observedStateSchemaVersion, PluginID: "nftables-forward", PluginVersion: "1.2.0",
		Health: "healthy", ObservedAtUnixMs: now.UnixMilli(), RulesetSHA256: strings.Repeat("b", 64),
	})

	observations, err := supervisor.PluginObservations(context.Background())
	require.NoError(t, err)
	assert.Empty(t, observations)
}

func TestPluginObservationsFailClosedWhenRuntimeStopsServing(t *testing.T) {
	supervisor, now, _ := newObservedStateTestSupervisor(t, []string{"plugin.runtime-state", observedStateCapability})
	t.Cleanup(func() { require.NoError(t, supervisor.Close(context.Background())) })
	writeObservedStateForTest(t, supervisor.runtimeObservedStatePath("nftables-forward"), healthyObservedState(now))

	// A stale healthy file must never override a current runtime health failure.
	// This covers observation persistence failures too: the runtime changes its
	// health service to NOT_SERVING before the Supervisor collects evidence.
	supervisor.health = failingHealth{err: errors.New("runtime observation persistence failed")}
	observations, err := supervisor.PluginObservations(context.Background())
	require.ErrorContains(t, err, "runtime health is unavailable")
	require.Len(t, observations, 1)
	observation := observations[0]
	assert.Equal(t, "unhealthy", observation.Health)
	assert.Empty(t, observation.RulesetSha256)
	assert.Empty(t, observation.RuleCounters)
	assert.Equal(t, now.UnixMilli(), observation.ObservedAtUnixMs)

	state, inspectErr := supervisor.inspect("nftables-forward")
	require.NoError(t, inspectErr)
	var persisted PluginState
	require.NoError(t, json.Unmarshal(state, &persisted))
	assert.Equal(t, "unhealthy", persisted.Health)
}

func TestPluginObservationsHandleMissingStaleMalformedAndUnsafeFiles(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, supervisor *Supervisor, now time.Time)
		wantErr string
	}{
		{
			name:    "missing file is no evidence",
			prepare: func(*testing.T, *Supervisor, time.Time) {},
		},
		{
			name: "stale file is rejected",
			prepare: func(t *testing.T, supervisor *Supervisor, now time.Time) {
				writeObservedStateForTest(t, supervisor.runtimeObservedStatePath("nftables-forward"), healthyObservedState(now.Add(-maxObservedStateAge-time.Millisecond)))
			},
			wantErr: "read observed state",
		},
		{
			name: "unknown JSON never leaks raw content",
			prepare: func(t *testing.T, supervisor *Supervisor, now time.Time) {
				contents := []byte(fmt.Sprintf(`{"version":1,"plugin_id":"nftables-forward","plugin_version":"1.2.0","health":"healthy","observed_at_unix_ms":%d,"ruleset_sha256":"%s","secret":"do-not-send-this-value"}`,
					now.UnixMilli(), strings.Repeat("c", 64)))
				require.NoError(t, writePrivateFile(supervisor.runtimeObservedStatePath("nftables-forward"), contents, 0o600))
			},
			wantErr: "read observed state",
		},
		{
			name: "plugin cannot provide config hash",
			prepare: func(t *testing.T, supervisor *Supervisor, now time.Time) {
				contents := []byte(fmt.Sprintf(`{"version":1,"plugin_id":"nftables-forward","plugin_version":"1.2.0","health":"healthy","observed_at_unix_ms":%d,"ruleset_sha256":"%s","config_hash":"%s"}`,
					now.UnixMilli(), strings.Repeat("c", 64), strings.Repeat("e", 64)))
				require.NoError(t, writePrivateFile(supervisor.runtimeObservedStatePath("nftables-forward"), contents, 0o600))
			},
			wantErr: "read observed state",
		},
		{
			name: "oversized file is rejected",
			prepare: func(t *testing.T, supervisor *Supervisor, _ time.Time) {
				contents := make([]byte, maxObservedStateBytes+1)
				require.NoError(t, writePrivateFile(supervisor.runtimeObservedStatePath("nftables-forward"), contents, 0o600))
			},
			wantErr: "read observed state",
		},
		{
			name: "non-private file is rejected",
			prepare: func(t *testing.T, supervisor *Supervisor, now time.Time) {
				path := supervisor.runtimeObservedStatePath("nftables-forward")
				writeObservedStateForTest(t, path, healthyObservedState(now))
				require.NoError(t, os.Chmod(path, 0o644))
			},
			wantErr: "read observed state",
		},
		{
			name: "symlink file is rejected",
			prepare: func(t *testing.T, supervisor *Supervisor, now time.Time) {
				path := supervisor.runtimeObservedStatePath("nftables-forward")
				target := filepath.Join(t.TempDir(), "observation.json")
				writeObservedStateForTest(t, target, healthyObservedState(now))
				require.NoError(t, os.Symlink(target, path))
			},
			wantErr: "read observed state",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			supervisor, now, _ := newObservedStateTestSupervisor(t, []string{"plugin.runtime-state", observedStateCapability})
			t.Cleanup(func() { require.NoError(t, supervisor.Close(context.Background())) })
			tt.prepare(t, supervisor, now)

			observations, err := supervisor.PluginObservations(context.Background())
			if tt.wantErr == "" {
				require.NoError(t, err)
				assert.Empty(t, observations)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
			require.Len(t, observations, 1)
			assert.Equal(t, "unhealthy", observations[0].Health)
			assert.Empty(t, observations[0].RulesetSha256)
			assert.Empty(t, observations[0].RuleCounters)
			assert.NotContains(t, err.Error(), "do-not-send-this-value")
		})
	}
}

func TestManifestObservedStateCapabilityRequiresRuntimeState(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	supervisor, err := NewSupervisor(Config{RootDir: t.TempDir(), SocketDir: shortSocketDir(t), PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, supervisor.Close(context.Background())) })

	_, err = supervisor.Install(context.Background(), signedRequestWithCapabilities(t, privateKey, []byte("kernel-observation"), "nftables-forward", "1.2.0", []string{observedStateCapability}))
	require.ErrorContains(t, err, "kernel.observed-state capability requires plugin.runtime-state")
}

func newObservedStateTestSupervisor(t *testing.T, capabilities []string) (*Supervisor, time.Time, *agent.OperationEnvelope) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Date(2026, time.July, 17, 12, 0, 0, 0, time.UTC)
	supervisor, err := NewSupervisor(Config{
		RootDir: t.TempDir(), SocketDir: shortSocketDir(t), PublicKey: publicKey,
		Runner: &statefulCleanupRunner{}, Health: &fakeHealth{}, Now: func() time.Time { return now },
	})
	require.NoError(t, err)
	_, err = supervisor.Install(context.Background(), signedRequestWithCapabilities(t, privateKey, []byte("nftables-observed"), "nftables-forward", "1.2.0", capabilities))
	require.NoError(t, err)
	configure := testEnvelope("configure-observed", "nftables-forward", "1.2.0", 7, []byte(`{"apply":true}`))
	_, err = supervisor.Handle(context.Background(), "plugin.configure", configure)
	require.NoError(t, err)
	_, err = supervisor.Handle(context.Background(), "plugin.enable", testEnvelope("enable-observed", "nftables-forward", "1.2.0", 8, nil))
	require.NoError(t, err)
	return supervisor, now, configure
}

func healthyObservedState(now time.Time) runtimeObservedState {
	return runtimeObservedState{
		Version: observedStateSchemaVersion, PluginID: "nftables-forward", PluginVersion: "1.2.0",
		Health: "healthy", ObservedAtUnixMs: now.UnixMilli(), RulesetSHA256: strings.Repeat("d", 64),
	}
}

func writeObservedStateForTest(t *testing.T, path string, observed runtimeObservedState) {
	t.Helper()
	contents, err := json.Marshal(observed)
	require.NoError(t, err)
	require.NoError(t, writePrivateFile(path, contents, 0o600))
}
