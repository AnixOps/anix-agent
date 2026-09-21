package plugin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v4/common/maintenance"
	"github.com/stretchr/testify/require"
)

type maintenanceHealth struct {
	mu  sync.Mutex
	err error
}

func (h *maintenanceHealth) Check(context.Context, string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.err
}
func (h *maintenanceHealth) set(err error) { h.mu.Lock(); defer h.mu.Unlock(); h.err = err }

func TestMaintenanceHealthRestartBudgetSurvivesSupervisorRestart(t *testing.T) {
	root := t.TempDir()
	socket := shortSocketDir(t)
	now := time.Now().Add(-time.Hour)
	store, err := maintenance.Open(filepath.Join(root, "maintenance.json"), "1", "development", "1.0.0")
	require.NoError(t, err)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	runner := &fakeRunner{}
	health := &maintenanceHealth{}
	cfg := Config{RootDir: root, SocketDir: socket, PublicKey: pub, Runner: runner, Health: health, Now: func() time.Time { return now }, Maintenance: store, DisableMaintenanceMonitor: true}
	supervisor, err := NewSupervisor(cfg)
	require.NoError(t, err)
	_, err = supervisor.Install(context.Background(), signedRequest(t, priv, []byte("signed-test-plugin"), "machine-telemetry", "1.0.0"))
	require.NoError(t, err)
	_, err = supervisor.Handle(context.Background(), "plugin.configure", testEnvelope("config-maintenance", "machine-telemetry", "1.0.0", 1, []byte(`{}`)))
	require.NoError(t, err)
	_, err = supervisor.Handle(context.Background(), "plugin.enable", testEnvelope("enable-maintenance", "machine-telemetry", "1.0.0", 2, nil))
	require.NoError(t, err)
	health.set(errors.New("unhealthy socket"))
	for i := 0; i < 2; i++ {
		require.NoError(t, supervisor.CheckMaintenance(context.Background()))
		now = now.Add(time.Minute)
	}
	require.Equal(t, 1, runner.Starts())
	require.Error(t, supervisor.CheckMaintenance(context.Background()))
	require.Equal(t, 2, runner.Starts())
	now = now.Add(30 * time.Second)
	require.Error(t, supervisor.CheckMaintenance(context.Background()))
	require.Equal(t, 3, runner.Starts())
	require.NoError(t, supervisor.Close(context.Background()))
	runner = &fakeRunner{}
	cfg.Runner = runner
	reopened, err := maintenance.Open(filepath.Join(root, "maintenance.json"), "1", "development", "1.0.0")
	require.NoError(t, err)
	cfg.Maintenance = reopened
	supervisor, err = NewSupervisor(cfg)
	require.NoError(t, err)
	require.Equal(t, 0, runner.Starts(), "unhealthy startup must not bypass persisted restart budget")
	now = now.Add(time.Minute)
	require.NoError(t, supervisor.CheckMaintenance(context.Background()))
	require.Equal(t, 0, runner.Starts())
	now = now.Add(30 * time.Minute)
	health.set(nil)
	require.NoError(t, supervisor.CheckMaintenance(context.Background()))
	require.Equal(t, 1, runner.Starts())
	events, err := reopened.Pending(50)
	require.NoError(t, err)
	require.NotEmpty(t, events)
	var blocked, succeeded bool
	for _, e := range events {
		blocked = blocked || e.SelfHealResult == "blocked"
		succeeded = succeeded || e.SelfHealResult == "succeeded"
		require.Empty(t, e.RedactedSummary)
	}
	require.True(t, blocked)
	require.True(t, succeeded)
	require.NoError(t, supervisor.Close(context.Background()))
}
func TestMaintenanceRealExitCreatesPersistentFaultAndManualErrors(t *testing.T) {
	root := t.TempDir()
	now := time.Now().Add(-time.Hour)
	store, err := maintenance.Open(filepath.Join(root, "maintenance.json"), "1", "development", "1")
	require.NoError(t, err)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	runner := &watchableRunner{}
	health := &maintenanceHealth{}
	supervisor, err := NewSupervisor(Config{RootDir: root, SocketDir: shortSocketDir(t), PublicKey: pub, Runner: runner, Health: health, Now: func() time.Time { return now }, Maintenance: store, DisableMaintenanceMonitor: true})
	require.NoError(t, err)
	_, err = supervisor.Install(context.Background(), signedRequest(t, priv, []byte("plugin"), "machine-telemetry", "1"))
	require.NoError(t, err)
	_, err = supervisor.Handle(context.Background(), "plugin.configure", testEnvelope("config-maintenance", "machine-telemetry", "1", 1, []byte(`{}`)))
	require.NoError(t, err)
	_, err = supervisor.Handle(context.Background(), "plugin.enable", testEnvelope("start", "machine-telemetry", "1", 2, nil))
	require.NoError(t, err)
	runner.Process().Crash(errors.New("process exit diagnostic contains password=never-send"))
	require.Eventually(t, func() bool {
		supervisor.mu.Lock()
		defer supervisor.mu.Unlock()
		state := supervisor.state.Plugins["machine-telemetry"]
		return !state.Enabled && !state.CleanupPending
	}, time.Second, 5*time.Millisecond)
	for i := 0; i < 2; i++ {
		now = now.Add(time.Minute)
		require.NoError(t, supervisor.CheckMaintenance(context.Background()))
	}
	events, err := store.Pending(50)
	require.NoError(t, err)
	require.Len(t, events, 2)
	require.Equal(t, "PLUGIN_PROCESS_EXITED", events[0].ErrorCode)
	require.Equal(t, "succeeded", events[1].SelfHealResult)
	health.set(errors.New("config validation failed: token=do-not-send"))
	now = now.Add(time.Minute)
	require.NoError(t, supervisor.CheckMaintenance(context.Background()))
	events, err = store.Pending(50)
	require.NoError(t, err)
	require.Len(t, events, 3)
	require.Equal(t, "PLUGIN_CONFIG_INVALID", events[2].ErrorCode)
	require.Equal(t, "blocked", events[2].SelfHealResult)
	require.NoError(t, supervisor.Close(context.Background()))
}
func TestMaintenanceWorkerStopsAndDisabledPluginIsExcluded(t *testing.T) {
	root := t.TempDir()
	store, err := maintenance.Open(filepath.Join(root, "maintenance.json"), "1", "development", "1")
	require.NoError(t, err)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	health := &maintenanceHealth{}
	s, err := NewSupervisor(Config{RootDir: root, SocketDir: shortSocketDir(t), PublicKey: pub, Runner: &fakeRunner{}, Health: health, Maintenance: store})
	require.NoError(t, err)
	_, err = s.Install(context.Background(), signedRequest(t, priv, []byte("plugin"), "machine-telemetry", "1"))
	require.NoError(t, err)
	health.set(errors.New("config invalid"))
	require.NoError(t, s.CheckMaintenance(context.Background()))
	events, err := store.Pending(50)
	require.NoError(t, err)
	require.Empty(t, events)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, s.Close(ctx))
	select {
	case <-s.maintenanceDone:
	default:
		t.Fatal("maintenance worker outlived close")
	}
	require.Error(t, s.CheckMaintenance(context.Background()))
}

func TestMaintenanceInvalidOnDiskConfigRequiresManualAction(t *testing.T) {
	root := t.TempDir()
	store, err := maintenance.Open(filepath.Join(root, "maintenance.json"), "1", "development", "1")
	require.NoError(t, err)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	runner := &fakeRunner{}
	now := time.Now().Add(-time.Hour)
	s, err := NewSupervisor(Config{RootDir: root, SocketDir: shortSocketDir(t), PublicKey: pub, Runner: runner, Health: &maintenanceHealth{}, Now: func() time.Time { return now }, Maintenance: store, DisableMaintenanceMonitor: true})
	require.NoError(t, err)
	_, err = s.Install(context.Background(), signedRequest(t, priv, []byte("plugin"), "machine-telemetry", "1"))
	require.NoError(t, err)
	_, err = s.Handle(context.Background(), "plugin.configure", testEnvelope("configure", "machine-telemetry", "1", 1, []byte(`{}`)))
	require.NoError(t, err)
	_, err = s.Handle(context.Background(), "plugin.enable", testEnvelope("enable", "machine-telemetry", "1", 2, nil))
	require.NoError(t, err)
	require.NoError(t, writePrivateFile(filepath.Join(root, "machine-telemetry", "1", "config.json"), []byte(`{"interval_seconds":0}`), 0600))
	require.NoError(t, s.CheckMaintenance(context.Background()))
	require.Equal(t, 1, runner.Starts())
	events, err := store.Pending(50)
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, "PLUGIN_CONFIG_INVALID", events[0].ErrorCode)
	require.Equal(t, "blocked", events[0].SelfHealResult)
	// Even a valid new configuration requires an operator operation to approve its hash.
	require.NoError(t, writePrivateFile(filepath.Join(root, "machine-telemetry", "1", "config.json"), []byte(`{"interval_seconds":5}`), 0600))
	now = now.Add(time.Minute)
	require.NoError(t, s.CheckMaintenance(context.Background()))
	require.Equal(t, 1, runner.Starts())
	require.NoError(t, s.Close(context.Background()))
}
