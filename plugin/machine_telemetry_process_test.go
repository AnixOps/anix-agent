package plugin

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"github.com/AnixOps/anix-agent/v4/common/maintenance"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v4/plugin/machinetelemetry"
	"github.com/stretchr/testify/require"
)

func TestMachineTelemetryBinaryWithProductionRuntime(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket plugin runtime")
	}
	if testing.Short() {
		t.Skip("builds the reference plugin binary")
	}

	_, sourceFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	repositoryRoot := filepath.Dir(filepath.Dir(sourceFile))
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	binaryPath := filepath.Join(dir, "plugin")
	build := exec.Command("go", "build", "-o", binaryPath, "./cmd/machine-telemetry")
	build.Dir = repositoryRoot
	build.Env = append(os.Environ(), "GOWORK=off", "GOEXPERIMENT=jsonv2")
	output, err := build.CombinedOutput()
	require.NoError(t, err, string(output))
	binary, err := os.ReadFile(binaryPath)
	require.NoError(t, err)

	webUI := []byte(`export default { name: "MachineTelemetry" }`)
	entrypoint := filepath.ToSlash(filepath.Join("agent", runtime.GOOS+"-"+runtime.GOARCH, "plugin"))
	artifact := buildMachineTelemetryPackage(t, entrypoint, binary, webUI)
	artifactDigest := sha256.Sum256(artifact)
	webUIDigest := sha256.Sum256(webUI)
	manifest := Manifest{
		ID: IDForMachineTelemetryTest, Name: "Machine Telemetry", Version: machinetelemetry.Version,
		APIVersion: pluginAPIVersion, Publisher: manifestPublisher,
		Targets: []string{"control", "agent"}, Architectures: []string{runtime.GOOS + "/" + runtime.GOARCH},
		ArtifactSHA256: hex.EncodeToString(artifactDigest[:]), Capabilities: []string{"telemetry.read"},
		Permissions: []string{"machine-telemetry.view"}, ConfigSchema: []byte(`{"additionalProperties":false,"properties":{"interval_seconds":{"maximum":3600,"minimum":5,"type":"integer"}},"type":"object"}`),
		Entrypoints:    map[string]string{"agent-" + runtime.GOOS + "-" + runtime.GOARCH: entrypoint},
		FrontendSHA256: hex.EncodeToString(webUIDigest[:]),
		WebUI: &PluginWebUI{
			Bundle:      PluginWebUIBundle{Path: "webui/index.mjs", SHA256: hex.EncodeToString(webUIDigest[:])},
			Permissions: []string{"machine-telemetry.view"},
			Menus: []PluginWebUIMenu{{
				ID: "machine-telemetry.main", Parent: "services", Label: "Machine Telemetry", Icon: "activity",
				Route: "/admin/extensions/machine-telemetry", Permission: "machine-telemetry.view", Order: 100,
			}},
			Routes: []PluginWebUIRoute{{
				ID: "machine-telemetry.main", Path: "/admin/extensions/machine-telemetry", Export: "default", Permission: "machine-telemetry.view",
			}},
		},
	}
	canonical, err := CanonicalManifest(manifest)
	require.NoError(t, err)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	request := InstallRequest{
		ManifestJSON: string(canonical),
		Signature:    base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)),
		Artifact:     artifact,
	}

	rootDir := filepath.Join(dir, "state")
	socketDir := filepath.Join(dir, "sockets")
	store, err := maintenance.Open(filepath.Join(rootDir, "maintenance.json"), "77", "development", "1.0.0")
	require.NoError(t, err)
	var observedTime atomic.Int64
	observedTime.Store(time.Now().Add(-time.Hour).UnixNano())
	supervisor, err := NewSupervisor(Config{
		Maintenance: store, DisableMaintenanceMonitor: true, Now: func() time.Time { return time.Unix(0, observedTime.Load()) },
		RootDir: rootDir, SocketDir: socketDir, PublicKey: publicKey,
		Runner: CommandRunner{}, Health: GRPCHealthChecker{Service: IDForMachineTelemetryTest, Timeout: 10 * time.Second},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = supervisor.Close(closeCtx)
	})
	_, err = supervisor.Install(context.Background(), request)
	require.NoError(t, err)

	config := []byte(`{"interval_seconds":5}`)
	_, err = supervisor.Handle(context.Background(), "plugin.configure", testEnvelope("machine-telemetry-configure", IDForMachineTelemetryTest, machinetelemetry.Version, 1, config))
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(rootDir, IDForMachineTelemetryTest, machinetelemetry.Version, "config.json"))

	startupCtx, cancelStartup := context.WithTimeout(context.Background(), 15*time.Second)
	_, err = supervisor.Handle(startupCtx, "plugin.enable", testEnvelope("machine-telemetry-enable", IDForMachineTelemetryTest, machinetelemetry.Version, 2, nil))
	require.NoError(t, err)
	cancelStartup()

	socketPath := filepath.Join(socketDir, IDForMachineTelemetryTest+".sock")
	healthCtx, cancelHealth := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelHealth()
	require.NoError(t, (GRPCHealthChecker{Timeout: time.Second}).Check(healthCtx, socketPath), "startup context cancellation must not terminate the plugin")
	metricsCtx, cancelMetrics := context.WithTimeout(context.Background(), 5*time.Second)
	metrics, metricsErr := supervisor.TelemetryMetrics(metricsCtx)
	cancelMetrics()
	require.NoError(t, metricsErr)
	require.NotEmpty(t, metrics)
	require.Contains(t, metrics, "plugin.machine-telemetry.cpu_usage_percent")
	require.Contains(t, metrics, "plugin.machine-telemetry.memory_usage_percent")
	require.Contains(t, metrics, "plugin.machine-telemetry.disk_usage_percent")
	require.Contains(t, metrics, "plugin.machine-telemetry.uptime_seconds")

	require.NoError(t, supervisor.CheckMaintenance(context.Background()))
	supervisor.mu.Lock()
	pid := supervisor.processes[IDForMachineTelemetryTest].PID()
	supervisor.mu.Unlock()
	observedTime.Add(int64(time.Second))
	crashed, err := os.FindProcess(pid)
	require.NoError(t, err)
	require.NoError(t, crashed.Kill())
	require.Eventually(t, func() bool {
		supervisor.mu.Lock()
		defer supervisor.mu.Unlock()
		state := supervisor.state.Plugins[IDForMachineTelemetryTest]
		return state.Health == "unhealthy" && !state.CleanupPending
	}, 5*time.Second, 10*time.Millisecond)
	for i := 0; i < 2; i++ {
		observedTime.Add(int64(time.Minute))
		require.NoError(t, supervisor.CheckMaintenance(context.Background()))
	}
	events, err := store.Pending(50)
	require.NoError(t, err)
	require.Len(t, events, 2)
	require.Equal(t, "PLUGIN_PROCESS_EXITED", events[0].ErrorCode)
	require.Equal(t, "succeeded", events[1].SelfHealResult)
	metrics, err = supervisor.TelemetryMetrics(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, metrics)
	for i := 0; i < 6; i++ {
		observedTime.Add(int64(time.Minute))
		require.NoError(t, supervisor.CheckMaintenance(context.Background()))
	}
	events, err = store.Pending(50)
	require.NoError(t, err)
	require.Len(t, events, 3)
	require.Equal(t, "recovered", events[2].Status)

	stopCtx, cancelStop := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelStop()
	_, err = supervisor.Handle(stopCtx, "plugin.disable", testEnvelope("machine-telemetry-disable", IDForMachineTelemetryTest, machinetelemetry.Version, 3, nil))
	require.NoError(t, err)
	_, err = os.Lstat(socketPath)
	require.ErrorIs(t, err, os.ErrNotExist)
}

const IDForMachineTelemetryTest = "machine-telemetry"

func buildMachineTelemetryPackage(t *testing.T, entrypoint string, binary, webUI []byte) []byte {
	t.Helper()
	var artifact bytes.Buffer
	writer := zip.NewWriter(&artifact)
	entry, err := writer.Create(entrypoint)
	require.NoError(t, err)
	_, err = entry.Write(binary)
	require.NoError(t, err)
	bundle, err := writer.Create("webui/index.mjs")
	require.NoError(t, err)
	_, err = bundle.Write(webUI)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return artifact.Bytes()
}
