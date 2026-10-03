package plugin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v4/plugin/machinetelemetry"
	"github.com/AnixOps/anix-control/sdk/telemetry/systemdreport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommandRunnerHandsThePluginItsNodeIDOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix process test")
	}
	t.Setenv(NodeIDEnvironment, "999")
	dir := t.TempDir()
	for name, runner := range map[string]CommandRunner{"node-77": {NodeID: 77}, "none": {}} {
		t.Run(name, func(t *testing.T) {
			output := filepath.Join(dir, name+".env")
			binary := filepath.Join(dir, name+".plugin")
			script := "#!/bin/sh\nprintf '%s' \"${" + NodeIDEnvironment + "-unset}\" > " + output + "\n"
			require.NoError(t, os.WriteFile(binary, []byte(script), 0o750))
			process, err := runner.Start(context.Background(), binary, filepath.Join(dir, name+".sock"), filepath.Join(dir, "config.json"))
			require.NoError(t, err)
			select {
			case <-process.(ProcessExitWatcher).Exited():
			case <-time.After(5 * time.Second):
				t.Fatal("the plugin did not exit")
			}
			value, err := os.ReadFile(output)
			require.NoError(t, err)
			if runner.NodeID > 0 {
				assert.Equal(t, "77", string(value))
			} else {
				assert.Equal(t, "unset", string(value), "an inherited node id is never passed on")
			}
		})
	}
}

// The machine-telemetry binary, under the production runtime, reports its
// systemd services table as a PackageReport that names the release the node
// is assigned (the operation's target_version), not the plugin's own
// version constant.
func TestPackageReportsFromTheMachineTelemetryBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket plugin runtime")
	}
	if testing.Short() {
		t.Skip("builds the reference plugin binary")
	}
	const assigned = "4.1.0"
	require.NotEqual(t, assigned, machinetelemetry.Version)

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

	install := func(t *testing.T, supervisor *Supervisor, privateKey ed25519.PrivateKey, capabilities []string) {
		t.Helper()
		webUI := []byte(`export default { name: "MachineTelemetry" }`)
		entrypoint := filepath.ToSlash(filepath.Join("agent", runtime.GOOS+"-"+runtime.GOARCH, "plugin"))
		artifact := buildMachineTelemetryPackage(t, entrypoint, binary, webUI)
		artifactDigest := sha256.Sum256(artifact)
		webUIDigest := sha256.Sum256(webUI)
		manifest := Manifest{
			ID: IDForMachineTelemetryTest, Name: "Machine Telemetry", Version: assigned,
			APIVersion: pluginAPIVersion, Publisher: manifestPublisher,
			Targets: []string{"control", "agent"}, Architectures: []string{runtime.GOOS + "/" + runtime.GOARCH},
			ArtifactSHA256: hex.EncodeToString(artifactDigest[:]), Capabilities: capabilities,
			Permissions: []string{"machine-telemetry.view"}, ConfigSchema: []byte(`{"type":"object"}`),
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
		_, err = supervisor.Install(context.Background(), InstallRequest{
			ManifestJSON: string(canonical), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)), Artifact: artifact,
		})
		require.NoError(t, err)
		config := []byte(`{"interval_seconds":5,"systemd_services":{"nodes":{"77":{"enabled":true}}}}`)
		_, err = supervisor.Handle(context.Background(), "plugin.configure", testEnvelope("configure", IDForMachineTelemetryTest, assigned, 1, config))
		require.NoError(t, err)
		startupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, err = supervisor.Handle(startupCtx, "plugin.enable", testEnvelope("enable", IDForMachineTelemetryTest, assigned, 2, nil))
		require.NoError(t, err)
	}
	newSupervisor := func(t *testing.T, nodeID int) (*Supervisor, ed25519.PrivateKey) {
		t.Helper()
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		// Short: a Unix socket path is at most 108 bytes.
		short, err := os.MkdirTemp("", "pr")
		require.NoError(t, err)
		t.Cleanup(func() { _ = os.RemoveAll(short) })
		root := filepath.Join(short, "state")
		supervisor, err := NewSupervisor(Config{
			DisableMaintenanceMonitor: true, RootDir: root, SocketDir: filepath.Join(root, "sockets"), PublicKey: publicKey,
			NodeID: nodeID, Health: GRPCHealthChecker{Service: IDForMachineTelemetryTest, Timeout: 10 * time.Second},
		})
		require.NoError(t, err)
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = supervisor.Close(ctx)
		})
		return supervisor, privateKey
	}

	t.Run("assigned release", func(t *testing.T) {
		supervisor, privateKey := newSupervisor(t, 77)
		install(t, supervisor, privateKey, []string{"telemetry.read", systemdreport.Capability})
		require.Eventually(t, func() bool {
			collected, err := supervisor.PackageReports(context.Background())
			return err == nil && len(collected) == 1
		}, 15*time.Second, 100*time.Millisecond)
		collected, err := supervisor.PackageReports(context.Background())
		require.NoError(t, err)
		report := collected[0]
		assert.Equal(t, IDForMachineTelemetryTest, report.PluginId)
		assert.Equal(t, systemdreport.Kind, report.Kind)
		assert.Equal(t, assigned, report.Version, "the assigned release, not the plugin's constant %s", machinetelemetry.Version)
		assert.Positive(t, report.ObservedAtUnixMs)
		sanitized, err := systemdreport.Sanitize(report.PayloadJson)
		require.NoError(t, err)
		var payload map[string]any
		require.NoError(t, json.Unmarshal(report.PayloadJson, &payload))
		assert.Contains(t, payload, "supported")
		assert.Equal(t, systemdreport.WindowSeconds, sanitized.WindowSeconds)
		assert.False(t, strings.Contains(string(report.PayloadJson), "Description"))
	})

	t.Run("no node id", func(t *testing.T) {
		supervisor, privateKey := newSupervisor(t, 0)
		install(t, supervisor, privateKey, []string{"telemetry.read", systemdreport.Capability})
		time.Sleep(time.Second)
		collected, err := supervisor.PackageReports(context.Background())
		require.NoError(t, err)
		assert.Empty(t, collected, "without ANIXOPS_NODE_ID the collector stays off")
	})

	t.Run("release without the capability", func(t *testing.T) {
		supervisor, privateKey := newSupervisor(t, 77)
		install(t, supervisor, privateKey, []string{"telemetry.read"})
		time.Sleep(time.Second)
		collected, err := supervisor.PackageReports(context.Background())
		require.NoError(t, err)
		assert.Empty(t, collected, "Control would refuse it (missing_capability)")
	})
}
