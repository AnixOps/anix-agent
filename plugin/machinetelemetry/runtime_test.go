package machinetelemetry

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func TestLoadConfigEnforcesSignedSchema(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name      string
		contents  string
		want      int
		wantError string
	}{
		{name: "default", contents: `{}`, want: DefaultIntervalSeconds},
		{name: "configured", contents: `{"interval_seconds":5}`, want: 5},
		{name: "maximum", contents: `{"interval_seconds":3600}`, want: MaximumIntervalSeconds},
		{name: "below minimum", contents: `{"interval_seconds":4}`, wantError: "at least 5"},
		{name: "above maximum", contents: `{"interval_seconds":3601}`, wantError: "at most 3600"},
		{name: "null", contents: `{"interval_seconds":null}`, wantError: "must be an integer"},
		{name: "fraction", contents: `{"interval_seconds":5.5}`, wantError: "must be an integer"},
		{name: "unknown field", contents: `{"interval_seconds":5,"command":"id"}`, wantError: "unknown field"},
		{name: "trailing document", contents: `{} {}`, wantError: "exactly one"},
		{name: "not object", contents: `null`, wantError: "JSON object"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(dir, test.name+".json")
			require.NoError(t, os.WriteFile(path, []byte(test.contents), 0o600))
			config, err := LoadConfig(path)
			if test.wantError != "" {
				require.ErrorContains(t, err, test.wantError)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.want, config.IntervalSeconds)
		})
	}
}

func TestLoadConfigRejectsUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{"interval_seconds":5}`), 0o600))
	require.NoError(t, os.Chmod(configPath, 0o622))
	_, err := LoadConfig(configPath)
	require.ErrorContains(t, err, "writable by group or other")

	if runtime.GOOS == "windows" {
		return
	}
	privatePath := filepath.Join(dir, "private.json")
	symlinkPath := filepath.Join(dir, "config-link.json")
	require.NoError(t, os.WriteFile(privatePath, []byte(`{}`), 0o600))
	require.NoError(t, os.Symlink(privatePath, symlinkPath))
	_, err = LoadConfig(symlinkPath)
	require.ErrorContains(t, err, "not a symlink")
}

func TestRunServesHealthAndCleansSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket plugin runtime")
	}
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	configPath := filepath.Join(dir, "config.json")
	socketPath := filepath.Join(dir, "plugin.sock")
	require.NoError(t, os.WriteFile(configPath, []byte(`{"interval_seconds":5}`), 0o600))

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- Run(ctx, Options{SocketPath: socketPath, ConfigPath: configPath})
	}()

	dialCtx, cancelDial := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelDial()
	connection, err := grpc.DialContext(dialCtx, "unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	require.NoError(t, err)
	response, err := healthpb.NewHealthClient(connection).Check(dialCtx, &healthpb.HealthCheckRequest{Service: ID})
	require.NoError(t, err)
	require.Equal(t, healthpb.HealthCheckResponse_SERVING, response.Status)
	require.NoError(t, connection.Close())

	cancel()
	select {
	case err := <-result:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("plugin did not stop after cancellation")
	}
	_, err = os.Lstat(socketPath)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestRunServesTelemetrySnapshot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket plugin runtime")
	}
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	configPath := filepath.Join(dir, "config.json")
	socketPath := filepath.Join(dir, "plugin.sock")
	require.NoError(t, os.WriteFile(configPath, []byte(`{"interval_seconds":5}`), 0o600))

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- Run(ctx, Options{SocketPath: socketPath, ConfigPath: configPath}) }()

	dialCtx, cancelDial := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelDial()
	connection, err := grpc.DialContext(dialCtx, "unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	require.NoError(t, err)
	client := NewTelemetryClient(connection)
	snapshot, err := client.Snapshot(dialCtx)
	require.NoError(t, err)
	require.NoError(t, snapshot.Validate())
	require.Greater(t, snapshot.ObservedAtUnixMs, int64(0))
	require.Contains(t, snapshot.Metrics, "cpu_usage_percent")
	require.Contains(t, snapshot.Metrics, "memory_usage_percent")
	require.Contains(t, snapshot.Metrics, "disk_usage_percent")
	require.Contains(t, snapshot.Metrics, "uptime_seconds")
	require.NoError(t, connection.Close())

	cancel()
	select {
	case err := <-result:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("plugin did not stop after cancellation")
	}
}

func TestSnapshotRejectsUntrustedValues(t *testing.T) {
	base := Snapshot{Metrics: map[string]float64{"cpu_usage_percent": 1}, ObservedAtUnixMs: 1}
	require.NoError(t, base.Validate())
	base.Metrics["Bad Key"] = 1
	require.ErrorContains(t, base.Validate(), "invalid")
	base.Metrics = map[string]float64{"cpu_usage_percent": 1}
	base.Metrics["memory_usage_percent"] = math.Inf(1)
	require.ErrorContains(t, base.Validate(), "not finite")
}

func startPluginForTest(t *testing.T, config string, options Options) (*telemetryClient, func()) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	options.ConfigPath = filepath.Join(dir, "config.json")
	options.SocketPath = filepath.Join(dir, "plugin.sock")
	require.NoError(t, os.WriteFile(options.ConfigPath, []byte(config), 0o600))
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- Run(ctx, options) }()
	dialCtx, cancelDial := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelDial()
	connection, err := grpc.DialContext(dialCtx, "unix://"+options.SocketPath, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	require.NoError(t, err)
	return NewTelemetryClient(connection), func() {
		require.NoError(t, connection.Close())
		cancel()
		select {
		case err := <-result:
			require.NoError(t, err)
		case <-time.After(3 * time.Second):
			t.Fatal("plugin did not stop after cancellation")
		}
	}
}

func TestRunServesSystemdServicesReportForItsNode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket plugin runtime")
	}
	fs := newFakeCgroupfs(t)
	fs.set("/system.slice/nginx.service", 1_000_000, 4096, -1)
	lister := &fakeLister{
		units: []ServiceUnit{
			{Name: "nginx.service", LoadState: "loaded", ActiveState: "active", SubState: "running"},
			{Name: "nginx-debug.service", LoadState: "loaded", ActiveState: "active", SubState: "running"},
			{Name: "cron.service", LoadState: "loaded", ActiveState: "active", SubState: "running"},
		},
		cgroups: map[string]string{"nginx.service": "/system.slice/nginx.service"},
	}
	platform := fs.platform(lister)

	client, stop := startPluginForTest(t, exactControlConfig, Options{NodeID: 12, ServicesPlatform: &platform})
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var report ServicesReport
	require.Eventually(t, func() bool {
		var ok bool
		var err error
		report, ok, err = client.SystemdServices(ctx)
		require.NoError(t, err)
		return ok
	}, 3*time.Second, 20*time.Millisecond)
	assert.Equal(t, "systemd.services", report.Kind)
	assert.Greater(t, report.ObservedAtUnixMs, int64(0))
	parsed := decodeReport(t, report)
	require.True(t, parsed.Supported)
	require.Len(t, parsed.Units, 1, "include and exclude of node 12 apply")
	assert.Equal(t, "nginx.service", parsed.Units[0].Name)
	assert.Equal(t, uint64(4096), parsed.Units[0].MemoryBytes)

	// The telemetry snapshot is unaffected.
	snapshot, err := client.Snapshot(ctx)
	require.NoError(t, err)
	require.NoError(t, snapshot.Validate())
}

func TestRunKeepsSystemdServicesOffUnlessEnabledForItsNode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket plugin runtime")
	}
	connects := 0
	platform := ServicesPlatform{Connect: func(context.Context) (ServiceLister, error) {
		connects++
		return &fakeLister{}, nil
	}}
	for name, test := range map[string]struct {
		config string
		nodeID uint64
	}{
		"no node id":       {config: exactControlConfig},
		"another node":     {config: exactControlConfig, nodeID: 13},
		"disabled":         {config: `{"systemd_services":{"nodes":{"12":{"enabled":false}}}}`, nodeID: 12},
		"no services key":  {config: `{"interval_seconds":30}`, nodeID: 12},
		"services is null": {config: `{"systemd_services":null}`, nodeID: 12},
	} {
		t.Run(name, func(t *testing.T) {
			client, stop := startPluginForTest(t, test.config, Options{NodeID: test.nodeID, ServicesPlatform: &platform})
			defer stop()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, ok, err := client.SystemdServices(ctx)
			require.NoError(t, err)
			assert.False(t, ok)
		})
	}
	assert.Zero(t, connects, "nothing is collected on a node that is not enabled")
}

func TestRunRefusesMalformedSystemdServicesConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{"systemd_services":{"nodes":{"12":{"enabled":true,"include":["a["]}}}}`), 0o600))
	err := Run(context.Background(), Options{SocketPath: filepath.Join(dir, "plugin.sock"), ConfigPath: configPath, NodeID: 12})
	require.ErrorIs(t, err, ErrInvalidServicesConfig)
}
