package node

import (
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v4/common/maintenance"
	"github.com/stretchr/testify/require"
)

// Invoked by Control's TestMaintenanceCrossRepositoryAgentToTicket with an
// ephemeral authenticated server. No production addresses/credentials are used.
func TestMaintenanceExternalControl(t *testing.T) {
	endpoint := os.Getenv("ANIXOPS_MAINTENANCE_E2E_URL")
	if endpoint == "" {
		t.Skip("requires Control integration harness")
	}
	target, err := url.Parse(endpoint)
	require.NoError(t, err)
	require.Equal(t, "http", target.Scheme)
	ip := net.ParseIP(target.Hostname())
	require.NotNil(t, ip)
	require.True(t, ip.IsLoopback(), "fixture permits only loopback Control")
	path := filepath.Join(t.TempDir(), "outbox.json")
	store := nodeMaintenanceStore(t, path)
	observation := maintenance.Observation{PluginID: "machine-telemetry", InstanceID: "machine-telemetry", PluginVersion: "1.1.0", ConfigVersion: "1", ErrorCode: "PLUGIN_PROCESS_EXITED"}
	start := time.Now().UTC().Add(-3 * time.Minute)
	for i := 0; i < 3; i++ {
		_, err := store.Observe(observation, start.Add(time.Duration(i)*time.Minute))
		require.NoError(t, err)
	}
	queued, err := store.Pending(50)
	require.NoError(t, err)
	require.NotEmpty(t, queued)
	// Reopen the Agent's durable state before transmitting to the real Control.
	store = nodeMaintenanceStore(t, path)
	config := DefaultSyncConfig()
	config.MaintenanceOnly = true
	config.EnableFallback = false
	config.PingInterval = 20 * time.Millisecond
	config.ReconnectInterval = 20 * time.Millisecond
	sm := NewSyncManager(&maintenanceNodeAPI{url: endpoint}, nil, config)
	sm.SetMaintenanceStore(store)
	require.NoError(t, sm.Start())
	defer sm.Close()
	require.Eventually(t, func() bool { events, err := store.Pending(50); return err == nil && len(events) == 0 }, 10*time.Second, 20*time.Millisecond)
}
