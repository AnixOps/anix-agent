package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The commands the O1 installer (anix-control internal/agentinstall) runs.

func TestServerAcceptsTheUnitCommand(t *testing.T) {
	// ExecStart=/usr/lib/anixops-agent/anix-agent server -c /etc/anixops/agent/config.json
	previous := config
	t.Cleanup(func() { config = previous })
	found, args, err := command.Find([]string{"server", "-c", "/etc/anixops/agent/config.json"})
	require.NoError(t, err)
	require.Equal(t, "server", found.Name())
	require.NoError(t, found.ParseFlags(args))
	value, err := found.Flags().GetString("config")
	require.NoError(t, err)
	require.Equal(t, "/etc/anixops/agent/config.json", value)
}

func TestForwardSysctlDropIn(t *testing.T) {
	for _, name := range []string{"sysctl-dropin", "sysctl"} {
		found, _, err := command.Find([]string{"forward", name})
		require.NoError(t, err)
		var out bytes.Buffer
		found.SetOut(&out)
		require.NoError(t, found.RunE(found, nil))
		require.Equal(t, ForwardSysctlDropIn, out.String())
		require.Contains(t, out.String(), "net.ipv4.ip_forward = 1")
		require.Contains(t, out.String(), "net.ipv6.conf.all.forwarding = 1")
	}
}

func TestForwardRelayUnit(t *testing.T) {
	found, _, err := command.Find([]string{"forward", "relay-unit"})
	require.NoError(t, err)
	var out bytes.Buffer
	found.SetOut(&out)
	require.NoError(t, found.RunE(found, nil))
	unit := out.String()
	require.Contains(t, unit, "Description=AnixOps forward relay (anixops-forward-driver anixops v1)")
	require.Contains(t, unit, "ExecStart=/usr/lib/anixops-agent/anixops-relay -config /var/lib/anixops-relay/relay.json -socket /run/anixops-relay/control.sock")
	require.Contains(t, unit, "User=anixops-relay")
	require.Contains(t, unit, "AmbientCapabilities=CAP_NET_BIND_SERVICE")
	require.NotContains(t, unit, "CAP_NET_ADMIN")
}

func TestForwardSysctlDropInRaisesTheQUICSocketBuffers(t *testing.T) {
	require.Contains(t, ForwardSysctlDropIn, "net.core.rmem_max = 7500000")
	require.Contains(t, ForwardSysctlDropIn, "net.core.wmem_max = 7500000")
}

func TestMigratePathsCopiesTheEarlierDefaults(t *testing.T) {
	root := t.TempDir()
	identity := filepath.Join(root, "var/lib/anix-agent/pki/proxy-12/identity.pem")
	require.NoError(t, os.MkdirAll(filepath.Dir(identity), 0o700))
	require.NoError(t, os.WriteFile(identity, []byte("identity"), 0o600))
	// The new stream directory exists already: kept.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "var/lib/anix-agent/stream/proxy-12"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "var/lib/anixops-agent/stream"), 0o700))

	found, _, err := command.Find([]string{"migrate-paths"})
	require.NoError(t, err)
	migrateRoot = root
	t.Cleanup(func() { migrateRoot = "" })
	var out bytes.Buffer
	found.SetOut(&out)
	require.NoError(t, found.RunE(found, nil))

	data, err := os.ReadFile(filepath.Join(root, "var/lib/anixops-agent/pki/proxy-12/identity.pem"))
	require.NoError(t, err)
	require.Equal(t, "identity", string(data))
	_, err = os.Stat(identity)
	require.NoError(t, err, "the old directory is left in place")
	_, err = os.Stat(filepath.Join(root, "var/lib/anixops-agent/stream/proxy-12"))
	require.True(t, os.IsNotExist(err), "an existing new directory is not touched")
	require.Contains(t, out.String(), "copied  agent identity")
	require.Contains(t, out.String(), "kept    stream state")
}
