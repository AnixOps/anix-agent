//go:build linux

package machinetelemetry

import (
	"context"
	"os"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnitObjectPathEscapesLikeSystemd(t *testing.T) {
	assert.Equal(t, dbus.ObjectPath("/org/freedesktop/systemd1/unit/nginx_2eservice"), unitObjectPath("nginx.service"))
	assert.Equal(t, dbus.ObjectPath("/org/freedesktop/systemd1/unit/postgresql_4017_2dmain_2eservice"), unitObjectPath("postgresql@17-main.service"))
	assert.Equal(t, dbus.ObjectPath("/org/freedesktop/systemd1/unit/a_5cx2d_3ab_5f_2eservice"), unitObjectPath(`a\x2d:b_.service`))
}

// TestSystemdListerOutlivesItsConnectContext runs on hosts with systemd and
// a reachable system bus (GitHub's Ubuntu runners): the kept connection must
// survive the end of the context it was opened with.
func TestSystemdListerOutlivesItsConnectContext(t *testing.T) {
	if info, err := os.Stat(DefaultSystemdRuntimeDir); err != nil || !info.IsDir() {
		t.Skip("systemd is not running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	lister, err := connectSystemd(ctx)
	cancel()
	if err != nil {
		t.Skipf("no systemd D-Bus API: %v", err)
	}
	defer lister.Close()
	units, err := lister.ListServices(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, units)
	for _, unit := range units {
		require.Contains(t, unit.Name, ".service")
	}
	report := mustCollect(t, NewServicesCollector(DefaultServicesPlatform(), ServicesNodeConfig{Enabled: true}, nil))
	parsed := decodeReport(t, report)
	if parsed.Supported {
		assert.NotEmpty(t, parsed.Units)
	}
}
