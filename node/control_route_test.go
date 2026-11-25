package node

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AnixOps/anix-agent/v5/conf"
	"github.com/AnixOps/anix-agent/v5/upgrade"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/require"
)

func noUpgrader(t *testing.T) {
	t.Helper()
	previous := agentUpgrader
	agentUpgrader = func() *upgrade.Agent { return nil }
	t.Cleanup(func() { agentUpgrader = previous })
}

func routeSnapshot(document string) *agentv1pb.ConfigSnapshot {
	return &agentv1pb.ConfigSnapshot{ConfigJson: []byte(document)}
}

func currentRelays(route *controlRoute) []string {
	if relays := route.dial.Current(); relays != nil {
		return relays.Addresses()
	}
	return nil
}

func TestControlRouteFollowsControl(t *testing.T) {
	noUpgrader(t)
	api := &conf.ApiConfig{GRPCRelays: []string{"relay-a.example.cn:50051"}}
	api.AgentStream.StateDir = t.TempDir()
	route, err := newControlRoute("proxy-9101", api, "ctl.example.com:50051", "ctl.example.com")
	require.NoError(t, err)
	reconnects := 0
	route.reconnect = func() { reconnects++ }
	require.Equal(t, []string{"relay-a.example.cn:50051"}, currentRelays(route))

	// No member: the route stays, nothing is stored.
	require.NoError(t, route.apply(routeSnapshot(`{"nodes":[]}`)))
	require.Equal(t, []string{"relay-a.example.cn:50051"}, currentRelays(route))
	require.NoFileExists(t, route.file)
	require.Zero(t, reconnects)

	// New relays: the next connection takes them, the session ends once,
	// and the route is stored.
	require.NoError(t, route.apply(routeSnapshot(`{"control_route":{"relays":["relay-b.example.cn:50051"],"release_caches":["https://relay-b.example.cn:8443"]}}`)))
	require.Equal(t, []string{"relay-b.example.cn:50051"}, currentRelays(route))
	require.Equal(t, 1, reconnects)
	stored, err := loadControlRoute(route.file)
	require.NoError(t, err)
	require.Equal(t, []string{"relay-b.example.cn:50051"}, stored.Relays)
	require.Equal(t, []string{"https://relay-b.example.cn:8443"}, stored.ReleaseCaches)

	// The same route again changes nothing.
	require.NoError(t, route.apply(routeSnapshot(`{"control_route":{"relays":["relay-b.example.cn:50051"],"release_caches":["https://relay-b.example.cn:8443"]}}`)))
	require.Equal(t, 1, reconnects)

	// Empty relays never mean direct: the relays stay, the caches follow,
	// no reconnect.
	require.NoError(t, route.apply(routeSnapshot(`{"control_route":{"relays":[" "],"release_caches":["https://relay-c.example.cn:8443"]}}`)))
	require.Equal(t, []string{"relay-b.example.cn:50051"}, currentRelays(route))
	require.Equal(t, []string{"https://relay-c.example.cn:8443"}, route.caches)
	require.Equal(t, 1, reconnects)

	// A relay list this Agent cannot use is refused; the relays stay.
	require.Error(t, route.apply(routeSnapshot(`{"control_route":{"relays":["no port"]}}`)))
	require.Equal(t, []string{"relay-b.example.cn:50051"}, currentRelays(route))
	require.Equal(t, 1, reconnects)

	// Only an explicit direct route drops the relays.
	require.NoError(t, route.apply(routeSnapshot(`{"control_route":{"direct":true}}`)))
	require.Nil(t, route.dial.Current())
	require.Equal(t, 2, reconnects)
}

func TestControlRouteRestartKeepsPushedRoute(t *testing.T) {
	noUpgrader(t)
	api := &conf.ApiConfig{}
	api.AgentStream.StateDir = t.TempDir()
	// Installed directly; Control pushed relays before the restart.
	require.NoError(t, saveControlRoute(controlRouteFile(api, "forward-9102"), storedControlRoute{Relays: []string{"relay-a.example.cn:50051"}}))
	route, err := newControlRoute("forward-9102", api, "ctl.example.com:50051", "ctl.example.com")
	require.NoError(t, err)
	require.Equal(t, []string{"relay-a.example.cn:50051"}, currentRelays(route))

	// A stored route that does not parse falls back to the configuration.
	other := &conf.ApiConfig{GRPCRelays: []string{"relay-z.example.cn:50051"}}
	other.AgentStream.StateDir = t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(other.AgentStream.StateDir, "control-route-proxy-9103.json"), []byte("{"), 0o600))
	route, err = newControlRoute("proxy-9103", other, "ctl.example.com:50051", "ctl.example.com")
	require.NoError(t, err)
	require.Equal(t, []string{"relay-z.example.cn:50051"}, currentRelays(route))
}
