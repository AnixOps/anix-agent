package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// stubRouteCheck runs route checks inline and answers them from failing
// (relay lists, joined with ","); it counts the checks.
func stubRouteCheck(t *testing.T, failing map[string]bool) *int {
	t.Helper()
	previousCheck, previousAsync := routeCheck, routeAsync
	checks := 0
	routeCheck = func(_ context.Context, relays []string, serverName string) error {
		checks++
		if serverName != "ctl.example.com" {
			return fmt.Errorf("server name %q", serverName)
		}
		if failing[strings.Join(relays, ",")] {
			return errors.New("handshake failed")
		}
		return nil
	}
	routeAsync = func(check func()) { check() }
	t.Cleanup(func() { routeCheck, routeAsync = previousCheck, previousAsync })
	return &checks
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
	checks := stubRouteCheck(t, map[string]bool{"relay-dead.example.cn:50051": true})
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

	// Relays that do not carry Control from here are not taken: the route,
	// the stored file and the session stay, and the same list is not
	// checked again before routeRetry.
	checksBefore := *checks
	require.NoError(t, route.apply(routeSnapshot(`{"control_route":{"relays":["relay-dead.example.cn:50051"]}}`)))
	require.Equal(t, checksBefore+1, *checks)
	require.Equal(t, []string{"relay-b.example.cn:50051"}, currentRelays(route))
	require.Equal(t, 1, reconnects)
	stored, err = loadControlRoute(route.file)
	require.NoError(t, err)
	require.Equal(t, []string{"relay-b.example.cn:50051"}, stored.Relays)
	require.NoError(t, route.apply(routeSnapshot(`{"control_route":{"relays":["relay-dead.example.cn:50051"]}}`)))
	require.Equal(t, checksBefore+1, *checks)

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
}

func TestControlRouteConfigurationChangeWins(t *testing.T) {
	noUpgrader(t)
	// The route was stored against a configuration with relay-a; the
	// installer since wrote relay-z (or someone edited it).
	api := &conf.ApiConfig{GRPCRelays: []string{"relay-z.example.cn:50051"}}
	api.AgentStream.StateDir = t.TempDir()
	file := controlRouteFile(api, "proxy-9104")
	require.NoError(t, saveControlRoute(file, storedControlRoute{
		Relays: []string{"relay-b.example.cn:50051"}, ConfigRelays: []string{"relay-a.example.cn:50051"},
	}))
	route, err := newControlRoute("proxy-9104", api, "ctl.example.com:50051", "ctl.example.com")
	require.NoError(t, err)
	require.Equal(t, []string{"relay-z.example.cn:50051"}, currentRelays(route))
	require.NoFileExists(t, file)
}

func TestControlRouteCorruptStoredRoute(t *testing.T) {
	noUpgrader(t)
	// With relays in the configuration, those are used.
	api := &conf.ApiConfig{GRPCRelays: []string{"relay-z.example.cn:50051"}}
	api.AgentStream.StateDir = t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(api.AgentStream.StateDir, "control-route-proxy-9103.json"), []byte("{"), 0o600))
	route, err := newControlRoute("proxy-9103", api, "ctl.example.com:50051", "ctl.example.com")
	require.NoError(t, err)
	require.Equal(t, []string{"relay-z.example.cn:50051"}, currentRelays(route))

	// Without, the node identity does not start rather than go direct:
	// a file that does not parse, an empty route ({} or null) and relays
	// this Agent cannot use are all damage.
	for i, body := range []string{"{", "{}", "null", `{"relays":[" "]}`, `{"relays":["no port"]}`} {
		direct := &conf.ApiConfig{}
		direct.AgentStream.StateDir = t.TempDir()
		owner := fmt.Sprintf("proxy-%d", 9110+i)
		require.NoError(t, os.WriteFile(controlRouteFile(direct, owner), []byte(body), 0o600))
		_, err = newControlRoute(owner, direct, "ctl.example.com:50051", "ctl.example.com")
		require.ErrorContains(t, err, "does not reach Control directly", body)
		require.NotContains(t, err.Error(), "remove the file")
	}

	// Control's explicit direct route is kept across a restart.
	explicit := &conf.ApiConfig{}
	explicit.AgentStream.StateDir = t.TempDir()
	require.NoError(t, saveControlRoute(controlRouteFile(explicit, "proxy-9120"), storedControlRoute{Direct: true}))
	route, err = newControlRoute("proxy-9120", explicit, "ctl.example.com:50051", "ctl.example.com")
	require.NoError(t, err)
	require.Nil(t, route.dial.Current())
}

func TestCheckRouteRelaysNeedsControlsCertificate(t *testing.T) {
	// Nothing listens: the check fails rather than taking the relay.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.Error(t, checkRouteRelays(ctx, []string{address}, "ctl.example.com"))
}
