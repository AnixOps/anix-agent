package agent

import (
	"testing"

	"github.com/AnixOps/anix-agent/v5/api/agent/agenttest"
)

// testIdentity is an identity root with no identity, for a client that
// never connects.
func testIdentity(t testing.TB) *IdentityConfig {
	return &IdentityConfig{Dir: t.TempDir()}
}

// provisionedIdentity is node nodeID's identity, enrolled before the test
// by a Control that is not listening.
func provisionedIdentity(t testing.TB, nodeID uint32) *IdentityConfig {
	return &IdentityConfig{Dir: agenttest.NewListener(t, nodeID).Provision(t)}
}

// listenerConfig points config at listener with the node's identity.
func listenerConfig(t testing.TB, listener *agenttest.Listener, config Config) Config {
	config.Target, config.UseTLS, config.ServerName, config.RootCAs = listener.Address, true, listener.ServerName, listener.ServerCAs
	config.Identity = &IdentityConfig{Dir: listener.Provision(t)}
	return config
}
