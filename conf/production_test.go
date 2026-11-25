package conf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func readyProductionAgentConfig() *Conf {
	return &Conf{
		Environment: "production",
		CoresConfig: []CoreConfig{{Type: "anixcore"}},
		NodeConfig: []NodeConfig{{
			ApiConfig: ApiConfig{
				APIHost:  "https://control.company.net",
				GRPCHost: "control.company.net:443", GRPCUseTLS: true, GRPCServerName: "control.company.net",
				MaintenanceEnvironment: "production", PluginSupervisorEnabled: true,
				PluginRoot: "/var/lib/anixops-agent/plugins", PluginSocketDir: "/run/anixops-agent/plugins",
				PluginOfficialPublicKey: "IaqXgif/OGydNv/mQHoyFmqOvzeplICaMZndrhqMG0M=",
				NodeID:                  7, GRPCKeepalive: 30,
			},
			Options: Options{Core: "anixcore"},
		}},
	}
}

func TestValidateForProductionAcceptsCompleteAgentConfig(t *testing.T) {
	require.NoError(t, readyProductionAgentConfig().ValidateForProduction())
}

func TestValidateForProductionRejectsDisabledOrPlaceholderRuntime(t *testing.T) {
	cfg := readyProductionAgentConfig()
	cfg.NodeConfig[0].ApiConfig.APIHost = "https://control.example.com"
	cfg.NodeConfig[0].ApiConfig.PluginOfficialPublicKey = ""
	cfg.NodeConfig[0].ApiConfig.GRPCUseTLS = false

	err := cfg.ValidateForProduction()
	require.Error(t, err)
	for _, expected := range []string{"ApiHost", "PluginOfficialPublicKey", "GRPCUseTLS"} {
		require.ErrorContains(t, err, expected)
	}
}

func TestProductionRootRequiresPerNodeEnvironment(t *testing.T) {
	cfg := readyProductionAgentConfig()
	cfg.NodeConfig[0].ApiConfig.MaintenanceEnvironment = ""
	require.ErrorContains(t, cfg.ValidateForProduction(), "MaintenanceEnvironment=production")
}

func TestProductionValidationRejectsUnknownEnvironmentAliases(t *testing.T) {
	cfg := readyProductionAgentConfig()
	cfg.Environment = "prod"
	require.ErrorContains(t, cfg.ValidateForProduction(), "unsupported Environment")

	cfg = readyProductionAgentConfig()
	cfg.NodeConfig[0].ApiConfig.MaintenanceEnvironment = "prod"
	require.ErrorContains(t, cfg.ValidateForProduction(), "unsupported MaintenanceEnvironment")
}

func TestProductionValidationRejectsMissingCoreAndInvalidGRPCTarget(t *testing.T) {
	cfg := readyProductionAgentConfig()
	cfg.NodeConfig[0].Options.Core = "wireguard"
	require.ErrorContains(t, cfg.ValidateForProduction(), "not configured")

	cfg = readyProductionAgentConfig()
	cfg.NodeConfig[0].ApiConfig.GRPCHost = "control.company.net"
	require.ErrorContains(t, cfg.ValidateForProduction(), "host:port")
}

func TestProductionTemplateRequiresOperatorValues(t *testing.T) {
	cfg := New()
	require.Error(t, cfg.LoadFromPath("../example/config.production.json"))
}

// Region relays (GRPCRelays) and their release caches (ReleaseCaches).
func TestProductionValidationChecksRelays(t *testing.T) {
	cfg := readyProductionAgentConfig()
	cfg.NodeConfig[0].ApiConfig.GRPCRelays = []string{"relay-1.company.net:50051", "203.0.113.10:50051"}
	cfg.NodeConfig[0].ApiConfig.ReleaseCaches = []string{"https://relay-1.company.net:8443"}
	require.NoError(t, cfg.ValidateForProduction())

	cfg.NodeConfig[0].ApiConfig.GRPCRelays = []string{"relay-1.company.net"}
	require.ErrorContains(t, cfg.ValidateForProduction(), "GRPCRelays")

	cfg = readyProductionAgentConfig()
	cfg.NodeConfig[0].ApiConfig.ReleaseCaches = []string{"http://relay-1.company.net:8443"}
	require.ErrorContains(t, cfg.ValidateForProduction(), "ReleaseCaches")
}

func TestNodeConfigDecodesRelays(t *testing.T) {
	var node NodeConfig
	require.NoError(t, node.UnmarshalJSON([]byte(`{"GRPCRelays":["relay-1.company.net:50051"],"ReleaseCaches":["https://relay-1.company.net:8443"]}`)))
	require.Equal(t, []string{"relay-1.company.net:50051"}, node.ApiConfig.GRPCRelays)
	require.Equal(t, []string{"https://relay-1.company.net:8443"}, node.ApiConfig.ReleaseCaches)
}
