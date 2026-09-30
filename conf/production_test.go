package conf

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func readyProductionAgentConfig() *Conf {
	return &Conf{
		Environment: "production",
		CoresConfig: []CoreConfig{{Type: "sing"}},
		NodeConfig: []NodeConfig{{
			ApiConfig: ApiConfig{
				APIHost: "https://control.company.net", Transport: "grpc",
				GRPCHost: "control.company.net:443", GRPCUseTLS: true, GRPCServerName: "control.company.net",
				AgentControlEnabled: true, MaintenanceEnvironment: "production", PluginSupervisorEnabled: true,
				PluginRoot: "/var/lib/anixops/plugins", PluginSocketDir: "/run/anixops/plugins",
				PluginOfficialPublicKey: "IaqXgif/OGydNv/mQHoyFmqOvzeplICaMZndrhqMG0M=",
				NodeID:                  7, Key: strings.Repeat("k", 32), Timeout: 30, EnableSign: true, GRPCKeepalive: 30,
			},
			Options: Options{Core: "sing", SyncConfig: &SyncConfig{
				EnableWebSocket: true, WSEndpoint: "/api/v2/agent/ws", ReconnectInterval: 5,
				PingInterval: 30, PongTimeout: 10, AckTimeout: 5, AckRetries: 2, BufferSize: 100,
			}},
		}},
	}
}

func TestValidateForProductionAcceptsCompleteAgentConfig(t *testing.T) {
	require.NoError(t, readyProductionAgentConfig().ValidateForProduction())
}

func TestValidateForProductionRejectsDisabledOrPlaceholderRuntime(t *testing.T) {
	cfg := readyProductionAgentConfig()
	cfg.NodeConfig[0].ApiConfig.APIHost = "https://control.example.com"
	cfg.NodeConfig[0].ApiConfig.PluginSupervisorEnabled = false
	cfg.NodeConfig[0].Options.SyncConfig.EnableWebSocket = false

	err := cfg.ValidateForProduction()
	require.Error(t, err)
	for _, expected := range []string{"ApiHost", "PluginSupervisorEnabled", "EnableWebSocket"} {
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
	cfg.NodeConfig[0].Options.Core = "xray"
	require.ErrorContains(t, cfg.ValidateForProduction(), "not configured")

	cfg = readyProductionAgentConfig()
	cfg.NodeConfig[0].ApiConfig.GRPCHost = "control.company.net"
	require.ErrorContains(t, cfg.ValidateForProduction(), "host:port")
}

func TestProductionTemplateRequiresOperatorValues(t *testing.T) {
	cfg := New()
	require.Error(t, cfg.LoadFromPath("../example/config.production.json"))
}
