package conf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// installerConfig is /etc/anixops/agent/config.json as the O1 installer
// (anix-control internal/agentinstall/install.sh, render_config) writes it.
func installerConfig(node string, id string) string {
	return `{
  "Log": {"Level": "info", "Output": ""},
  "Cores": [],
  "Nodes": [
    {
      "ApiHost": "https://control.anixops.net",
      "GRPCHost": "control.anixops.net:50051",
      "GRPCUseTLS": true,
      "AgentControlAllowInsecure": false,
      "AgentNode": "` + node + `",
      "NodeID": ` + id + `,
      "AgentIdentity": {
        "Enroll": "auto",
        "CertDir": "/var/lib/anixops-agent/pki",
        "EnrollCredentialFile": "/var/lib/anixops-agent/enroll.credential"
      },
      "AgentStream": {"StateDir": "/var/lib/anixops-agent/stream"}
    }
  ]
}`
}

func loadDocument(t *testing.T, document string) (*Conf, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(path, []byte(document), 0o600))
	c := New()
	return c, c.LoadFromPath(path)
}

func TestInstallerProxyConfigIsCredentialOnly(t *testing.T) {
	c, err := loadDocument(t, installerConfig("proxy-12", "12"))
	require.NoError(t, err)
	require.Len(t, c.NodeConfig, 1)
	require.Empty(t, c.CoresConfig, "the cores come from the stream's configuration")
	require.False(t, c.Forward.Enabled())
	api := c.NodeConfig[0].ApiConfig
	require.Equal(t, 12, api.NodeID)
	require.NoError(t, api.validateCredentials())
	require.Equal(t, "/var/lib/anixops-agent/pki", api.AgentIdentity.Dir())
	require.Equal(t, "/var/lib/anixops-agent/stream", api.AgentStream.Dir())
}

func TestInstallerForwardConfigIsCredentialOnly(t *testing.T) {
	c, err := loadDocument(t, installerConfig("forward-41", "41"))
	require.NoError(t, err)
	require.Empty(t, c.NodeConfig)
	require.True(t, c.Forward.ForwardNodeOnly())
	require.Equal(t, 41, c.Forward.ForwardNode.NodeID)
	require.Equal(t, DefaultForwardStateDir, c.Forward.Dir())
}

func TestInstallerConfigPassesProductionValidation(t *testing.T) {
	for _, node := range [][2]string{{"proxy-12", "12"}, {"forward-41", "41"}} {
		document := strings.Replace(installerConfig(node[0], node[1]), `"Log"`, `"Environment": "production", "Log"`, 1)
		document = strings.Replace(document, `"AgentNode"`, `"MaintenanceEnvironment": "production", "AgentNode"`, 1)
		_, err := loadDocument(t, document)
		require.NoError(t, err, node[0])
	}
}

func TestProxyNodeNeedsStreamTLSAndACredential(t *testing.T) {
	document := installerConfig("proxy-12", "12")
	for name, broken := range map[string]string{
		"no credential": strings.Replace(document, `"EnrollCredentialFile": "/var/lib/anixops-agent/enroll.credential"`, `"EnrollCredentialFile": ""`, 1),
		"enroll off":    strings.Replace(document, `"Enroll": "auto"`, `"Enroll": "off"`, 1),
		"no TLS":        strings.Replace(strings.Replace(document, `"GRPCUseTLS": true`, `"GRPCUseTLS": false`, 1), "https://", "http://", 1),
		"no node":       strings.Replace(strings.Replace(document, `"NodeID": 12,`, ``, 1), `"AgentNode": "proxy-12",`, ``, 1),
	} {
		_, err := loadDocument(t, broken)
		require.Error(t, err, name)
	}
}

func TestProxyNodeWithAnEnrolledIdentity(t *testing.T) {
	pki := t.TempDir()
	document := strings.Replace(installerConfig("proxy-12", "12"), `"EnrollCredentialFile": "/var/lib/anixops-agent/enroll.credential"`, `"EnrollCredentialFile": ""`, 1)
	document = strings.Replace(document, `"CertDir": "/var/lib/anixops-agent/pki"`, `"CertDir": "`+pki+`"`, 1)
	_, err := loadDocument(t, document)
	require.Error(t, err, "neither a credential nor an identity")
	require.NoError(t, os.MkdirAll(filepath.Join(pki, "proxy-12"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(pki, "proxy-12", "identity.pem"), []byte("identity"), 0o600))
	c, err := loadDocument(t, document)
	require.NoError(t, err)
	require.True(t, c.NodeConfig[0].ApiConfig.IdentityEnrolled())
}

func TestRemovedSettingsAreIgnored(t *testing.T) {
	// A configuration from before the stream-only Agent still loads: the
	// removed settings (ApiKey, Transport, SyncConfig, ...) are ignored.
	document := strings.Replace(installerConfig("proxy-12", "12"), `"NodeID": 12,`,
		`"NodeID": 12, "ApiKey": "node-api-key-0123456789", "Transport": "grpc", "AgentControlEnabled": true, "SyncConfig": {"EnableWebSocket": true},`, 1)
	c, err := loadDocument(t, document)
	require.NoError(t, err)
	require.Equal(t, 12, c.NodeConfig[0].ApiConfig.NodeID)
}

func TestProductionNodeNeedsNoCoreOrSupervisor(t *testing.T) {
	cfg := readyProductionAgentConfig()
	api := &cfg.NodeConfig[0].ApiConfig
	api.PluginSupervisorEnabled = false
	api.GRPCServerName = ""
	cfg.CoresConfig = nil
	cfg.NodeConfig[0].Options = Options{}
	require.NoError(t, cfg.ValidateForProduction())
}
