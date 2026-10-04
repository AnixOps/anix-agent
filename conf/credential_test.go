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
      "Transport": "grpc",
      "GRPCHost": "control.anixops.net:50051",
      "GRPCUseTLS": true,
      "AgentControlEnabled": true,
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
	require.Empty(t, api.Key)
	require.True(t, api.StreamCredentialOnly())
	require.Equal(t, "/var/lib/anixops-agent/pki", api.AgentIdentity.Dir())
	require.Equal(t, "/var/lib/anixops-agent/stream", api.AgentStream.Dir())
}

func TestInstallerForwardConfigIsCredentialOnly(t *testing.T) {
	c, err := loadDocument(t, installerConfig("forward-41", "41"))
	require.NoError(t, err)
	require.Empty(t, c.NodeConfig)
	require.True(t, c.Forward.ForwardNodeOnly())
	require.Empty(t, c.Forward.ForwardNode.Key)
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

func TestKeyLessProxyNodeNeedsStreamTLSAndACredential(t *testing.T) {
	document := installerConfig("proxy-12", "12")
	for name, broken := range map[string]string{
		"no credential":   strings.Replace(document, `"EnrollCredentialFile": "/var/lib/anixops-agent/enroll.credential"`, `"EnrollCredentialFile": ""`, 1),
		"enroll off":      strings.Replace(document, `"Enroll": "auto"`, `"Enroll": "off"`, 1),
		"data plane off":  strings.Replace(document, `"AgentStream": {`, `"AgentStream": {"DataPlane": "off", `, 1),
		"no TLS":          strings.Replace(strings.Replace(document, `"GRPCUseTLS": true`, `"GRPCUseTLS": false`, 1), "https://", "http://", 1),
		"no AgentControl": strings.Replace(strings.Replace(document, `"AgentControlEnabled": true`, `"AgentControlEnabled": false`, 1), `"AgentNode": "proxy-12",`, ``, 1),
	} {
		_, err := loadDocument(t, broken)
		if name == "no AgentControl" {
			// Neither AgentNode nor the stream: an older configuration,
			// left as it was.
			require.NoError(t, err, name)
			continue
		}
		require.ErrorContains(t, err, "no ApiKey", name)
	}
}

func TestKeyLessProxyNodeWithAnEnrolledIdentity(t *testing.T) {
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

func TestApiKeyConfigStillLoads(t *testing.T) {
	document := strings.Replace(installerConfig("proxy-12", "12"), `"NodeID": 12,`, `"NodeID": 12, "ApiKey": "node-api-key-0123456789",`, 1)
	document = strings.Replace(document, `"EnrollCredentialFile": "/var/lib/anixops-agent/enroll.credential"`, `"EnrollCredentialFile": ""`, 1)
	c, err := loadDocument(t, document)
	require.NoError(t, err)
	require.False(t, c.NodeConfig[0].ApiConfig.StreamCredentialOnly())
	_, err = loadDocument(t, `{"Nodes":[{"ApiHost":"http://127.0.0.1","ApiKey":"legacy","NodeID":3}]}`)
	require.NoError(t, err)
}

func TestProductionCredentialOnlyNodeRelaxesLegacySettings(t *testing.T) {
	cfg := readyProductionAgentConfig()
	api := &cfg.NodeConfig[0].ApiConfig
	api.Key = ""
	api.PluginSupervisorEnabled = false
	api.EnableSign = false
	api.GRPCServerName = ""
	api.AgentIdentity.EnrollCredentialFile = "/var/lib/anixops-agent/enroll.credential"
	cfg.CoresConfig = nil
	cfg.NodeConfig[0].Options = Options{}
	require.NoError(t, cfg.ValidateForProduction())

	// Without a credential or an identity it is not credential-only:
	// the full legacy requirements apply again.
	api.AgentIdentity.EnrollCredentialFile = ""
	api.AgentIdentity.CertDir = t.TempDir()
	require.ErrorContains(t, cfg.ValidateForProduction(), "production configuration requires at least one core")
}
