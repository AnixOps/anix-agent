package conf

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExampleConfigLoads(t *testing.T) {
	c := New()
	require.NoError(t, c.LoadFromPath("../example/config.json"))
	require.Equal(t, "development", c.Environment)
	require.Equal(t, "info", c.LogConfig.Level)
	require.Empty(t, c.CoresConfig)
	require.Len(t, c.NodeConfig, 1)
	node := c.NodeConfig[0]
	require.Equal(t, 33, node.ApiConfig.NodeID)
	require.Equal(t, 30, node.ApiConfig.GRPCKeepalive)
	require.True(t, node.ApiConfig.PluginSupervisorEnabled)
	require.Equal(t, int64(200), node.Options.DeviceOnlineMinTraffic)
	require.Equal(t, "0.0.0.0", node.Options.ListenIP)
	require.Equal(t, "self", node.Options.CertConfig.CertMode)
	require.NotEmpty(t, node.Options.RawOptions)
}

func TestWireGuardExampleKeepsItsCore(t *testing.T) {
	c := New()
	require.NoError(t, c.LoadFromPath("../example/config.wireguard.json"))
	require.Len(t, c.CoresConfig, 1)
	core := c.CoresConfig[0]
	require.Equal(t, "wireguard", core.Type)
	require.NotNil(t, core.WireGuardConfig)
	require.Equal(t, int64(180), core.WireGuardConfig.OnlineHandshakeTimeoutSeconds)
	require.Equal(t, "wireguard", c.NodeConfig[0].Options.Core)
	require.Equal(t, "wireguard", c.NodeConfig[0].ApiConfig.NodeType)
}

func TestApiConfigDefaultsAreSafe(t *testing.T) {
	var node NodeConfig
	require.NoError(t, json.Unmarshal([]byte(`{"NodeID": 5}`), &node))
	api := node.ApiConfig
	require.Equal(t, "http://127.0.0.1", api.APIHost)
	require.Equal(t, 30, api.GRPCKeepalive)
	require.False(t, api.PluginSupervisorEnabled)
	require.False(t, api.AgentControlAllowInsecure)
	require.Equal(t, "0.0.0.0", node.Options.ListenIP)
	require.Equal(t, "none", node.Options.CertConfig.CertMode)
}

func TestOptionsNormaliseCore(t *testing.T) {
	for in, want := range map[string]string{
		"anixcore": "anixcore", "wireguard": "wireguard",
		"xray": "anixcore", "sing": "anixcore", "hysteria2": "anixcore",
		"v2ray": "", "": "",
	} {
		var o Options
		require.NoError(t, json.Unmarshal([]byte(`{"Core":"`+in+`"}`), &o))
		require.Equal(t, want, o.Core, in)
	}
}

func TestWatchMissingFileFails(t *testing.T) {
	require.Error(t, New().Watch(filepath.Join(t.TempDir(), "missing.json"), func() {}))
}

func TestStripJSONC(t *testing.T) {
	for in, want := range map[string]string{
		"{\"a\": 1, // note\n\"b\": [1, 2,],}":          `{"a":1,"b":[1,2]}`,
		`{/* block */"a": /* x */ 1}`:                   `{"a":1}`,
		`{"s": "http://x/*y*/ \"q\" ] }, // z"}`:        `{"s":"http://x/*y*/ \"q\" ] }, // z"}`,
		"[\"a\\\\\", // c\n \"b\" , /* d */ ]":          `["a\\","b"]`,
		"{\"a\": {\"b\": 1,\n// trailing\n},\n}\n//end": `{"a":{"b":1}}`,
	} {
		var got, expected any
		require.NoError(t, json.Unmarshal(stripJSONC([]byte(in)), &got), in)
		require.NoError(t, json.Unmarshal([]byte(want), &expected))
		require.Equal(t, expected, got, in)
	}
	// Strings are copied byte for byte.
	in := `{"k": "a // b /* c */ \" ], d"}`
	require.Equal(t, in, string(stripJSONC([]byte(in))))
}

func TestUnknownMembersAreIgnored(t *testing.T) {
	document := `{
  // comments and trailing commas are accepted
  "Unknown": {"x": 1},
  "Log": {"Level": "debug", "Extra": true,},
  "Cores": [{"Type": "anixcore", "BinaryPath": "/usr/bin/anixcore", "Retired": 1}],
  "Nodes": [{
    "ApiHost": "https://control.example.com", "GRPCUseTLS": true, "NodeID": 9,
    "AgentIdentity": {"EnrollCredentialFile": "/var/lib/anixops-agent/enroll.credential"},
    "SendIP": "0.0.0.0", "RuleListPath": "/etc/rules", "RejectUnknownSni": true,
    "LimitConfig": {"SpeedLimit": 10, "EnableRealtime": true, "DeviceLimit": 2, "ConnLimit": 3,
      "EnableIpRecorder": true, "IpRecorderConfig": {"Periodic": 60}},
    "CertConfig": {"CertMode": "file", "RejectUnknownSni": true},
  },],
}`
	c, err := loadDocument(t, document)
	require.NoError(t, err)
	require.Equal(t, "debug", c.LogConfig.Level)
	require.Equal(t, "/usr/bin/anixcore", c.CoresConfig[0].AnixcoreConfig.BinaryPath)
	require.Equal(t, 10, c.NodeConfig[0].Options.LimitConfig.SpeedLimit)
	require.Equal(t, "file", c.NodeConfig[0].Options.CertConfig.CertMode)
}
