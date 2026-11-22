package panel

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseWireGuardExitWithoutKeys(t *testing.T) {
	body := `{"type":"wireguard","node_type":"wireguard","host":"exit.example","server_port":0,
		"cidr":"10.8.0.0/24","mtu":1420,"tunnel_type":"relay",
		"relay":{"backend":"wss","mode":"relay","role":"exit","exit_nat":true,"tun_name":"anx-wg0",
			"tun_address":"10.9.0.2/30","outbound_iface":"eth0","routing_table":100,
			"wss_path":"/tunnel","wss_secure":true,"wss_ca_file":"/etc/anixops/agent/ca.pem",
			"wss_cert_file":"/etc/anixops/agent/exit.pem","wss_key_file":"/etc/anixops/agent/exit.key",
			"network_policy":{"version":1,"strategy":"failover","paths":[{"name":"a","interface":"eth0","priority":1}],
				"health_check":{"interval_seconds":5,"failure_threshold":3}}}}`
	info, category, err := ParseNodeInfo([]byte(body), 7)
	require.NoError(t, err)
	assert.Equal(t, "wireguard", category)
	assert.Equal(t, 7, info.Id)
	assert.Equal(t, None, info.Security)
	require.NotNil(t, info.WireGuard)
	assert.Equal(t, 0, info.Common.ServerPort)
	assert.Equal(t, 0, info.WireGuard.ServerPort)
	assert.Equal(t, "exit.example", info.WireGuard.Host)
	assert.Empty(t, info.WireGuard.ServerPrivateKey)
	relay := info.WireGuard.Relay
	assert.Equal(t, "exit", relay.Role)
	assert.True(t, relay.ExitNAT)
	assert.Equal(t, "/etc/anixops/agent/exit.key", relay.WSSKeyFile)
	assert.Equal(t, 100, relay.RoutingTable)
	assert.Equal(t, "failover", relay.NetworkPolicy.Strategy)
	assert.Equal(t, 3, relay.NetworkPolicy.HealthCheck.FailureThreshold)
	require.Len(t, relay.NetworkPolicy.Paths, 1)
	assert.Nil(t, info.VLessVMess)
}

func TestParseTypeAndCategory(t *testing.T) {
	for _, test := range []struct{ body, protocol, category string }{
		{`{"type":"VLESS"}`, "vless", "vless"},
		{`{"node_type":"Trojan"}`, "trojan", "trojan"},
		{`{"type":"v2ray"}`, "vmess", "vmess"},
		{`{"node_type":"v2ray"}`, "vmess", "vmess"},
		{`{"type":"shadowsocks","node_type":"proxy"}`, "shadowsocks", "proxy"},
	} {
		info, category, err := ParseNodeInfo([]byte(test.body), 1)
		require.NoError(t, err, test.body)
		assert.Equal(t, test.protocol, info.Type, test.body)
		assert.Equal(t, test.category, category, test.body)
	}
	info, _, err := ParseNodeInfo([]byte(`{"type":"v2ray","server_port":443}`), 1)
	require.NoError(t, err)
	require.NotNil(t, info.VLessVMess)
	assert.Equal(t, 443, info.VLessVMess.ServerPort)
}

func TestParseSecurity(t *testing.T) {
	for body, want := range map[string]int{
		`{"type":"vless","tls":2}`:  Reality,
		`{"type":"vmess","tls":1}`:  Tls,
		`{"type":"vless"}`:          None,
		`{"type":"trojan"}`:         Tls,
		`{"type":"tuic"}`:           Tls,
		`{"type":"anytls"}`:         Tls,
		`{"type":"hysteria2"}`:      Tls,
		`{"type":"shadowsocks"}`:    None,
		`{"type":"snell"}`:          None,
		`{"type":"iwan"}`:           None,
		`{"type":"anx"}`:            None,
		`{"type":"wireguard"}`:      None,
		`{"type":"trojan","tls":0}`: Tls,
	} {
		info, _, err := ParseNodeInfo([]byte(body), 1)
		require.NoError(t, err, body)
		assert.Equal(t, want, info.Security, body)
	}
}

func TestParseProtocolMembers(t *testing.T) {
	info, _, err := ParseNodeInfo([]byte(`{"type":"vless","server_port":443,"tls":2,"network":"tcp","flow":"xtls-rprx-vision",
		"network_settings":{"path":"/"},
		"tls_settings":{"server_name":"www.example.com","dest":"www.example.com:443","server_port":"443","short_id":"ab","private_key":"pk"}}`), 1)
	require.NoError(t, err)
	node := info.VLessVMess
	assert.Equal(t, TlsSettings{ServerName: "www.example.com", Dest: "www.example.com:443", ServerPort: "443", ShortId: "ab", PrivateKey: "pk"}, node.TlsSettings)
	assert.JSONEq(t, `{"path":"/"}`, string(node.NetworkSettings))
	assert.Equal(t, "xtls-rprx-vision", node.Flow)

	info, _, err = ParseNodeInfo([]byte(`{"type":"hysteria2","obfs":"salamander","obfs-password":"p"}`), 1)
	require.NoError(t, err)
	assert.Equal(t, "salamander", info.Hysteria2.ObfsType)
	assert.Equal(t, "p", info.Hysteria2.ObfsPassword)

	info, _, err = ParseNodeInfo([]byte(`{"type":"anytls","padding_scheme":["stop=2"]}`), 1)
	require.NoError(t, err)
	assert.Equal(t, []string{"stop=2"}, info.AnyTls.PaddingScheme)

	info, _, err = ParseNodeInfo([]byte(`{"type":"shadowsocks","cipher":"aes-128-gcm","server_key":"k"}`), 1)
	require.NoError(t, err)
	assert.Equal(t, "aes-128-gcm", info.Shadowsocks.Cipher)
	assert.Equal(t, "k", info.Shadowsocks.ServerKey)
}

func TestParseBlockRules(t *testing.T) {
	body := `{"type":"vmess","routes":[
		{"id":1,"match":"regexp:(^|\\.)ads\\.example$, protocol:bittorrent","action":"block"},
		{"id":2,"match":["example.org","protocol:quic"],"action":"block"},
		{"id":3,"match":"ignored.example","action":"dns"}]}`
	info, _, err := ParseNodeInfo([]byte(body), 1)
	require.NoError(t, err)
	assert.Equal(t, Rules{
		Regexp:   []string{`(^|\.)ads\.example$`, "example.org"},
		Protocol: []string{"bittorrent", "quic"},
	}, info.Rules)
	assert.Nil(t, info.Common.Routes)
	assert.Nil(t, info.Common.BaseConfig)
	assert.Nil(t, info.VLessVMess.Routes)

	for _, match := range []string{`1`, `{"a":"b"}`, `["a",2]`} {
		body := fmt.Sprintf(`{"type":"vmess","routes":[{"id":9,"match":%s,"action":"dns"}]}`, match)
		_, _, err := ParseNodeInfo([]byte(body), 1)
		require.ErrorContains(t, err, "route 9:", match)
	}
}

func TestParseIntervals(t *testing.T) {
	for body, want := range map[string][2]time.Duration{
		`{"type":"vless","base_config":{"push_interval":60,"pull_interval":"30"}}`:  {60 * time.Second, 30 * time.Second},
		`{"type":"vless","base_config":{"push_interval":null,"pull_interval":"x"}}`: {0, 0},
		`{"type":"vless","base_config":{}}`:                                         {0, 0},
		`{"type":"vless"}`:                                                          {0, 0},
	} {
		info, _, err := ParseNodeInfo([]byte(body), 1)
		require.NoError(t, err, body)
		assert.Equal(t, want, [2]time.Duration{info.PushInterval, info.PullInterval}, body)
	}
}

func TestParseErrors(t *testing.T) {
	_, _, err := ParseNodeInfo([]byte(`{"type":"socks"}`), 1)
	require.EqualError(t, err, "unsupported node type: socks")

	const secret = "s3cret-server-key"
	for _, body := range []string{
		`{"server_key":"` + secret + `"}`,
		`{"type":"shadowsocks","server_key":"` + secret + `","server_port":"x"}`,
		`{"type":"vless","server_key":"` + secret + `","routes":[{"id":1,"match":5}]}`,
		`{"type":"vless","server_key":"` + secret + `"`,
	} {
		_, _, err := ParseNodeInfo([]byte(body), 1)
		require.Error(t, err, body)
		assert.NotContains(t, err.Error(), secret)
	}
	_, _, err = ParseNodeInfo([]byte(`{"host":"a"}`), 1)
	require.EqualError(t, err, "node type not found in the node configuration (12 bytes)")
}
