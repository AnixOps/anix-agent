package panel

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseNodeInfoParsesWireGuardExitWithoutEntryKeyMaterial(t *testing.T) {
	node, _, err := ParseNodeInfo([]byte(`{
			"type":"wireguard",
			"node_type":"wireguard",
			"host":"exit.example.com",
			"server_port":0,
			"server_name":"exit.example.com",
			"cidr":"10.66.0.0/24",
			"server_address":"",
			"server_private_key":"",
			"server_public_key":"",
			"mtu":1280,
			"dns":[],
			"allowed_ips":[],
			"tunnel_type":"wss",
			"relay":{
				"backend":"gost",
				"mode":"relay+wss",
				"role":"exit",
				"wss_compat":true,
				"wss_path":"/wireguard",
				"wss_cert_file":"/etc/v2bx/relay-cert.pem",
				"wss_key_file":"/etc/v2bx/relay-key.pem",
				"exit_nat":true,
				"server_port":18443,
				"tun_port":18421,
				"tun_name":"wg-exit",
				"entry_tun_address":"172.31.66.2/24",
				"exit_tun_address":"172.31.66.1/24",
				"outbound_iface":"eth0"
			},
			"routes":[],
			"base_config":{"pull_interval":60,"push_interval":60}
		}`), 1)
	require.NoError(t, err)
	require.Equal(t, "wireguard", node.Type)
	require.NotNil(t, node.WireGuard)
	require.Equal(t, "exit", node.WireGuard.Relay.Role)
	require.Empty(t, node.WireGuard.ServerAddress)
	require.Empty(t, node.WireGuard.ServerPrivateKey)
	require.Zero(t, node.Common.ServerPort)
	require.Equal(t, 18443, node.WireGuard.Relay.ServerPort)
	require.Equal(t, "wss", node.WireGuard.TunnelType)
	require.Equal(t, "/wireguard", node.WireGuard.Relay.WSSPath)
	require.Equal(t, "/etc/v2bx/relay-cert.pem", node.WireGuard.Relay.WSSCertFile)
	require.Equal(t, "/etc/v2bx/relay-key.pem", node.WireGuard.Relay.WSSKeyFile)
}
