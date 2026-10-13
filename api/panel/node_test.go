package panel

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AnixOps/anix-agent/v5/conf"
	"github.com/stretchr/testify/require"
)

func TestClientGetNodeInfoParsesWireGuardExitWithoutEntryKeyMaterial(t *testing.T) {
	type requestRecord struct {
		path     string
		nodeID   string
		nodeType string
		apiKey   string
	}
	requests := make(chan requestRecord, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- requestRecord{
			path:     r.URL.Path,
			nodeID:   r.URL.Query().Get("node_id"),
			nodeType: r.URL.Query().Get("node_type"),
			apiKey:   r.Header.Get("X-API-Key"),
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := fmt.Fprint(w, `{
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
		}`); err != nil {
			return
		}
	}))
	defer server.Close()

	client, err := New(&conf.ApiConfig{APIHost: server.URL, Key: "test-api-key", NodeID: 1})
	require.NoError(t, err)
	client.SetNodeType("wireguard")

	node, err := client.GetNodeInfo()
	require.NoError(t, err)
	request := <-requests
	require.Equal(t, "/api/v2/server/UniProxy/config", request.path)
	require.Equal(t, "1", request.nodeID)
	require.Equal(t, "wireguard", request.nodeType)
	require.Equal(t, "test-api-key", request.apiKey)
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

func TestClientReportUserTrafficPostsExpectedPayload(t *testing.T) {
	type requestRecord struct {
		path   string
		method string
		nodeID string
	}
	requests := make(chan requestRecord, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- requestRecord{
			path:   r.URL.Path,
			method: r.Method,
			nodeID: r.URL.Query().Get("node_id"),
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := fmt.Fprint(w, `{}`); err != nil {
			return
		}
	}))
	defer server.Close()

	client, err := New(&conf.ApiConfig{APIHost: server.URL, Key: "test-api-key", NodeID: 1})
	require.NoError(t, err)
	require.NoError(t, client.ReportUserTraffic([]UserTraffic{{UID: 10372, Upload: 1000, Download: 2000}}))
	request := <-requests
	require.Equal(t, "/api/v2/server/UniProxy/push", request.path)
	require.Equal(t, http.MethodPost, request.method)
	require.Equal(t, "1", request.nodeID)
}
