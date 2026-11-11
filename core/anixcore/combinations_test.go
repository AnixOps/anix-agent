package anixcore

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/AnixOps/anix-agent/v5/api/panel"
)

// Every protocol, TLS mode and transport combination Control may offer
// (contracts/agent/v1/protocol-combinations.json, the same file as in
// anix-control, whose tests hold the panel to it) must become an anixcore
// inbound of that shape, from a configuration answer as Control builds it.
func TestEveryOfferedCombinationMaps(t *testing.T) {
	raw, err := os.ReadFile("../../contracts/agent/v1/protocol-combinations.json")
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		Combinations []struct {
			Type       string   `json:"type"`
			TLS        []int    `json:"tls"`
			Transports []string `json:"transports"`
		} `json:"combinations"`
	}
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	old := anxKeyFile
	anxKeyFile = func() (string, error) { return "/var/lib/anixops-agent/anx-server/server.key", nil }
	defer func() { anxKeyFile = old }()

	core := &Core{}
	for _, row := range table.Combinations {
		// WireGuard runs in core/wireguard, not in anixcore.
		if row.Type == "wireguard" {
			continue
		}
		if !slices.Contains(core.Protocols(), row.Type) {
			t.Errorf("%s is not among the core's protocols", row.Type)
		}
		for _, tls := range row.TLS {
			for _, transport := range row.Transports {
				name := fmt.Sprintf("%s/%d/%s", row.Type, tls, transport)
				// One answer with every type's settings; each type reads its own.
				body, _ := json.Marshal(map[string]any{
					"type": row.Type, "server_port": 443, "tls": tls, "network": transport,
					"network_settings": map[string]any{"path": "/p", "serviceName": "svc"},
					"tls_settings":     map[string]any{"private_key": "private", "server_name": "www.example.com", "short_id": "0123abcd"},
					"cipher":           "2022-blake3-aes-128-gcm", "server_key": "AAECAwQFBgcICQoLDA0ODw==",
					"psk": "shared-psk", "version": 4, "pool": "10.66.0.0/16", "server_names": []string{"www.example.com"},
				})
				info, _, err := panel.ParseNodeInfo(body, 1)
				if err != nil {
					t.Errorf("%s: %v", name, err)
					continue
				}
				inbound, err := inboundConfig("x", info, certOptions())
				if err != nil {
					t.Errorf("%s: %v", name, err)
					continue
				}
				_, hasTLS := inbound["tls"]
				_, hasReality := inbound["reality"]
				carried, _ := inbound["transport"].(map[string]any)
				stream := transport != "tcp" && transport != "udp"
				settings := !stream || carried["path"] == "/p" || carried["service_name"] == "svc"
				if inbound["type"] != row.Type || hasTLS != (tls == 1) || hasReality != (tls == 2) || stream != (carried["type"] == transport) || !settings {
					t.Errorf("%s: inbound = %v", name, inbound)
				}
				if _, err := apiUsersFor(info, panel.UserInfo{Id: 1, Uuid: "c9a1e7b0-5b0e-4a4b-9a54-2f3f1c1b0d11"}); err != nil {
					t.Errorf("%s: user: %v", name, err)
				}
			}
		}
	}
}
