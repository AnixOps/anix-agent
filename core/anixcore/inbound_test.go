package anixcore

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
)

func certOptions() *conf.Options {
	return &conf.Options{CertConfig: &conf.CertConfig{
		CertMode: "dns", CertFile: "/etc/anixops/cert.pem", KeyFile: "/etc/anixops/key.pem",
	}}
}

func TestVlessRealityNodesBecomeRealityInbounds(t *testing.T) {
	info := &panel.NodeInfo{
		Type:     "vless",
		Security: panel.Reality,
		Common:   &panel.CommonNode{ServerPort: 443},
		VAllss: &panel.VAllssNode{
			Network: "tcp",
			Flow:    visionFlow,
			TlsSettings: panel.TlsSettings{
				ServerName: "www.example.com",
				Dest:       "www.example.com:8443",
				ShortId:    "0123abcd",
				PrivateKey: "private",
			},
			RealityConfig: panel.RealityConfig{MaxTimeDiff: "1m30s"},
		},
	}
	inbound, err := inboundConfig("vless-1", info, &conf.Options{ListenIP: "0.0.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"private_key":              "private",
		"short_ids":                []string{"0123abcd"},
		"server_names":             []string{"www.example.com"},
		"handshake":                map[string]any{"server": "www.example.com", "server_port": 8443},
		"max_time_difference_secs": int64(90),
	}
	if !reflect.DeepEqual(inbound["reality"], want) {
		t.Fatalf("reality = %#v", inbound["reality"])
	}
	if _, ok := inbound["tls"]; ok {
		t.Fatal("reality inbounds take no tls")
	}
	user, err := apiUserFor(info, panel.UserInfo{Id: 5, Uuid: "c9a1e7b0-5b0e-4a4b-9a54-2f3f1c1b0d11"})
	if err != nil {
		t.Fatal(err)
	}
	if user != (apiUser{Name: "5", UUID: "c9a1e7b0-5b0e-4a4b-9a54-2f3f1c1b0d11", Flow: visionFlow}) {
		t.Fatalf("user = %+v", user)
	}

	info.VAllss.Network = "ws"
	if _, err := inboundConfig("vless-1", info, &conf.Options{}); err == nil {
		t.Fatal("reality over ws should be refused")
	}
}

func TestTransportsFollowTheNetworkSettings(t *testing.T) {
	for _, test := range []struct {
		name     string
		network  string
		settings string
		want     map[string]any
	}{
		{"tcp", "tcp", ``, nil},
		{"ws with early data", "ws", `{"path": "/ray?ed=2048", "headers": {"Host": "cdn.example.com"}}`,
			map[string]any{"type": "ws", "path": "/ray", "max_early_data": 2048, "host": "cdn.example.com"}},
		{"grpc", "grpc", `{"serviceName": "TunService"}`,
			map[string]any{"type": "grpc", "service_name": "TunService"}},
	} {
		info := &panel.NodeInfo{
			Type:     "vmess",
			Security: panel.Tls,
			Common:   &panel.CommonNode{ServerPort: 443},
			VAllss:   &panel.VAllssNode{Network: test.network, NetworkSettings: json.RawMessage(test.settings)},
		}
		inbound, err := inboundConfig("vmess", info, certOptions())
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		transport, _ := inbound["transport"].(map[string]any)
		if !reflect.DeepEqual(transport, test.want) {
			t.Fatalf("%s: transport = %#v", test.name, inbound["transport"])
		}
		if inbound["tls"] == nil {
			t.Fatalf("%s: tls is missing", test.name)
		}
	}

	for _, network := range []string{"httpupgrade", "quic"} {
		info := &panel.NodeInfo{
			Type: "trojan", Common: &panel.CommonNode{ServerPort: 443},
			Trojan: &panel.TrojanNode{Network: network},
		}
		if _, err := inboundConfig("trojan", info, certOptions()); err == nil {
			t.Fatalf("network %s should be refused", network)
		}
	}
}

func TestQuicProtocolsNeedCertificates(t *testing.T) {
	hysteria := &panel.NodeInfo{
		Type:      "hysteria2",
		Common:    &panel.CommonNode{ServerPort: 8443},
		Hysteria2: &panel.Hysteria2Node{ObfsType: "salamander", ObfsPassword: "obfs"},
	}
	if _, err := inboundConfig("hy2", hysteria, &conf.Options{}); err == nil ||
		!strings.Contains(err.Error(), "certificate") {
		t.Fatalf("hysteria2 without a certificate: %v", err)
	}
	inbound, err := inboundConfig("hy2", hysteria, certOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inbound["obfs"], map[string]any{"type": "salamander", "password": "obfs"}) {
		t.Fatalf("obfs = %#v", inbound["obfs"])
	}

	tuic := &panel.NodeInfo{
		Type:   "tuic",
		Common: &panel.CommonNode{ServerPort: 8443},
		Tuic:   &panel.TuicNode{CongestionControl: "bbr"},
	}
	inbound, err = inboundConfig("tuic", tuic, certOptions())
	if err != nil || inbound["congestion_control"] != "bbr" {
		t.Fatalf("tuic inbound = %v, %v", inbound, err)
	}
	user, _ := apiUserFor(tuic, panel.UserInfo{Id: 1, Uuid: "c9a1e7b0-5b0e-4a4b-9a54-2f3f1c1b0d11"})
	if user.UUID == "" || user.Password != user.UUID {
		t.Fatalf("tuic user = %+v", user)
	}
}

func TestIwanInbound(t *testing.T) {
	deny := false
	info := &panel.NodeInfo{
		Type:   "iwan",
		Common: &panel.CommonNode{ServerPort: 4500},
		Iwan: &panel.IwanNode{
			Pool:           "10.66.0.0/16",
			MTU:            1380,
			DNSUpstream:    "9.9.9.9",
			AllowEncrypt:   &deny,
			FixedAddresses: map[string]string{"7": "10.66.0.9"},
		},
	}
	inbound, err := inboundConfig("iwan", info, &conf.Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"tag": "iwan", "type": "iwan", "listen": "0.0.0.0", "listen_port": 4500,
		"pool": "10.66.0.0/16", "mtu": 1380, "dns_upstream": "9.9.9.9",
		"allow_encrypt": false, "allow_client_to_client": false,
	}
	if !reflect.DeepEqual(inbound, want) {
		t.Fatalf("iwan inbound = %#v", inbound)
	}
	uuid := "C9A1E7B0-5B0E-4A4B-9A54-2F3F1C1B0D11"
	fixed, err := apiUserFor(info, panel.UserInfo{Id: 7, Uuid: uuid})
	if err != nil || fixed != (apiUser{Name: "7", Password: "c9a1e7b05b0e4a4b", Address: "10.66.0.9"}) {
		t.Fatalf("iwan fixed user = %+v, %v", fixed, err)
	}
	dynamic, err := apiUserFor(info, panel.UserInfo{Id: 8, Uuid: uuid})
	if err != nil || dynamic.Address != "" || dynamic.Password != "c9a1e7b05b0e4a4b" {
		t.Fatalf("iwan user = %+v, %v", dynamic, err)
	}
	if _, err := apiUserFor(info, panel.UserInfo{Id: 9, Uuid: "short"}); err == nil {
		t.Fatal("a short uuid should be refused")
	}
	info.Iwan.Pool = ""
	if _, err := inboundConfig("iwan", info, &conf.Options{}); err == nil {
		t.Fatal("an iwan node without a pool should be refused")
	}
}

func TestUnsupportedNodesAreRefused(t *testing.T) {
	for _, info := range []*panel.NodeInfo{
		{Type: "anytls", Common: &panel.CommonNode{ServerPort: 1}},
		{Type: "shadowsocks", Common: &panel.CommonNode{ServerPort: 1},
			Shadowsocks: &panel.ShadowsocksNode{Cipher: "aes-128-gcm"}},
		{Type: "shadowsocks", Common: &panel.CommonNode{ServerPort: 1},
			Shadowsocks: &panel.ShadowsocksNode{Cipher: "2022-blake3-chacha20-poly1305"}},
		{Type: "trojan"},
	} {
		if _, err := inboundConfig("x", info, certOptions()); err == nil {
			t.Fatalf("%s node should be refused", info.Type)
		}
	}
	if _, err := inboundConfig("x", &panel.NodeInfo{
		Type: "vmess", Common: &panel.CommonNode{ServerPort: 1}, VAllss: &panel.VAllssNode{},
	}, &conf.Options{ListenIP: "not an ip"}); err == nil {
		t.Fatal("an invalid listen ip should be refused")
	}
}
