package grpc

import (
	"testing"

	pb "github.com/AnixOps/anix-agent/v5/api/grpc/v2boardpb"
)

func TestParseWireGuardRelayPreservesWSSCertificateContract(t *testing.T) {
	relay := parseWireGuardRelay(`{
		"backend":"gost",
		"mode":"relay+wss",
		"role":"entry",
		"wss_compat":true,
		"wss_path":"/wireguard",
		"wss_secure":true,
		"wss_server_name":"exit.example.com",
		"wss_ca_file":"/etc/v2bx/relay-ca.pem"
	}`)
	if relay.Backend != "gost" || relay.Mode != "relay+wss" || relay.Role != "entry" {
		t.Fatalf("relay identity = %#v", relay)
	}
	if !relay.WSSCompat || !relay.WSSSecure || relay.WSSPath != "/wireguard" {
		t.Fatalf("relay WSS transport settings = %#v", relay)
	}
	if relay.WSSServerName != "exit.example.com" || relay.WSSCAFile != "/etc/v2bx/relay-ca.pem" {
		t.Fatalf("relay WSS verification settings = %#v", relay)
	}
}

func TestNodeConfigFingerprintAvoidsUnchangedWireGuardReloads(t *testing.T) {
	first := &pb.NodeConfigResponse{
		NodeType: "wireguard",
		Type:     "wireguard",
		Extra: map[string]string{
			"relay":          `{"mode":"relay+wss","role":"entry"}`,
			"server_address": "10.66.0.1/24",
		},
	}
	second := &pb.NodeConfigResponse{
		NodeType: "wireguard",
		Type:     "wireguard",
		Extra: map[string]string{
			"server_address": "10.66.0.1/24",
			"relay":          `{"mode":"relay+wss","role":"entry"}`,
		},
	}

	firstFingerprint, err := nodeConfigFingerprint(first)
	if err != nil {
		t.Fatalf("fingerprint first config: %v", err)
	}
	secondFingerprint, err := nodeConfigFingerprint(second)
	if err != nil {
		t.Fatalf("fingerprint second config: %v", err)
	}
	if firstFingerprint != secondFingerprint {
		t.Fatal("equivalent WireGuard configs produced different fingerprints")
	}

	client := &GRPCClient{nodeConfigHash: firstFingerprint, hasNodeConfigHash: true}
	if client.nodeConfigHash != secondFingerprint {
		t.Fatal("unchanged WireGuard config would trigger a runtime reload")
	}

	second.Extra["relay"] = `{"mode":"relay+wss","role":"exit"}`
	changedFingerprint, err := nodeConfigFingerprint(second)
	if err != nil {
		t.Fatalf("fingerprint changed config: %v", err)
	}
	if client.nodeConfigHash == changedFingerprint {
		t.Fatal("changed WireGuard relay config was not detected")
	}
}
