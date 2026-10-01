package node

import (
	"strings"
	"testing"

	"github.com/AnixOps/anix-agent/v4/conf"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
)

func TestResolveAgentControlTargetSecurity(t *testing.T) {
	tests := []struct {
		name           string
		config         conf.ApiConfig
		wantTarget     string
		wantTLS        bool
		wantServerName string
		wantErr        string
	}{
		{
			name:           "https API host infers TLS",
			config:         conf.ApiConfig{APIHost: "https://control.example.com"},
			wantTarget:     "control.example.com:50051",
			wantTLS:        true,
			wantServerName: "control.example.com",
		},
		{
			name: "explicit target still inherits API TLS",
			config: conf.ApiConfig{
				APIHost:  "https://control.example.com",
				GRPCHost: "grpc.internal.example:443",
			},
			wantTarget:     "grpc.internal.example:443",
			wantTLS:        true,
			wantServerName: "grpc.internal.example",
		},
		{
			name:           "loopback plaintext is allowed",
			config:         conf.ApiConfig{APIHost: "http://127.0.0.1:8080"},
			wantTarget:     "127.0.0.1:50051",
			wantServerName: "127.0.0.1",
		},
		{
			name: "remote plaintext is rejected",
			config: conf.ApiConfig{
				APIHost:  "http://control.example.com",
				GRPCHost: "control.example.com:50051",
			},
			wantErr: "refuses plaintext credentials",
		},
		{
			name: "remote plaintext requires explicit opt in",
			config: conf.ApiConfig{
				APIHost:                   "http://control.example.com",
				GRPCHost:                  "control.example.com:50051",
				AgentControlAllowInsecure: true,
			},
			wantTarget:     "control.example.com:50051",
			wantServerName: "control.example.com",
		},
		{
			name: "explicit TLS and server name",
			config: conf.ApiConfig{
				APIHost:        "http://control.example.com",
				GRPCHost:       "10.0.0.10:443",
				GRPCUseTLS:     true,
				GRPCServerName: "control.example.com",
			},
			wantTarget:     "10.0.0.10:443",
			wantTLS:        true,
			wantServerName: "control.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, useTLS, serverName, err := resolveAgentControlTarget(&tt.config)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("resolveAgentControlTarget() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveAgentControlTarget() error = %v", err)
			}
			if target != tt.wantTarget || useTLS != tt.wantTLS || serverName != tt.wantServerName {
				t.Fatalf(
					"resolveAgentControlTarget() = (%q, %t, %q), want (%q, %t, %q)",
					target, useTLS, serverName,
					tt.wantTarget, tt.wantTLS, tt.wantServerName,
				)
			}
		})
	}
}

func TestIsLoopbackAgentControlTarget(t *testing.T) {
	for _, target := range []string{"localhost:50051", "127.0.0.2:50051", "[::1]:50051"} {
		if !isLoopbackAgentControlTarget(target) {
			t.Fatalf("isLoopbackAgentControlTarget(%q) = false", target)
		}
	}
	if isLoopbackAgentControlTarget("control.example.com:50051") {
		t.Fatal("remote DNS target was treated as loopback")
	}
}

func TestAgentCapabilitiesAdvertisePluginOperationsOnlyWhenEnabled(t *testing.T) {
	legacy := agentCapabilities(&errorTestCore{}, false)
	current := agentCapabilities(&errorTestCore{}, true)
	contains := func(capabilities []*agentv1pb.Capability, name string) bool {
		for _, capability := range capabilities {
			if capability.Name == name {
				return true
			}
		}
		return false
	}
	if contains(legacy, "plugin.enable") {
		t.Fatal("legacy Agent advertised plugin.enable")
	}
	for _, capabilities := range [][]*agentv1pb.Capability{legacy, current} {
		if !contains(capabilities, "operation.cancel") {
			t.Fatal("Agent did not advertise operation.cancel")
		}
		for _, capability := range capabilities {
			if capability.Name == "operation.cancel" && capability.Version != "v1" {
				t.Fatalf("operation.cancel version = %q, want v1", capability.Version)
			}
		}
	}
	for _, name := range []string{"plugin.install", "plugin.inspect", "plugin.configure", "plugin.enable", "plugin.disable", "plugin.update", "plugin.rollback", "plugin.health"} {
		if !contains(current, name) {
			t.Fatalf("plugin-enabled Agent did not advertise %s", name)
		}
	}
	if !contains(current, "kernel.observed-state") {
		t.Fatal("plugin-enabled Agent did not advertise kernel.observed-state")
	}
}
