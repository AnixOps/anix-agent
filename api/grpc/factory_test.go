package grpc

import (
	"testing"

	"github.com/AnixOps/anix-agent/v5/conf"
)

func TestResolveGRPCTarget(t *testing.T) {
	tests := []struct {
		name       string
		cfg        conf.ApiConfig
		wantTarget string
		wantTLS    bool
		wantSNI    string
		wantErr    bool
	}{
		{
			name: "explicit GRPCHost",
			cfg: conf.ApiConfig{
				APIHost:  "https://panel.example.com",
				GRPCHost: "grpc.example.com:1234",
			},
			wantTarget: "grpc.example.com:1234",
			wantTLS:    false,
			wantSNI:    "grpc.example.com",
		},
		{
			name: "api host https",
			cfg: conf.ApiConfig{
				APIHost: "https://panel.example.com",
			},
			wantTarget: "panel.example.com:443",
			wantTLS:    true,
			wantSNI:    "panel.example.com",
		},
		{
			name: "api host http",
			cfg: conf.ApiConfig{
				APIHost: "http://panel.example.com",
			},
			wantTarget: "panel.example.com:80",
			wantTLS:    false,
			wantSNI:    "panel.example.com",
		},
		{
			name: "grpc scheme",
			cfg: conf.ApiConfig{
				APIHost: "grpc://panel.example.com",
			},
			wantTarget: "panel.example.com:80",
			wantTLS:    false,
			wantSNI:    "panel.example.com",
		},
		{
			name: "grpcs scheme",
			cfg: conf.ApiConfig{
				APIHost: "grpcs://panel.example.com",
			},
			wantTarget: "panel.example.com:443",
			wantTLS:    true,
			wantSNI:    "panel.example.com",
		},
		{
			name: "grpc use tls override and server name",
			cfg: conf.ApiConfig{
				APIHost:        "http://panel.example.com",
				GRPCUseTLS:     true,
				GRPCServerName: "sni.example.com",
			},
			wantTarget: "panel.example.com:80",
			wantTLS:    true,
			wantSNI:    "sni.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, useTLS, serverName, err := resolveGRPCTarget(&tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("resolveGRPCTarget error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if target != tt.wantTarget {
				t.Fatalf("target = %q, want %q", target, tt.wantTarget)
			}
			if useTLS != tt.wantTLS {
				t.Fatalf("useTLS = %v, want %v", useTLS, tt.wantTLS)
			}
			if serverName != tt.wantSNI {
				t.Fatalf("serverName = %q, want %q", serverName, tt.wantSNI)
			}
		})
	}
}
