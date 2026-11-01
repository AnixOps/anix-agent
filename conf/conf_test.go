package conf

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestConf_LoadFromPath(t *testing.T) {
	c := New()
	if err := c.LoadFromPath("../example/config.json"); err != nil {
		t.Fatalf("LoadFromPath() error = %v", err)
	}
	if len(c.NodeConfig) == 0 {
		t.Fatal("LoadFromPath() loaded no nodes")
	}
	if !c.NodeConfig[0].ApiConfig.AgentControlEnabled {
		t.Fatal("example config must explicitly enable the v3 Agent control stream")
	}
}

func TestApiConfigAgentControlRequiresExplicitOptIn(t *testing.T) {
	var legacy ApiConfig
	if err := json.Unmarshal([]byte(`{"ApiHost":"http://127.0.0.1","NodeID":1,"ApiKey":"key"}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy API config: %v", err)
	}
	if legacy.AgentControlEnabled {
		t.Fatal("legacy config without AgentControlEnabled unexpectedly enabled the control stream")
	}
	if legacy.PluginSupervisorEnabled {
		t.Fatal("legacy config without PluginSupervisorEnabled unexpectedly enabled the plugin runtime")
	}

	var current ApiConfig
	if err := json.Unmarshal([]byte(`{"AgentControlEnabled":true}`), &current); err != nil {
		t.Fatalf("unmarshal current API config: %v", err)
	}
	if !current.AgentControlEnabled {
		t.Fatal("AgentControlEnabled=true was not preserved")
	}
	if current.AgentControlAllowInsecure {
		t.Fatal("AgentControlAllowInsecure unexpectedly defaults to true")
	}
	if current.PluginSupervisorEnabled {
		t.Fatal("AgentControlEnabled must not implicitly enable the plugin Supervisor")
	}

	var insecure ApiConfig
	if err := json.Unmarshal([]byte(`{"AgentControlAllowInsecure":true}`), &insecure); err != nil {
		t.Fatalf("unmarshal insecure opt-in: %v", err)
	}
	if !insecure.AgentControlAllowInsecure {
		t.Fatal("AgentControlAllowInsecure=true was not preserved")
	}
}

func TestConf_LoadWireGuardConfigPreservesExplicitCore(t *testing.T) {
	c := New()
	if err := c.LoadFromPath("../example/config.wireguard.json"); err != nil {
		t.Fatalf("LoadFromPath() error = %v", err)
	}
	if len(c.NodeConfig) != 1 {
		t.Fatalf("LoadFromPath() nodes = %d, want 1", len(c.NodeConfig))
	}
	node := c.NodeConfig[0]
	if node.Options.Core != "wireguard" {
		t.Fatalf("Options.Core = %q, want wireguard", node.Options.Core)
	}
	if node.ApiConfig.NodeType != "wireguard" {
		t.Fatalf("ApiConfig.NodeType = %q, want wireguard", node.ApiConfig.NodeType)
	}
}

func TestConf_WatchMissingFile(t *testing.T) {
	c := New()
	err := c.Watch(filepath.Join(t.TempDir(), "missing.json"), func() {})
	if err == nil {
		t.Fatal("Watch() missing file error = nil")
	}
}
