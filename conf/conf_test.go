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
	if c.NodeConfig[0].ApiConfig.NodeID != 33 {
		t.Fatalf("NodeID = %d, want 33", c.NodeConfig[0].ApiConfig.NodeID)
	}
}

func TestApiConfigDefaultsAreSafe(t *testing.T) {
	var api ApiConfig
	if err := json.Unmarshal([]byte(`{"ApiHost":"https://control.company.net","NodeID":1}`), &api); err != nil {
		t.Fatalf("unmarshal API config: %v", err)
	}
	if api.PluginSupervisorEnabled {
		t.Fatal("a config without PluginSupervisorEnabled unexpectedly enabled the plugin runtime")
	}
	if api.AgentControlAllowInsecure {
		t.Fatal("AgentControlAllowInsecure unexpectedly defaults to true")
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
