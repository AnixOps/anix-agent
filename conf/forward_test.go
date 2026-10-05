package conf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestForwardConfigValidate(t *testing.T) {
	var none *ForwardConfig
	if err := none.Validate(); err != nil || none.Enabled() || none.Kind() != ForwardNodeKindProxy || none.Dir() != DefaultForwardStateDir {
		t.Fatalf("absent section: %v", err)
	}
	proxy := &ForwardConfig{Enable: true, ProxyNodeID: 7}
	if err := proxy.Validate(); err != nil || proxy.ForwardNodeOnly() {
		t.Fatalf("proxy forwarding: %v", err)
	}
	forward := &ForwardConfig{Enable: true, NodeKind: "forward", ForwardNode: &ApiConfig{
		GRPCHost: "control.example.com:50051", GRPCUseTLS: true, NodeID: 41, Key: "token",
	}}
	if err := forward.Validate(); err != nil || !forward.ForwardNodeOnly() {
		t.Fatalf("forward node: %v", err)
	}
	for name, c := range map[string]*ForwardConfig{
		"no forward node":    {Enable: true, NodeKind: "forward"},
		"no node id":         {Enable: true, NodeKind: "forward", ForwardNode: &ApiConfig{GRPCHost: "c:1", Key: "t"}},
		"no enrollment":      {Enable: true, NodeKind: "forward", ForwardNode: &ApiConfig{GRPCHost: "c:1", NodeID: 41, Key: "t", AgentIdentity: AgentIdentityConfig{Enroll: "off"}}},
		"forward node proxy": {Enable: true, ForwardNode: &ApiConfig{}},
		"unknown kind":       {Enable: true, NodeKind: "relay"},
		"relative dir":       {Enable: true, StateDir: "forward"},
		"bad interface":      {Enable: true, Nftables: ForwardNftablesConfig{LimitInterfaces: []string{strings.Repeat("e", 16)}}},
		"relative relay dir": {Enable: true, AnixOps: ForwardAnixOpsConfig{Enable: true, Dir: "relay"}},
		"relative relay bin": {Enable: true, AnixOps: ForwardAnixOpsConfig{Enable: true, Binary: "anixops-relay"}},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The experimental anixops engine is off unless the section says so.
func TestForwardAnixOpsIsOffByDefault(t *testing.T) {
	c := &ForwardConfig{Enable: true, ProxyNodeID: 7}
	if c.AnixOps.Enable {
		t.Fatal("the experimental engine is on by default")
	}
	c.AnixOps = ForwardAnixOpsConfig{Enable: true, Binary: "/usr/lib/anixops-agent/anixops-relay", Dir: "/var/lib/anixops-relay", RuntimeDir: "/run/anixops-relay"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestForwardNodeOnlyProduction(t *testing.T) {
	c := &Conf{Environment: "production", Forward: &ForwardConfig{Enable: true, NodeKind: "forward", ForwardNode: &ApiConfig{
		GRPCHost: "control.anixops.net:50051", GRPCServerName: "control.anixops.net", GRPCUseTLS: true, NodeID: 41, Key: "f0rward-n0de-t0ken-value",
	}}}
	if err := c.ValidateForProduction(); err != nil {
		t.Fatalf("a forward node needs no proxy node or core: %v", err)
	}
	c.Forward.ForwardNode.GRPCUseTLS = false
	if err := c.ValidateForProduction(); err == nil {
		t.Fatal("a production forward node without TLS was accepted")
	}
}

// The O1 installer's configuration: the forward node is an entry of Nodes
// with AgentNode forward-<id>, no ApiKey and no core.
func TestO1ForwardNodeConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	document := `{
  "Log": {"Level": "info", "Output": ""},
  "Cores": [],
  "Nodes": [
    {
      "ApiHost": "https://control.anixops.net",
      "Transport": "grpc",
      "GRPCHost": "control.anixops.net:50051",
      "GRPCUseTLS": true,
      "AgentControlEnabled": true,
      "AgentControlAllowInsecure": false,
      "AgentNode": "forward-41",
      "NodeID": 41,
      "AgentIdentity": {"Enroll": "auto", "CertDir": "/var/lib/anixops-agent/pki", "EnrollCredentialFile": "/var/lib/anixops-agent/enroll.credential"},
      "AgentStream": {"StateDir": "/var/lib/anixops-agent/stream"}
    }
  ]
}`
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	c := New()
	if err := c.LoadFromPath(path); err != nil {
		t.Fatal(err)
	}
	if len(c.NodeConfig) != 0 || !c.Forward.ForwardNodeOnly() || c.Forward.ForwardNode.NodeID != 41 ||
		c.Forward.ForwardNode.AgentIdentity.Dir() != "/var/lib/anixops-agent/pki" || c.Forward.Dir() != DefaultForwardStateDir {
		t.Fatalf("normalized: nodes %d, forward %+v", len(c.NodeConfig), c.Forward)
	}
	for name, doc := range map[string]string{
		"mismatched id": strings.Replace(document, `"NodeID": 41`, `"NodeID": 42`, 1),
		"unknown kind":  strings.Replace(document, `"forward-41"`, `"edge-41"`, 1),
	} {
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := New().LoadFromPath(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A proxy node's AgentNode stays a proxy node.
	if err := os.WriteFile(path, []byte(strings.Replace(document, `"forward-41"`, `"proxy-41"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	c = New()
	if err := c.LoadFromPath(path); err != nil {
		t.Fatal(err)
	}
	if len(c.NodeConfig) != 1 || c.Forward.Enabled() {
		t.Fatalf("proxy AgentNode: nodes %d, forward %+v", len(c.NodeConfig), c.Forward)
	}
}
