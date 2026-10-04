package conf

import (
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
		"no token":           {Enable: true, NodeKind: "forward", ForwardNode: &ApiConfig{GRPCHost: "c:1", NodeID: 41}},
		"no enrollment":      {Enable: true, NodeKind: "forward", ForwardNode: &ApiConfig{GRPCHost: "c:1", NodeID: 41, Key: "t", AgentIdentity: AgentIdentityConfig{Enroll: "off"}}},
		"forward node proxy": {Enable: true, ForwardNode: &ApiConfig{}},
		"unknown kind":       {Enable: true, NodeKind: "relay"},
		"relative dir":       {Enable: true, StateDir: "forward"},
		"bad interface":      {Enable: true, Nftables: ForwardNftablesConfig{LimitInterfaces: []string{strings.Repeat("e", 16)}}},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
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
