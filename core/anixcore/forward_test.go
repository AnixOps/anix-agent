package anixcore

import (
	"strings"
	"testing"

	anxmgmtpb "github.com/AnixOps/anix-agent/v5/api/anxmgmt/v1"
	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
)

func forwardPlan() *networkv1.NetworkPlan {
	plan := dialPlan("PUB-1")
	plan.PortForwards = []*networkv1.PortForward{
		{Id: "rt-1", Listen: &networkv1.Endpoint{Address: "0.0.0.0", Port: 20001}, Protocols: []string{"tcp", "udp"},
			Targets: []*networkv1.ForwardTarget{{Host: "10.0.0.5", Port: 22}},
			Next:    &networkv1.PortForward_TransportId{TransportId: "tr-jp"}},
		{Id: "rt-2", Listen: &networkv1.Endpoint{Address: "0.0.0.0", Port: 20002}, Protocols: []string{"tcp"},
			Targets: []*networkv1.ForwardTarget{{Host: "a.example", Port: 443, Weight: 2}, {Host: "203.0.113.8", Port: 443, Priority: 1}},
			Next:    &networkv1.PortForward_EgressId{EgressId: "eg-1"},
			Policy: &networkv1.ForwardPolicy{Balance: "least_conn", ProxyProtocol: "v1", BandwidthBps: 8_000_000, MaxConns: 100,
				Health:         &networkv1.ForwardHealth{IntervalMs: 5000, TimeoutMs: 2000},
				CircuitBreaker: &networkv1.ForwardBreaker{FailureThreshold: 3, OpenMs: 30000}}},
	}
	return plan
}

// Port forwards run as forward inbounds after the plan, leaving by their
// transport's anx-line outbound or their egress; anixcore never sees them
// in the plan, they report their bytes, a changed one is replaced and a
// gone one removed, and a restarted anixcore gets them again after the plan.
func TestPortForwardsAreForwardInbounds(t *testing.T) {
	line := &fakeLine{links: map[string]*anxmgmtpb.Link{}}
	api, core := lineCore(t, line)

	status, err := core.ApplyNetwork(forwardPlan())
	if err != nil {
		t.Fatal(err)
	}
	if _, sent := api.network[len(api.network)-1]["port_forwards"]; sent {
		t.Fatal("anixcore got the port forwards in the plan")
	}
	one, two := api.inbounds["forward-rt-1"], api.inbounds["forward-rt-2"]
	if one["type"] != "forward" || one["outbound"] != "anx-line:tr-jp" || one["network"] != "tcp,udp" ||
		one["server"] != "10.0.0.5" || one["server_port"] != float64(22) || one["listen_port"] != float64(20001) {
		t.Fatalf("rt-1 = %v", one)
	}
	if two["outbound"] != "egress:eg-1" || two["server"] != nil || len(two["targets"].([]any)) != 2 {
		t.Fatalf("rt-2 = %v", two)
	}
	first, second := two["targets"].([]any)[0].(map[string]any), two["targets"].([]any)[1].(map[string]any)
	if first["weight"] != float64(2) || first["priority"] != nil || second["priority"] != float64(1) ||
		two["balance"] != "least_conn" || two["proxy_protocol"] != "v1" || two["bandwidth_bps"] != float64(8_000_000) ||
		two["max_conns"] != float64(100) || two["health"].(map[string]any)["interval_ms"] != float64(5000) ||
		two["circuit_breaker"].(map[string]any)["open_ms"] != float64(30000) {
		t.Fatalf("rt-2 policy = %v", two)
	}
	for _, key := range []string{"balance", "health", "circuit_breaker", "proxy_protocol", "bandwidth_bps", "max_conns"} {
		if _, set := one[key]; set {
			t.Fatalf("rt-1 without a policy has %s: %v", key, one)
		}
	}
	if last := api.calls[len(api.calls)-1]; !strings.HasPrefix(last, "GET /v1/inbounds/forward-") {
		t.Fatalf("calls = %v", api.calls)
	}
	forwards := status.GetPortForwards()
	if len(forwards) != 2 || forwards[0].GetId() != "rt-1" || forwards[0].GetUpBytes() != 110 || forwards[0].GetDownBytes() != 210 ||
		forwards[0].GetState() != networkv1.ComponentState_COMPONENT_STATE_APPLIED {
		t.Fatalf("status = %v", forwards)
	}
	if status, err := core.NetworkStatus(); err != nil || len(status.GetPortForwards()) != 2 {
		t.Fatalf("NetworkStatus = %v, %v", status, err)
	}

	// The same plan adds nothing; a changed forward is replaced, a gone one
	// removed.
	api.calls = nil
	if _, err := core.ApplyNetwork(forwardPlan()); err != nil {
		t.Fatal(err)
	}
	for _, call := range api.calls {
		if strings.HasPrefix(call, "POST /v1/inbounds") || strings.HasPrefix(call, "DELETE") {
			t.Fatalf("calls = %v", api.calls)
		}
	}
	plan := forwardPlan()
	plan.PortForwards[0].Targets[0].Port = 2222
	plan.PortForwards = plan.PortForwards[:1]
	api.calls = nil
	if _, err := core.ApplyNetwork(plan); err != nil {
		t.Fatal(err)
	}
	var changes []string
	for _, call := range api.calls {
		if strings.HasPrefix(call, "POST /v1/inbounds") || strings.HasPrefix(call, "DELETE") {
			changes = append(changes, call)
		}
	}
	if strings.Join(changes, ";") != "DELETE /v1/inbounds/forward-rt-1;DELETE /v1/inbounds/forward-rt-2;POST /v1/inbounds" ||
		api.inbounds["forward-rt-1"]["server_port"] != float64(2222) {
		t.Fatalf("changes = %v", changes)
	}

	// A restarted anixcore gets the plan, then the forward.
	api.inbounds = map[string]map[string]any{}
	api.calls = nil
	if err := core.replay(); err != nil {
		t.Fatal(err)
	}
	put, post := -1, -1
	for i, call := range api.calls {
		switch {
		case call == "PUT /v1/network" && put < 0:
			put = i
		case call == "POST /v1/inbounds" && post < 0:
			post = i
		}
	}
	if put < 0 || post < put || api.inbounds["forward-rt-1"] == nil {
		t.Fatalf("replay calls = %v", api.calls)
	}

	if _, err := core.ApplyNetwork(dialPlan("PUB-1")); err != nil {
		t.Fatal(err)
	}
	if api.inbounds["forward-rt-1"] != nil {
		t.Fatal("the gone forward is still there")
	}
}

func TestPortForwardIntoAnUnrunTransport(t *testing.T) {
	_, server := newFakeAPI(t)
	core := externalCore(t, server)
	defer core.Close()
	plan := networkPlan(443)
	plan.PortForwards = []*networkv1.PortForward{{Id: "rt-1", Listen: &networkv1.Endpoint{Address: "0.0.0.0", Port: 20001},
		Protocols: []string{"tcp"}, Targets: []*networkv1.ForwardTarget{{Host: "10.0.0.5", Port: 22}},
		Next: &networkv1.PortForward_TransportId{TransportId: "tr-x"}}}
	if _, err := core.ApplyNetwork(plan); err == nil || !strings.Contains(err.Error(), "dialing anx_line") {
		t.Fatalf("ApplyNetwork = %v", err)
	}
}
