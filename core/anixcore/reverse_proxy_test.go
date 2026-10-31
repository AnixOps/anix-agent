package anixcore

import (
	"testing"

	anxmgmtpb "github.com/AnixOps/anix-agent/v5/api/anxmgmt/v1"
	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
)

func reverseProxyPlan() *networkv1.NetworkPlan {
	plan := forwardPlan()
	plan.ReverseProxies = []*networkv1.ReverseProxy{{
		Id: "rp-1", Listen: &networkv1.Endpoint{Address: "0.0.0.0", Port: 443},
		CertificatePem: "CERT", PrivateKeyPem: "KEY",
		Sites: []*networkv1.ReverseProxySite{{Hosts: []string{"app.example.com"}, Routes: []*networkv1.ReverseProxyRoute{
			{Path: "/api", StripPrefix: true, HostHeader: "upstream", Headers: map[string]string{"X-Route": "api"},
				Upstreams: []*networkv1.ForwardTarget{{Host: "10.0.0.5", Port: 8080, Weight: 2}},
				Policy:    &networkv1.ForwardPolicy{Balance: "least_conn", Health: &networkv1.ForwardHealth{IntervalMs: 5000, TimeoutMs: 2000}}},
			{Path: "/", Host: "origin.example.com", Upstreams: []*networkv1.ForwardTarget{{Host: "10.0.0.6", Port: 80}}},
		}}},
		Next: &networkv1.ReverseProxy_TransportId{TransportId: "tr-jp"},
	}, {
		Id: "rp-2", Listen: &networkv1.Endpoint{Address: "0.0.0.0", Port: 80},
		Sites: []*networkv1.ReverseProxySite{{Hosts: []string{"app.example.com"}, RedirectHttps: true}},
		Next:  &networkv1.ReverseProxy_EgressId{EgressId: "eg-1"},
	}}
	return plan
}

// Reverse proxies run as reverse_proxy inbounds next to the forwards,
// never in the plan anixcore gets, and report like forwards.
func TestReverseProxiesAreInbounds(t *testing.T) {
	line := &fakeLine{links: map[string]*anxmgmtpb.Link{}}
	api, core := lineCore(t, line)
	core.client.reverseProxy.Store(true)

	status, err := core.ApplyNetwork(reverseProxyPlan())
	if err != nil {
		t.Fatal(err)
	}
	if _, sent := api.network[len(api.network)-1]["reverse_proxies"]; sent {
		t.Fatal("anixcore got the reverse proxies in the plan")
	}
	tls, plain := api.inbounds["rproxy-rp-1"], api.inbounds["rproxy-rp-2"]
	if tls["type"] != "reverse_proxy" || tls["outbound"] != "anx-line:tr-jp" || tls["listen_port"] != float64(443) ||
		tls["forwarded_proto"] != "https" || tls["tls"].(map[string]any)["certificate"] != "CERT" ||
		tls["tls"].(map[string]any)["key"] != "KEY" {
		t.Fatalf("rp-1 = %v", tls)
	}
	routes := tls["sites"].([]any)[0].(map[string]any)["routes"].([]any)
	api0, root := routes[0].(map[string]any), routes[1].(map[string]any)
	if api0["path"] != "/api" || api0["strip_prefix"] != true || api0["host_header"] != "upstream" ||
		api0["headers"].(map[string]any)["X-Route"] != "api" || api0["balance"] != "least_conn" ||
		api0["health"].(map[string]any)["interval_ms"] != float64(5000) ||
		api0["upstreams"].([]any)[0].(map[string]any)["weight"] != float64(2) {
		t.Fatalf("api route = %v", api0)
	}
	if _, set := root["path"]; set || root["host"] != "origin.example.com" || root["host_header"] != nil {
		t.Fatalf("root route = %v", root)
	}
	if plain["outbound"] != "egress:eg-1" || plain["tls"] != nil || plain["forwarded_proto"] != nil ||
		plain["sites"].([]any)[0].(map[string]any)["redirect_https"] != true {
		t.Fatalf("rp-2 = %v", plain)
	}
	if api.inbounds["forward-rt-1"] == nil {
		t.Fatal("the forwards are gone")
	}
	proxies := status.GetReverseProxies()
	if len(proxies) != 2 || proxies[0].GetId() != "rp-1" || proxies[1].GetId() != "rp-2" ||
		proxies[0].GetState() != networkv1.ComponentState_COMPONENT_STATE_APPLIED || len(status.GetPortForwards()) != 2 {
		t.Fatalf("status = %v", status)
	}
	if status, err := core.NetworkStatus(); err != nil || len(status.GetReverseProxies()) != 2 || len(status.GetPortForwards()) != 2 {
		t.Fatalf("NetworkStatus = %v, %v", status, err)
	}

	// Gone from the plan, gone from anixcore.
	if _, err := core.ApplyNetwork(forwardPlan()); err != nil {
		t.Fatal(err)
	}
	if api.inbounds["rproxy-rp-1"] != nil || api.inbounds["forward-rt-1"] == nil {
		t.Fatalf("inbounds = %v", api.inbounds)
	}
}

// A kernel without the reverse_proxy feature gets no reverse_proxy
// inbound; the status says why.
func TestReverseProxyOnAnOldKernel(t *testing.T) {
	line := &fakeLine{links: map[string]*anxmgmtpb.Link{}}
	api, core := lineCore(t, line)
	status, err := core.ApplyNetwork(reverseProxyPlan())
	if err != nil {
		t.Fatal(err)
	}
	if api.inbounds["rproxy-rp-1"] != nil || api.inbounds["forward-rt-1"] == nil {
		t.Fatalf("inbounds = %v", api.inbounds)
	}
	proxies := status.GetReverseProxies()
	if len(proxies) != 2 || proxies[0].GetState() != networkv1.ComponentState_COMPONENT_STATE_DOWN || proxies[0].GetDetail() == "" {
		t.Fatalf("status = %v", proxies)
	}
}
