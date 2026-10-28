package anixcore

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
)

// fakeNetworkStatus answers /v1/network like anixcore: every egress
// applied, every ingress on its first egress.
func fakeNetworkStatus(plan map[string]any) map[string]any {
	status := map[string]any{"generation": 0, "egresses": []any{}, "ingresses": []any{}}
	if plan == nil {
		return status
	}
	if generation, ok := plan["generation"].(string); ok {
		status["generation"], _ = strconv.ParseUint(generation, 10, 64)
	}
	var egresses, ingresses []any
	first := ""
	for _, raw := range asList(plan["egresses"]) {
		egress := raw.(map[string]any)
		if first == "" {
			first = egress["id"].(string)
		}
		egresses = append(egresses, map[string]any{"id": egress["id"], "state": "applied", "checked": true,
			"rtt_ms": 12, "detail": nil, "changed_at_unix_ms": 1700000000000})
	}
	for _, raw := range asList(plan["ingresses"]) {
		ingress := raw.(map[string]any)
		ingresses = append(ingresses, map[string]any{"id": ingress["id"], "state": "applied", "active_egress_id": first})
	}
	status["egresses"], status["ingresses"] = egresses, ingresses
	return status
}

func asList(value any) []any {
	list, _ := value.([]any)
	return list
}

func networkPlan(port uint32) *networkv1.NetworkPlan {
	return &networkv1.NetworkPlan{
		DeviceRef: "proxy-1", Generation: 3, Hash: strings.Repeat("a", 64),
		Lines: []*networkv1.Line{{Id: "ln-1", Interface: "eth0", Families: []networkv1.Family{networkv1.Family_FAMILY_V4}}},
		Ingresses: []*networkv1.Ingress{{Id: "in-1", LineId: "ln-1", Kind: "direct", KindVersion: 1,
			Audience: networkv1.Audience_AUDIENCE_USER, Family: networkv1.Family_FAMILY_V4,
			Listen: &networkv1.Endpoint{Address: "0.0.0.0", Port: port}, Protocols: []string{"trojan"},
			Pairing: &networkv1.Pairing{Mode: networkv1.PairingMode_PAIRING_MODE_SAME_LINE}}},
		Egresses: []*networkv1.Egress{{Id: "eg-1", LineId: "ln-1", Kind: "nat_direct", KindVersion: 1,
			Audience: networkv1.Audience_AUDIENCE_INTERNET, Family: networkv1.Family_FAMILY_V4, Source: "auto"}},
		Paths: []*networkv1.Path{{Id: "pa-1", IngressId: "in-1", Next: &networkv1.Path_EgressId{EgressId: "eg-1"}}},
	}
}

func trojanNode(port int) (*panel.NodeInfo, *conf.Options) {
	return &panel.NodeInfo{Type: "trojan", Common: &panel.CommonNode{ServerPort: port}, Trojan: &panel.TrojanNode{Network: "tcp"}},
		&conf.Options{ListenIP: "::", CertConfig: &conf.CertConfig{CertMode: "file", CertFile: "/etc/cert.pem", KeyFile: "/etc/key.pem"}}
}

// The plan goes to anixcore as protojson; the inbound on the ingress's
// port joins it (created again when the plan arrives after it), the status
// comes back as components, and a restarted anixcore gets the plan before
// the inbounds. No plan removes it and the inbound leaves the ingress.
func TestNetworkPlanIsSentJoinedAndReplayed(t *testing.T) {
	api, server := newFakeAPI(t)
	core := externalCore(t, server)
	defer core.Close()

	info, options := trojanNode(443)
	if err := core.AddNode("trojan", info, options); err != nil {
		t.Fatal(err)
	}
	if _, ok := api.inbounds["trojan"]["ingress"]; ok {
		t.Fatal("an inbound joined an ingress before any plan")
	}
	status, err := core.ApplyNetwork(networkPlan(443))
	if err != nil {
		t.Fatal(err)
	}
	if len(api.network) != 1 || api.network[0]["device_ref"] != "proxy-1" || api.network[0]["generation"] != "3" {
		t.Fatalf("sent plan = %v", api.network)
	}
	if paths := asList(api.network[0]["paths"]); len(paths) != 1 || paths[0].(map[string]any)["egress_id"] != "eg-1" {
		t.Fatalf("sent paths = %v", api.network[0]["paths"])
	}
	if api.inbounds["trojan"]["ingress"] != "in-1" {
		t.Fatalf("inbound after the plan = %v", api.inbounds["trojan"])
	}
	if len(status.GetComponents()) != 2 {
		t.Fatalf("status = %v", status)
	}
	egress, ingress := status.GetComponents()[0], status.GetComponents()[1]
	if egress.GetComponent() != networkv1.Component_COMPONENT_EGRESS || egress.GetId() != "eg-1" ||
		egress.GetState() != networkv1.ComponentState_COMPONENT_STATE_APPLIED || egress.GetRttMs() != 12 {
		t.Fatalf("egress status = %v", egress)
	}
	if ingress.GetActiveEgressId() != "eg-1" || ingress.GetState() != networkv1.ComponentState_COMPONENT_STATE_APPLIED {
		t.Fatalf("ingress status = %v", ingress)
	}
	read, err := core.NetworkStatus()
	if err != nil || len(read.GetComponents()) != 2 {
		t.Fatalf("NetworkStatus = %v, %v", read, err)
	}

	// A node added under the plan joins at once.
	other, otherOptions := trojanNode(8443)
	if err := core.AddNode("other", other, otherOptions); err != nil {
		t.Fatal(err)
	}
	if _, ok := api.inbounds["other"]["ingress"]; ok {
		t.Fatal("an inbound on another port joined the ingress")
	}

	api.mu.Lock()
	api.inbounds = map[string]map[string]any{}
	api.calls = nil
	api.mu.Unlock()
	if err := core.replay(); err != nil {
		t.Fatal(err)
	}
	if len(api.network) != 2 || api.inbounds["trojan"]["ingress"] != "in-1" {
		t.Fatalf("replay = %v, %v", api.network, api.inbounds)
	}
	if api.calls[0] != "PUT /v1/network" {
		t.Fatalf("the plan was not replayed first: %v", api.calls)
	}

	if _, err := core.ApplyNetwork(nil); err != nil {
		t.Fatal(err)
	}
	if len(api.network[2]) != 0 {
		t.Fatalf("no plan sent %v", api.network[2])
	}
	if _, ok := api.inbounds["trojan"]["ingress"]; ok {
		t.Fatalf("the inbound kept its ingress: %v", api.inbounds["trojan"])
	}
	api.mu.Lock()
	api.inbounds = map[string]map[string]any{}
	api.mu.Unlock()
	if err := core.replay(); err != nil {
		t.Fatal(err)
	}
	if len(api.network) != 3 {
		t.Fatal("no plan was replayed")
	}
	var _ vCore.NetworkApplier = core
}

func TestNetworkNeedsAnAnixcoreWithTheEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/status" {
			_, _ = io.WriteString(w, `{}`)
			return
		}
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"error":"no such endpoint"}`)
	}))
	defer server.Close()
	core := externalCore(t, server)
	defer core.Close()
	if _, err := core.ApplyNetwork(networkPlan(443)); err == nil || !strings.Contains(err.Error(), "update it") {
		t.Fatalf("ApplyNetwork = %v", err)
	}
	if core.network != nil {
		t.Fatal("a refused plan was kept")
	}
}
