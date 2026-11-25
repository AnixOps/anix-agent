package anixcore

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	vCore "github.com/AnixOps/anix-agent/v5/core"
)

func testMeshNetworkWithSections() panel.MeshNetwork {
	network := testMeshNetwork()
	network.DNS = json.RawMessage(`{"enabled":true,"suffix":"mesh.internal","names":[{"name":"nas.cn","address":"10.150.128.7"}]}`)
	network.HostGroups = json.RawMessage(`[{"cidr":"10.127.0.0/24","gateway":"gw-a"}]`)
	return network
}

func testMeshNetwork() panel.MeshNetwork {
	return panel.MeshNetwork{
		ID: "cn", Name: "region-cn", Secret: "s3cret", SecureMode: true, Cipher: "aes-gcm",
		Address: "10.150.0.5/16", Role: "full",
		Listen:  json.RawMessage(`[{"transport":"tcp","port":11010}]`),
		Peers:   json.RawMessage(`[{"server":"203.0.113.1","port":11010,"transport":"tcp"}]`),
		Routing: json.RawMessage(`{"policy":"latency"}`),
	}
}

func TestMeshNetworksGoToTheKernelLayered(t *testing.T) {
	api, server := newFakeAPI(t)
	api.features = []string{meshFeature}
	core := externalCore(t, server)
	t.Cleanup(func() { _ = core.Close() })
	if !core.MeshSupported() {
		t.Fatal("the kernel lists the mesh feature")
	}
	if err := core.ApplyMesh([]panel.MeshNetwork{testMeshNetwork()}); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(api.mesh[len(api.mesh)-1])
	want := `{"networks":[{"config_version":1,"network":{"cipher":"aes-gcm","name":"region-cn","secret":"s3cret","secure_mode":true},` +
		`"node":{"address":"10.150.0.5/16","listen":[{"port":11010,"transport":"tcp"}],"role":"full"},` +
		`"peers":[{"port":11010,"server":"203.0.113.1","transport":"tcp"}],"routing":{"policy":"latency"},"tag":"mesh-cn","type":"mesh"}]}`
	if string(got) != want {
		t.Fatalf("PUT /v1/mesh\n got %s\nwant %s", got, want)
	}

	state, err := core.MeshStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	status := state.Networks
	if len(status) != 1 || status[0].ID != "cn" || status[0].Tag != "" || !status[0].Running || status[0].Peers[0].Via[0] != "10.150.0.3" {
		t.Fatalf("status = %+v", status)
	}

	// A restarted kernel gets the networks again; none stops them.
	if err := core.replay(); err != nil {
		t.Fatal(err)
	}
	if len(api.mesh) != 2 {
		t.Fatalf("PUT /v1/mesh calls = %d", len(api.mesh))
	}
	if err := core.ApplyMesh(nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := json.Marshal(api.mesh[len(api.mesh)-1]); string(got) != `{"networks":[]}` {
		t.Fatalf("stop = %s", got)
	}
}

func TestMeshNeedsTheKernelFeature(t *testing.T) {
	api, server := newFakeAPI(t)
	core := externalCore(t, server)
	t.Cleanup(func() { _ = core.Close() })
	if core.MeshSupported() {
		t.Fatal("no mesh feature")
	}
	if err := core.ApplyMesh(nil); err != nil {
		t.Fatal(err)
	}
	if err := core.ApplyMesh([]panel.MeshNetwork{testMeshNetwork()}); !errors.Is(err, vCore.ErrMeshUnsupported) {
		t.Fatalf("err = %v", err)
	}
	if len(api.mesh) != 0 {
		t.Fatalf("PUT /v1/mesh sent to a kernel without it: %v", api.mesh)
	}
}

func TestMeshSectionsGoOnlyToAKernelThatTakesThem(t *testing.T) {
	for _, test := range []struct {
		features        []string
		dns, hostGroups bool
	}{
		{[]string{meshFeature}, false, false},
		{[]string{meshFeature, meshDNSFeature}, true, false},
		{[]string{meshFeature, meshDNSFeature, meshHostGroupsFeature}, true, true},
		// The sections need the mesh itself.
		{[]string{meshDNSFeature, meshHostGroupsFeature}, false, false},
	} {
		api, server := newFakeAPI(t)
		api.features = test.features
		core := externalCore(t, server)
		err := core.ApplyMesh([]panel.MeshNetwork{testMeshNetworkWithSections()})
		_ = core.Close()
		if !slices.Contains(test.features, meshFeature) {
			if !errors.Is(err, vCore.ErrMeshUnsupported) || len(api.mesh) != 0 {
				t.Fatalf("%v: err = %v, PUT %v", test.features, err, api.mesh)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		network := api.mesh[0]["networks"].([]any)[0].(map[string]any)
		_, dns := network["dns"]
		_, hostGroups := network["host_groups"]
		if dns != test.dns || hostGroups != test.hostGroups {
			t.Fatalf("%v: dns %v, host_groups %v in %v", test.features, dns, hostGroups, network)
		}
	}

	// A null section is no section.
	network := testMeshNetwork()
	network.DNS, network.HostGroups = json.RawMessage(`null`), json.RawMessage(`null`)
	body := meshBody([]panel.MeshNetwork{network}, true, true)["networks"].([]map[string]any)[0]
	if _, ok := body["dns"]; ok {
		t.Fatalf("null dns sent: %v", body)
	}
	if _, ok := body["host_groups"]; ok {
		t.Fatalf("null host_groups sent: %v", body)
	}
}

func TestMeshReplayFollowsTheKernelFeatures(t *testing.T) {
	api, server := newFakeAPI(t)
	api.features = []string{meshFeature}
	core := externalCore(t, server)
	t.Cleanup(func() { _ = core.Close() })
	if err := core.ApplyMesh([]panel.MeshNetwork{testMeshNetworkWithSections()}); err != nil {
		t.Fatal(err)
	}
	// An updated, restarted kernel gets the sections it now takes.
	api.features = []string{meshFeature, meshDNSFeature, meshHostGroupsFeature}
	if err := core.client.status(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := core.replay(); err != nil {
		t.Fatal(err)
	}
	network := api.mesh[len(api.mesh)-1]["networks"].([]any)[0].(map[string]any)
	if network["dns"] == nil || network["host_groups"] == nil {
		t.Fatalf("replayed = %v", network)
	}
}

func TestMeshInstanceIDAndRegionRequests(t *testing.T) {
	api, server := newFakeAPI(t)
	api.features = []string{meshFeature}
	api.meshInstance = "2f6d7c1e-0b8a-4c55-9e0e-6a1f3b9d2c10"
	api.meshRequests = []map[string]any{
		{"id": "r1", "network": "mesh-cn", "region": "eu", "reason": "moved"},
		{"id": "../x", "region": "eu"},
	}
	core := externalCore(t, server)
	t.Cleanup(func() { _ = core.Close() })

	// Without the feature the kernel's region requests are not taken.
	state, err := core.MeshStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.InstanceID != api.meshInstance || len(state.RegionRequests) != 0 {
		t.Fatalf("state = %+v", state)
	}
	if err := core.DoneMeshRegionRequest(context.Background(), "r1"); !errors.Is(err, vCore.ErrMeshUnsupported) {
		t.Fatalf("done without the feature: %v", err)
	}

	api.features = []string{meshFeature, meshRegionRequestsFeature}
	api.meshInstance = "bad id!"
	if err := core.client.status(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, err = core.MeshStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// An invalid instance id is no instance id; a request whose id does
	// not fit a path segment is left out.
	if state.InstanceID != "" || len(state.RegionRequests) != 1 || state.RegionRequests[0].ID != "r1" ||
		state.RegionRequests[0].Network != "cn" || state.RegionRequests[0].Region != "eu" {
		t.Fatalf("state = %+v", state)
	}
	if err := core.DoneMeshRegionRequest(context.Background(), "r1"); err != nil {
		t.Fatal(err)
	}
	if err := core.DoneMeshRegionRequest(context.Background(), "../x"); err == nil {
		t.Fatal("an invalid id reached the kernel")
	}
	if len(api.meshDone) != 1 || api.meshDone[0] != "r1" {
		t.Fatalf("deleted = %v", api.meshDone)
	}
}

func TestMeshManagedNetworksAndStaticKeys(t *testing.T) {
	api, server := newFakeAPI(t)
	api.features = []string{meshFeature}
	core := externalCore(t, server)
	t.Cleanup(func() { _ = core.Close() })

	// kind and native_keys go to the kernel's network section; an empty
	// list is still sent.
	managed := testMeshNetwork()
	managed.Kind = "managed"
	managed.NativeKeys = json.RawMessage(`[]`)
	if err := core.ApplyMesh([]panel.MeshNetwork{managed}); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(api.mesh[len(api.mesh)-1]["networks"].([]any)[0].(map[string]any)["network"])
	if want := `{"cipher":"aes-gcm","kind":"managed","name":"region-cn","native_keys":[],"secret":"s3cret","secure_mode":true}`; string(got) != want {
		t.Fatalf("network section\n got %s\nwant %s", got, want)
	}

	key := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	api.meshKeys = []map[string]any{
		{"network": "region-cn", "static_key": key},
		{"network": "region-eu", "static_key": "not base64"},
		{"network": "region-na", "static_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd"},
	}
	api.meshExtra = map[string]any{
		"static_key": "short",
		"failure":    map[string]any{"code": "peer_not_native", "detail": "node-7"},
		"alerts":     []any{map[string]any{"code": "peer_not_native", "peer": "node-9"}},
	}
	state, err := core.MeshStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Only well-formed keys are kept.
	if len(state.StaticKeys) != 1 || state.StaticKeys[0].Network != "region-cn" || state.StaticKeys[0].StaticKey != key {
		t.Fatalf("static keys = %+v", state.StaticKeys)
	}
	network := state.Networks[0]
	if network.StaticKey != "" {
		t.Fatalf("a malformed key was kept: %q", network.StaticKey)
	}
	// A refused peer becomes an alert, beside the kernel's own, once.
	want := []panel.MeshAlert{{Code: "peer_not_native", Peer: "node-9"}, {Code: "peer_not_native", Peer: "node-7"}}
	if !slices.Equal(network.Alerts, want) || network.Failure == nil || network.Failure.Code != "peer_not_native" {
		t.Fatalf("network = %+v", network)
	}
	api.meshExtra["alerts"] = []any{map[string]any{"code": "peer_not_native", "peer": "node-7"}}
	state, err = core.MeshStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Networks[0].Alerts) != 1 {
		t.Fatalf("alerts = %+v", state.Networks[0].Alerts)
	}
}
