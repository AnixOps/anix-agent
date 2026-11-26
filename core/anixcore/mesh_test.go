package anixcore

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
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
	api.features = []string{meshFeature, meshNativeKeysFeature}
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
		{[]string{meshFeature, meshNativeKeysFeature}, false, false},
		{[]string{meshFeature, meshNativeKeysFeature, meshDNSFeature}, true, false},
		{[]string{meshFeature, meshNativeKeysFeature, meshDNSFeature, meshHostGroupsFeature}, true, true},
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
	body := meshBody([]panel.MeshNetwork{network}, meshSections{dns: true, hostGroups: true, nativeKeys: true})["networks"].([]map[string]any)[0]
	if _, ok := body["dns"]; ok {
		t.Fatalf("null dns sent: %v", body)
	}
	if _, ok := body["host_groups"]; ok {
		t.Fatalf("null host_groups sent: %v", body)
	}
}

func TestMeshReplayFollowsTheKernelFeatures(t *testing.T) {
	api, server := newFakeAPI(t)
	api.features = []string{meshFeature, meshNativeKeysFeature}
	core := externalCore(t, server)
	t.Cleanup(func() { _ = core.Close() })
	if err := core.ApplyMesh([]panel.MeshNetwork{testMeshNetworkWithSections()}); err != nil {
		t.Fatal(err)
	}
	// An updated, restarted kernel gets the sections it now takes.
	api.features = []string{meshFeature, meshNativeKeysFeature, meshDNSFeature, meshHostGroupsFeature}
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
		state.RegionRequests[0].Network != "mesh-cn" || state.RegionRequests[0].Region != "eu" {
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

func TestMeshNetworkLayerAndStaticKeys(t *testing.T) {
	api, server := newFakeAPI(t)
	api.features = []string{meshFeature, meshNativeKeysFeature}
	api.meshKeys = []map[string]any{
		{"network": "region-cn", "static_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="},
		{"network": "region-eu", "static_key": "c2hvcnQ="},
		{"network": "", "static_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="},
	}
	core := externalCore(t, server)
	t.Cleanup(func() { _ = core.Close() })
	network := testMeshNetwork()
	network.Kind = "managed"
	network.NativeKeys = json.RawMessage(`["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","HxQdHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA="]`)
	empty := testMeshNetwork()
	empty.ID, empty.Name, empty.NativeKeys = "eu", "region-eu", json.RawMessage(`[]`)
	none := testMeshNetwork()
	none.ID, none.Name, none.NativeKeys = "na", "region-na", json.RawMessage(`null`)
	if !core.MeshNativeKeysSupported() {
		t.Fatal("the kernel lists mesh_native_keys")
	}
	if err := core.ApplyMesh([]panel.MeshNetwork{network, empty, none}); err != nil {
		t.Fatal(err)
	}
	networks := api.mesh[0]["networks"].([]any)
	layer := networks[0].(map[string]any)["network"].(map[string]any)
	// The list goes as it came, in order; an empty one too (the kernel
	// holds that network), a null one not at all.
	if got, _ := json.Marshal(layer["native_keys"]); layer["kind"] != "managed" ||
		string(got) != `["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","HxQdHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA="]` {
		t.Fatalf("network layer = %v", layer)
	}
	if keys, ok := networks[1].(map[string]any)["network"].(map[string]any)["native_keys"]; !ok || len(keys.([]any)) != 0 {
		t.Fatalf("empty list = %v", networks[1])
	}
	if _, ok := networks[2].(map[string]any)["network"].(map[string]any)["native_keys"]; ok {
		t.Fatalf("null list sent: %v", networks[2])
	}
	state, err := core.MeshStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Only a 32-byte key in standard base64 under a network name stays.
	if len(state.StaticKeys) != 1 || state.StaticKeys[0].Network != "region-cn" || state.StaticKeys[0].StaticKey != "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" {
		t.Fatalf("static keys = %+v", state.StaticKeys)
	}
}

func TestMeshNativeKeysNeedTheKernelFeature(t *testing.T) {
	api, server := newFakeAPI(t)
	api.features = []string{meshFeature}
	core := externalCore(t, server)
	t.Cleanup(func() { _ = core.Close() })
	if core.MeshNativeKeysSupported() {
		t.Fatal("no mesh_native_keys feature")
	}
	network := testMeshNetwork()
	network.Kind = panel.MeshKindLegacy
	network.NativeKeys = json.RawMessage(`["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="]`)
	if err := core.ApplyMesh([]panel.MeshNetwork{network}); err != nil {
		t.Fatal(err)
	}
	layer := api.mesh[0]["networks"].([]any)[0].(map[string]any)["network"].(map[string]any)
	if _, ok := layer["native_keys"]; ok || layer["kind"] != "legacy" {
		t.Fatalf("network layer = %v", layer)
	}
}

// A restarted kernel without mesh_native_keys (a downgrade) never gets a
// managed network on replay; nor does any kernel get one of an unknown
// kind.
func TestMeshReplayLeavesOutWhatTheKernelMayNotRun(t *testing.T) {
	api, server := newFakeAPI(t)
	api.features = []string{meshFeature, meshNativeKeysFeature}
	core := externalCore(t, server)
	t.Cleanup(func() { _ = core.Close() })
	managed := testMeshNetwork()
	managed.NativeKeys = json.RawMessage(`["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="]`)
	legacy := testMeshNetwork()
	legacy.ID, legacy.Name, legacy.Kind = "old", "old", panel.MeshKindLegacy
	unknown := testMeshNetwork()
	unknown.ID, unknown.Name, unknown.Kind = "odd", "odd", "open"
	if err := core.ApplyMesh([]panel.MeshNetwork{managed, legacy, unknown}); err != nil {
		t.Fatal(err)
	}
	names := func() []string {
		var out []string
		for _, n := range api.mesh[len(api.mesh)-1]["networks"].([]any) {
			out = append(out, n.(map[string]any)["network"].(map[string]any)["name"].(string))
		}
		return out
	}
	if got := names(); len(got) != 2 || got[0] != managed.Name || got[1] != "old" {
		t.Fatalf("applied = %v", got)
	}
	api.features = []string{meshFeature}
	if err := core.client.status(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := core.replay(); err != nil {
		t.Fatal(err)
	}
	if got := names(); len(got) != 1 || got[0] != "old" {
		t.Fatalf("replayed = %v", got)
	}
	// Updated again: the restarted kernel gets the managed network back,
	// with its native_keys.
	api.features = []string{meshFeature, meshNativeKeysFeature}
	if err := core.client.status(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := core.replay(); err != nil {
		t.Fatal(err)
	}
	if got := names(); len(got) != 2 || got[0] != managed.Name || got[1] != "old" {
		t.Fatalf("replayed after the update = %v", got)
	}
	layer := api.mesh[len(api.mesh)-1]["networks"].([]any)[0].(map[string]any)["network"].(map[string]any)
	if layer["native_keys"] == nil {
		t.Fatalf("network layer = %v", layer)
	}
}

// dns.resolver_address goes only to a kernel that lists mesh_resolver_address:
// an older one rejects the unknown field, and with it every network.
func TestMeshDNSResolverAddressNeedsTheKernelFeature(t *testing.T) {
	network := testMeshNetwork()
	network.DNS = json.RawMessage(`{"enabled":true,"suffix":"mesh.internal","resolver_address":"10.150.255.254"}`)
	for _, test := range []struct {
		features []string
		resolver bool
	}{
		{[]string{meshFeature, meshNativeKeysFeature, meshDNSFeature}, false},
		{[]string{meshFeature, meshNativeKeysFeature, meshDNSFeature, meshResolverAddressFeature}, true},
		// The resolver needs the dns section itself.
		{[]string{meshFeature, meshNativeKeysFeature, meshResolverAddressFeature}, false},
	} {
		api, server := newFakeAPI(t)
		api.features = test.features
		core := externalCore(t, server)
		err := core.ApplyMesh([]panel.MeshNetwork{network})
		_ = core.Close()
		if err != nil {
			t.Fatal(err)
		}
		config := api.mesh[0]["networks"].([]any)[0].(map[string]any)
		dns, _ := config["dns"].(map[string]any)
		if !slices.Contains(test.features, meshDNSFeature) {
			if dns != nil {
				t.Fatalf("%v: dns = %v", test.features, dns)
			}
			continue
		}
		_, resolver := dns["resolver_address"]
		if resolver != test.resolver || dns["enabled"] != true || dns["suffix"] != "mesh.internal" {
			t.Fatalf("%v: dns = %v", test.features, dns)
		}
	}

	// A restarted, updated kernel gets the resolver on replay.
	api, server := newFakeAPI(t)
	api.features = []string{meshFeature, meshNativeKeysFeature, meshDNSFeature}
	core := externalCore(t, server)
	t.Cleanup(func() { _ = core.Close() })
	if err := core.ApplyMesh([]panel.MeshNetwork{network}); err != nil {
		t.Fatal(err)
	}
	api.features = append(api.features, meshResolverAddressFeature)
	if err := core.client.status(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := core.replay(); err != nil {
		t.Fatal(err)
	}
	dns := api.mesh[len(api.mesh)-1]["networks"].([]any)[0].(map[string]any)["dns"].(map[string]any)
	if dns["resolver_address"] != "10.150.255.254" {
		t.Fatalf("replayed dns = %v", dns)
	}
}

func TestMeshDNSKeepsWhatIsNotAnObject(t *testing.T) {
	for _, raw := range []string{`{"enabled":true}`, `[1]`, `"x"`} {
		if got := meshDNS(json.RawMessage(raw), false); string(got) != raw {
			t.Fatalf("%s -> %s", raw, got)
		}
	}
	if got := meshDNS(json.RawMessage(`{"enabled":true,"resolver_address":"10.0.0.1"}`), false); string(got) != `{"enabled":true}` {
		t.Fatalf("dropped = %s", got)
	}
}

// external_bridge goes only to a kernel that lists mesh_external_bridge,
// on replay too; the digest of the bridge the kernel applies
// (externalBridge) goes on as it gives it.
func TestMeshExternalBridge(t *testing.T) {
	network := testMeshNetwork()
	network.ExternalBridge = json.RawMessage(`{"interface":"ext0","routes":["100.100.1.2/32"],"allow":["10.150.128.7/32"]}`)
	api, server := newFakeAPI(t)
	api.features = []string{meshFeature, meshNativeKeysFeature}
	core := externalCore(t, server)
	t.Cleanup(func() { _ = core.Close() })
	if err := core.ApplyMesh([]panel.MeshNetwork{network}); err != nil {
		t.Fatal(err)
	}
	config := api.mesh[0]["networks"].([]any)[0].(map[string]any)
	if _, ok := config["external_bridge"]; ok {
		t.Fatalf("external_bridge sent to a kernel without it: %v", config)
	}
	api.features = append(api.features, meshExternalBridgeFeature)
	if err := core.client.status(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := core.replay(); err != nil {
		t.Fatal(err)
	}
	config = api.mesh[len(api.mesh)-1]["networks"].([]any)[0].(map[string]any)
	bridge, _ := config["external_bridge"].(map[string]any)
	if bridge["interface"] != "ext0" || len(bridge["allow"].([]any)) != 1 {
		t.Fatalf("external_bridge = %v", config["external_bridge"])
	}

	// No key: unknown, left out of the report.
	state, err := core.MeshStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report, _ := json.Marshal(state.Networks[0]); state.Networks[0].ExternalBridge != nil || strings.Contains(string(report), "externalBridge") {
		t.Fatalf("report = %s", report)
	}
	// An explicit null (no bridge runs) goes on as null.
	api.meshBridge = json.RawMessage(`null`)
	state, err = core.MeshStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report, _ := json.Marshal(state.Networks[0]); !strings.Contains(string(report), `"externalBridge":null`) {
		t.Fatalf("report = %s", report)
	}
	// The kernel's digest goes on as it gives it, an empty list's too.
	digest := `{"allowCount":0,"allowDigest":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",` +
		`"appliedAt":"2026-11-25T21:00:00Z","routesDigest":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`
	api.meshBridge = json.RawMessage(digest)
	state, err = core.MeshStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := string(state.Networks[0].ExternalBridge); got != digest {
		t.Fatalf("externalBridge = %s", got)
	}
	report, _ := json.Marshal(state.Networks[0])
	if !strings.Contains(string(report), `"externalBridge":`+digest) {
		t.Fatalf("report = %s", report)
	}
}

// routing.paths goes as it is only to a kernel that lists mesh_paths; any
// other kernel gets an empty list, and a routing without paths, or one that
// is not an object, is left alone.
func TestMeshRoutingPaths(t *testing.T) {
	routingOf := func(routing string, paths bool) string {
		network := testMeshNetwork()
		network.Routing = json.RawMessage(routing)
		body := meshBody([]panel.MeshNetwork{network}, meshSections{nativeKeys: true, paths: paths})["networks"].([]map[string]any)[0]
		out, err := json.Marshal(body["routing"])
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	with := `{"policy":"latency","paths":[{"to_peer":"10.150.0.9","via":["10.150.0.2"]}]}`
	if got := routingOf(with, true); got != with {
		t.Fatalf("with mesh_paths: %s", got)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(routingOf(with, false)), &decoded); err != nil {
		t.Fatal(err)
	}
	list, ok := decoded["paths"].([]any)
	if decoded["policy"] != "latency" || !ok || len(list) != 0 {
		t.Fatalf("without mesh_paths: %v", decoded)
	}
	for _, same := range []string{`{"policy":"latency"}`, `{"policy":"latency","paths":[]}`, `"latency"`, `[1]`,
		`{"policy":"latency","paths":null}`, `{"policy":"latency","paths":{"to_peer":"10.150.0.9"}}`, `{"paths":"x"}`} {
		if got := routingOf(same, false); got != same {
			t.Fatalf("%s changed to %s", same, got)
		}
	}
}

// mesh_paths is taken from the features, and only together with mesh.
func TestMeshPathsFeature(t *testing.T) {
	api, server := newFakeAPI(t)
	api.features = []string{meshFeature, meshNativeKeysFeature}
	core := externalCore(t, server)
	t.Cleanup(func() { _ = core.Close() })
	if core.MeshPathsSupported() {
		t.Fatal("mesh_paths without the feature")
	}
	api.features = append(api.features, meshPathsFeature)
	if err := core.client.status(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !core.MeshPathsSupported() {
		t.Fatal("mesh_paths not taken")
	}
	api.features = []string{meshPathsFeature}
	if err := core.client.status(context.Background()); err != nil {
		t.Fatal(err)
	}
	if core.MeshPathsSupported() {
		t.Fatal("mesh_paths without mesh")
	}
}

// The top-level region goes in the PUT body, and on replay, only to a kernel
// that lists mesh_region_probe.
func TestMeshRegionGoesOnlyToAKernelThatTakesIt(t *testing.T) {
	api, server := newFakeAPI(t)
	api.features = []string{meshFeature, meshNativeKeysFeature}
	core := externalCore(t, server)
	t.Cleanup(func() { _ = core.Close() })
	region := json.RawMessage(`{"current":"cn","basis":"admin","directory":null}`)
	core.SetMeshRegion(region)
	if err := core.ApplyMesh([]panel.MeshNetwork{testMeshNetwork()}); err != nil {
		t.Fatal(err)
	}
	if _, ok := api.mesh[len(api.mesh)-1]["region"]; ok {
		t.Fatalf("region sent to a kernel without the feature: %v", api.mesh[len(api.mesh)-1])
	}

	api.features = append(api.features, meshRegionProbeFeature)
	if err := core.client.status(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !core.MeshRegionProbeSupported() {
		t.Fatal("mesh_region_probe not taken")
	}
	if err := core.replay(); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(api.mesh[len(api.mesh)-1]["region"])
	if string(got) != `{"basis":"admin","current":"cn","directory":null}` {
		t.Fatalf("replayed region = %s", got)
	}

	// Null is the same as none; a kernel that loses the feature gets none.
	core.SetMeshRegion(json.RawMessage(`null`))
	if err := core.ApplyMesh([]panel.MeshNetwork{testMeshNetwork()}); err != nil {
		t.Fatal(err)
	}
	if _, ok := api.mesh[len(api.mesh)-1]["region"]; ok {
		t.Fatal("null region sent")
	}
	core.SetMeshRegion(region)
	api.features = []string{meshFeature, meshNativeKeysFeature}
	if err := core.client.status(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := core.replay(); err != nil {
		t.Fatal(err)
	}
	if _, ok := api.mesh[len(api.mesh)-1]["region"]; ok {
		t.Fatal("region replayed to a kernel without the feature")
	}
}

// region_probe is passed on raw (null or an object) from a kernel that lists
// mesh_region_probe, and left out otherwise.
func TestMeshRegionProbeStatus(t *testing.T) {
	api, server := newFakeAPI(t)
	api.features = []string{meshFeature}
	core := externalCore(t, server)
	t.Cleanup(func() { _ = core.Close() })
	object := `{"measured_at":null,"next_at":"2026-11-26T09:04:12Z","regions":[{"region":"eu","rtt_ms":18.4}],"unreachable":[],"rejected":0,"suggestion":null}`
	api.meshProbe = json.RawMessage(object)
	state, err := core.MeshStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.RegionProbe != nil {
		t.Fatalf("region_probe without the feature: %s", state.RegionProbe)
	}

	api.features = append(api.features, meshRegionProbeFeature)
	if err := core.client.status(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{object, `null`} {
		api.meshProbe = json.RawMessage(want)
		state, err = core.MeshStatus(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if string(state.RegionProbe) != want {
			t.Fatalf("region_probe = %s, want %s", state.RegionProbe, want)
		}
		report, _ := json.Marshal(panel.MeshStatus{RegionProbe: state.RegionProbe})
		if !strings.Contains(string(report), `"region_probe":`+want) {
			t.Fatalf("report = %s", report)
		}
	}
	// A value that is neither is left out; so is a missing one.
	for _, bad := range []any{json.RawMessage(`"x"`), json.RawMessage(`[1]`), nil} {
		api.meshProbe = bad
		state, err = core.MeshStatus(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if state.RegionProbe != nil {
			t.Fatalf("region_probe = %s", state.RegionProbe)
		}
	}
}
