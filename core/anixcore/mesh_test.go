package anixcore

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	vCore "github.com/AnixOps/anix-agent/v5/core"
)

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

	status, err := core.MeshStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
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
