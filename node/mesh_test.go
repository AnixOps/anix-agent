package node

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	agentapi "github.com/AnixOps/anix-agent/v5/api/agent"
	"github.com/AnixOps/anix-agent/v5/api/panel"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	"github.com/AnixOps/anix-agent/v5/mesh"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
)

// fakeMesh is a kernel's mesh: supported or not, recording what it runs.
type fakeMesh struct {
	supported bool
	applied   [][]panel.MeshNetwork
}

func (f *fakeMesh) MeshSupported() bool { return f.supported }

func (f *fakeMesh) ApplyMesh(networks []panel.MeshNetwork) error {
	if len(networks) > 0 && !f.supported {
		return vCore.ErrMeshUnsupported
	}
	f.applied = append(f.applied, networks)
	return nil
}

func (f *fakeMesh) MeshStatus(context.Context) ([]panel.MeshNetworkStatus, error) {
	last := f.applied[len(f.applied)-1]
	out := make([]panel.MeshNetworkStatus, 0, len(last))
	for _, network := range last {
		out = append(out, panel.MeshNetworkStatus{ID: network.ID, Running: true, Peers: []panel.MeshPeerStatus{}})
	}
	return out, nil
}

func meshSnapshot(member string) *agentv1pb.ConfigSnapshot {
	return &agentv1pb.ConfigSnapshot{ConfigJson: []byte(`{"nodes":[]` + member + `}`)}
}

const meshMember = `,"mesh":{"networks":[{"id":"cn","name":"n","secret":"s","secure_mode":true,"address":"10.150.0.5/16"}],` +
	`"takeover":{"service_names":["old.service"]}}`

func testMeshComponent(t *testing.T, kernel *fakeMesh, active map[string]bool) *meshComponent {
	t.Helper()
	run := func(args ...string) error {
		if args[0] == "is-active" && active[args[len(args)-1]] {
			return nil
		}
		return context.Canceled
	}
	return &meshComponent{
		core:     kernel,
		takeover: &mesh.Takeover{StatePath: filepath.Join(t.TempDir(), "takeover.json"), Proc: t.TempDir(), Run: run},
		wake:     make(chan struct{}, 1),
	}
}

func TestMeshRunsTheMemberOnTheKernel(t *testing.T) {
	kernel := &fakeMesh{supported: true}
	c := testMeshComponent(t, kernel, nil)
	if err := c.apply(meshSnapshot(meshMember)); err != nil {
		t.Fatal(err)
	}
	if len(kernel.applied) != 1 || kernel.applied[0][0].ID != "cn" {
		t.Fatalf("applied = %+v", kernel.applied)
	}
	status := c.status(context.Background())
	if len(status.Networks) != 1 || !status.Networks[0].Running || status.Takeover != nil {
		t.Fatalf("status = %+v", status)
	}
	// The same member again changes nothing; none stops the networks.
	if err := c.apply(meshSnapshot(meshMember)); err != nil || len(kernel.applied) != 1 {
		t.Fatalf("same member: %v, applied %d", err, len(kernel.applied))
	}
	if err := c.apply(meshSnapshot("")); err != nil || len(kernel.applied) != 2 || kernel.applied[1] != nil {
		t.Fatalf("no member: %v, applied %+v", err, kernel.applied)
	}
	if status := c.status(context.Background()); len(status.Networks) != 0 {
		t.Fatalf("status = %+v", status)
	}
}

func TestMeshWaitsForTheKernelAndTheTakeover(t *testing.T) {
	kernel := &fakeMesh{}
	active := map[string]bool{"old.service": true}
	c := testMeshComponent(t, kernel, active)

	// A kernel without the mesh fails nothing; the report says so.
	if err := c.apply(meshSnapshot(meshMember)); err != nil {
		t.Fatal(err)
	}
	if status := c.status(context.Background()); status.Networks[0].Running || status.Networks[0].Alerts[0].Code != panel.MeshAlertUnsupported {
		t.Fatalf("status = %+v", status)
	}

	// An updated kernel: the networks still wait for the existing program.
	kernel.supported = true
	c.retry()
	status := c.status(context.Background())
	if len(kernel.applied) != 0 || status.Networks[0].Alerts[0].Code != panel.MeshAlertTakeoverPending || !status.Takeover.Found {
		t.Fatalf("applied %+v, status %+v", kernel.applied, status)
	}

	// Taken over: the next retry starts them.
	active["old.service"] = false
	c.retry()
	if len(kernel.applied) != 1 || !c.status(context.Background()).Networks[0].Running {
		t.Fatalf("applied = %+v", kernel.applied)
	}
}

func TestMeshRefusesAnInvalidMember(t *testing.T) {
	c := testMeshComponent(t, &fakeMesh{supported: true}, nil)
	err := c.apply(meshSnapshot(`,"mesh":{"networks":[{"id":"cn"}]}`))
	if !errors.Is(err, agentapi.ErrConfigInvalid) {
		t.Fatalf("err = %v", err)
	}
}
