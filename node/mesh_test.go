package node

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	agentapi "github.com/AnixOps/anix-agent/v5/api/agent"
	"github.com/AnixOps/anix-agent/v5/api/panel"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	"github.com/AnixOps/anix-agent/v5/mesh"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
)

// fakeMesh is a kernel's mesh: supported or not, recording what it runs,
// with an instance id and the region requests it holds.
type fakeMesh struct {
	supported  bool
	applied    [][]panel.MeshNetwork
	instanceID string
	requests   []panel.MeshRegionRequest
	done       []string
}

func (f *fakeMesh) MeshSupported() bool { return f.supported }

func (f *fakeMesh) ApplyMesh(networks []panel.MeshNetwork) error {
	if len(networks) > 0 && !f.supported {
		return vCore.ErrMeshUnsupported
	}
	f.applied = append(f.applied, networks)
	return nil
}

func (f *fakeMesh) MeshStatus(context.Context) (panel.MeshState, error) {
	state := panel.MeshState{InstanceID: f.instanceID, RegionRequests: f.requests}
	if len(f.applied) > 0 {
		for _, network := range f.applied[len(f.applied)-1] {
			state.Networks = append(state.Networks, panel.MeshNetworkStatus{ID: network.ID, Running: true, Peers: []panel.MeshPeerStatus{}})
		}
	}
	return state, nil
}

func (f *fakeMesh) DoneMeshRegionRequest(_ context.Context, id string) error {
	f.done = append(f.done, id)
	kept := f.requests[:0]
	for _, request := range f.requests {
		if request.ID != id {
			kept = append(kept, request)
		}
	}
	f.requests = kept
	return nil
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
	status, _, ok := c.status(context.Background())
	if !ok || len(status.Networks) != 1 || !status.Networks[0].Running || status.Takeover != nil {
		t.Fatalf("status = %+v", status)
	}
	// The same member again changes nothing; none stops the networks.
	if err := c.apply(meshSnapshot(meshMember)); err != nil || len(kernel.applied) != 1 {
		t.Fatalf("same member: %v, applied %d", err, len(kernel.applied))
	}
	if err := c.apply(meshSnapshot("")); err != nil || len(kernel.applied) != 2 || kernel.applied[1] != nil {
		t.Fatalf("no member: %v, applied %+v", err, kernel.applied)
	}
	// A node in no region reports nothing: Control refuses it (not_assigned).
	if status, _, ok := c.status(context.Background()); ok || len(status.Networks) != 0 {
		t.Fatalf("status = %+v, ok %v", status, ok)
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
	if status, _, _ := c.status(context.Background()); status.Networks[0].Running || status.Networks[0].Alerts[0].Code != panel.MeshAlertUnsupported || status.InstanceID != "" {
		t.Fatalf("status = %+v", status)
	}

	// An updated kernel: the networks still wait for the existing program.
	// It answers its instance id even while they wait.
	kernel.supported, kernel.instanceID = true, "2f6d7c1e-0b8a-4c55-9e0e-6a1f3b9d2c10"
	c.retry()
	status, _, _ := c.status(context.Background())
	if len(kernel.applied) != 0 || status.Networks[0].Alerts[0].Code != panel.MeshAlertTakeoverPending || !status.Takeover.Found ||
		status.InstanceID != kernel.instanceID {
		t.Fatalf("applied %+v, status %+v", kernel.applied, status)
	}

	// Taken over: the next retry starts them.
	active["old.service"] = false
	c.retry()
	if status, _, _ := c.status(context.Background()); len(kernel.applied) != 1 || !status.Networks[0].Running {
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

func TestMeshReportsTheStatusThenTheRegionRequests(t *testing.T) {
	kernel := &fakeMesh{supported: true, instanceID: "node-a", requests: []panel.MeshRegionRequest{
		{ID: "r1", Network: "cn", Region: "eu", Reason: "  " + strings.Repeat("迁", panel.MeshRegionRequestReasonMax+10)},
		{ID: "r2", Region: "EU!"},
	}}
	c := testMeshComponent(t, kernel, nil)
	var sent []*agentv1pb.PackageReport
	c.sendReport = func(report *agentv1pb.PackageReport) error {
		sent = append(sent, report)
		return nil
	}
	c.negotiated = true

	// In no region: nothing goes and the kernel keeps the requests.
	c.report()
	if len(sent) != 0 || len(kernel.done) != 0 {
		t.Fatalf("sent %d reports, done %v", len(sent), kernel.done)
	}

	if err := c.apply(meshSnapshot(meshMember)); err != nil {
		t.Fatal(err)
	}
	c.report()
	if len(sent) != 2 {
		t.Fatalf("sent %d reports", len(sent))
	}
	if sent[0].GetKind() != agentapi.MeshStatusKind || sent[0].GetVersion() != agentapi.MeshStatusVersion ||
		!strings.Contains(string(sent[0].GetPayloadJson()), `"instance_id":"node-a"`) {
		t.Fatalf("status = %s %s", sent[0].GetKind(), sent[0].GetPayloadJson())
	}
	var request panel.MeshRegionRequestReport
	if err := json.Unmarshal(sent[1].GetPayloadJson(), &request); err != nil {
		t.Fatal(err)
	}
	if sent[1].GetPluginId() != agentapi.MeshPluginID || sent[1].GetKind() != agentapi.MeshRegionRequestKind ||
		sent[1].GetVersion() != agentapi.MeshRegionRequestVersion || request.Region != "eu" ||
		len([]rune(request.Reason)) != panel.MeshRegionRequestReasonMax || strings.HasPrefix(request.Reason, " ") {
		t.Fatalf("region request = %s %s", sent[1].GetKind(), sent[1].GetPayloadJson())
	}
	// Both leave the kernel: r1 sent, r2 never takeable.
	if strings.Join(kernel.done, ",") != "r1,r2" {
		t.Fatalf("done = %v", kernel.done)
	}

	// A session that is gone keeps the requests in the kernel.
	kernel.requests = []panel.MeshRegionRequest{{ID: "r3", Region: "na"}}
	c.sendReport = func(report *agentv1pb.PackageReport) error {
		if report.GetKind() == agentapi.MeshRegionRequestKind {
			return agentapi.ErrSessionGone
		}
		return nil
	}
	c.report()
	if len(kernel.requests) != 1 || len(kernel.done) != 2 {
		t.Fatalf("requests %v, done %v", kernel.requests, kernel.done)
	}
}
