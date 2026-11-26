package node

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentapi "github.com/AnixOps/anix-agent/v5/api/agent"
	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/common/layout"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	"github.com/AnixOps/anix-agent/v5/mesh"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
)

// fakeMesh is a kernel's mesh: supported or not, recording what it runs,
// with an instance id and the region requests it holds. Like the kernel it
// has a static key only for a network it was given (keys, by name), and
// answers failures (by id) for networks it holds back.
type fakeMesh struct {
	supported    bool
	noNativeKeys bool
	// externalBridge: the kernel takes external_bridge.
	externalBridge bool
	// paths: the kernel applies routing.paths.
	paths bool
	// pathState is the networks' paths (by id), raw.
	pathState  map[string]json.RawMessage
	applied    [][]panel.MeshNetwork
	instanceID string
	requests   []panel.MeshRegionRequest
	keys       map[string]string
	failures   map[string]*panel.MeshFailure
	statusErr  error
	// bridges are the networks' externalBridge (by id), raw.
	bridges map[string]json.RawMessage
	// alerts are the networks' kernel alerts (by id); nodeAlerts the
	// kernel's node-level ones.
	alerts     map[string][]panel.MeshAlert
	nodeAlerts []panel.MeshAlert
	done       []string
	// regionProbe: the kernel lists mesh_region_probe; probe is its
	// region_probe, region the region it was given last.
	regionProbe bool
	probe       json.RawMessage
	region      json.RawMessage
}

func (f *fakeMesh) MeshSupported() bool { return f.supported }

func (f *fakeMesh) MeshNativeKeysSupported() bool { return f.supported && !f.noNativeKeys }

func (f *fakeMesh) MeshExternalBridgeSupported() bool { return f.supported && f.externalBridge }

func (f *fakeMesh) MeshPathsSupported() bool { return f.supported && f.paths }

func (f *fakeMesh) MeshRegionProbeSupported() bool { return f.supported && f.regionProbe }

func (f *fakeMesh) SetMeshRegion(region json.RawMessage) { f.region = region }

func (f *fakeMesh) ApplyMesh(networks []panel.MeshNetwork) error {
	if len(networks) > 0 && !f.supported {
		return vCore.ErrMeshUnsupported
	}
	f.applied = append(f.applied, networks)
	return nil
}

func (f *fakeMesh) MeshStatus(context.Context) (panel.MeshState, error) {
	if f.statusErr != nil {
		return panel.MeshState{}, f.statusErr
	}
	state := panel.MeshState{InstanceID: f.instanceID, RegionRequests: f.requests, Alerts: f.nodeAlerts, RegionProbe: f.probe}
	if len(f.applied) > 0 {
		for _, network := range f.applied[len(f.applied)-1] {
			entry := panel.MeshNetworkStatus{ID: network.ID, Running: true, Peers: []panel.MeshPeerStatus{}}
			entry.ExternalBridge = f.bridges[network.ID]
			entry.Alerts = f.alerts[network.ID]
			entry.Paths = f.pathState[network.ID]
			if failure := f.failures[network.ID]; failure != nil {
				entry.Running, entry.Failure = false, failure
			}
			state.Networks = append(state.Networks, entry)
			if key, ok := f.keys[network.Name]; ok {
				state.StaticKeys = append(state.StaticKeys, panel.MeshStaticKey{Network: network.Name, StaticKey: key})
			}
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
		core:        kernel,
		takeover:    &mesh.Takeover{StatePath: filepath.Join(t.TempDir(), "takeover.json"), Proc: t.TempDir(), Run: run},
		bridgedPath: filepath.Join(t.TempDir(), "bridged.json"),
		wake:        make(chan struct{}, 1),
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

const (
	testKeyA = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	testKeyB = "HxQdHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA="
)

func TestMeshReportsTheStaticKeyOnceTheKernelHasTheNetwork(t *testing.T) {
	kernel := &fakeMesh{supported: true, keys: map[string]string{"n": testKeyA}}
	active := map[string]bool{"old.service": true}
	c := testMeshComponent(t, kernel, active)
	if err := c.apply(meshSnapshot(meshMember)); err != nil {
		t.Fatal(err)
	}
	// First takeover: the kernel never had the network, so it has no key.
	status, _, ok := c.status(context.Background())
	if !ok || status.Networks[0].StaticKey != "" || status.Networks[0].Alerts[0].Code != panel.MeshAlertTakeoverPending {
		t.Fatalf("status = %+v", status)
	}
	// Taken over: the network goes to the kernel, which makes the key.
	active["old.service"] = false
	c.retry()
	status, _, _ = c.status(context.Background())
	if !status.Networks[0].Running || status.Networks[0].StaticKey != testKeyA {
		t.Fatalf("status = %+v", status)
	}
	payload, _ := json.Marshal(status)
	if !strings.Contains(string(payload), `"static_key":"`+testKeyA+`"`) {
		t.Fatalf("payload = %s", payload)
	}
	// The existing program back: the kernel keeps the network it has, and
	// its key still goes.
	active["old.service"] = true
	c.member = nil
	if err := c.apply(meshSnapshot(meshMember)); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := c.status(context.Background()); status.Networks[0].StaticKey != testKeyA ||
		status.Networks[0].Alerts[0].Code != panel.MeshAlertTakeoverPending {
		t.Fatalf("status = %+v", status)
	}

	// A status the kernel cannot answer carries no key.
	kernel.statusErr = errors.New("down")
	if status, _, _ := c.status(context.Background()); status.Networks[0].StaticKey != "" {
		t.Fatalf("status = %+v", status)
	}
}

func TestMeshStaticKeysGoByNetworkName(t *testing.T) {
	kernel := &fakeMesh{supported: true, keys: map[string]string{"mesh-cn": testKeyA, "mesh-eu": testKeyB}}
	c := testMeshComponent(t, kernel, nil)
	member := `,"mesh":{"networks":[` +
		`{"id":"cn","name":"mesh-cn","secret":"s","secure_mode":true,"address":"10.150.0.5/16"},` +
		`{"id":"eu","name":"mesh-eu","secret":"s","secure_mode":true,"address":"10.151.0.5/16"}]}`
	if err := c.apply(meshSnapshot(member)); err != nil {
		t.Fatal(err)
	}
	status, _, _ := c.status(context.Background())
	if status.Networks[0].StaticKey != testKeyA || status.Networks[1].StaticKey != testKeyB {
		t.Fatalf("status = %+v", status)
	}
	// Moved to another region: the new network's name, never the old key.
	moved := `,"mesh":{"networks":[{"id":"na","name":"mesh-na","secret":"s","secure_mode":true,"address":"10.152.0.5/16"}]}`
	if err := c.apply(meshSnapshot(moved)); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := c.status(context.Background()); len(status.Networks) != 1 || status.Networks[0].StaticKey != "" {
		t.Fatalf("status = %+v", status)
	}
}

func TestMeshReportsWhyTheKernelHoldsANetwork(t *testing.T) {
	kernel := &fakeMesh{supported: true, keys: map[string]string{"n": testKeyA},
		failures: map[string]*panel.MeshFailure{"cn": {Code: "native_keys_pending", Detail: "self_missing"}}}
	c := testMeshComponent(t, kernel, nil)
	if err := c.apply(meshSnapshot(meshMember)); err != nil {
		t.Fatal(err)
	}
	status, _, _ := c.status(context.Background())
	network := status.Networks[0]
	if network.Running || network.StaticKey != testKeyA || network.Failure != nil || len(network.Alerts) != 1 ||
		network.Alerts[0] != (panel.MeshAlert{Code: "native_keys_pending", Detail: "self_missing"}) {
		t.Fatalf("status = %+v", network)
	}
	if payload, _ := json.Marshal(status); strings.Contains(string(payload), `"failure"`) {
		t.Fatalf("payload = %s", payload)
	}
}

func TestMeshHoldsManagedNetworksFromAKernelWithoutNativeKeys(t *testing.T) {
	kernel := &fakeMesh{supported: true, noNativeKeys: true}
	c := testMeshComponent(t, kernel, nil)
	member := `,"mesh":{"networks":[` +
		`{"id":"cn","name":"mesh-cn","secret":"s","secure_mode":true,"address":"10.150.0.5/16","native_keys":[]},` +
		`{"id":"old","name":"old","kind":"legacy","secret":"s","address":"10.99.0.5/24"}]}`
	if err := c.apply(meshSnapshot(member)); err != nil {
		t.Fatal(err)
	}
	if len(kernel.applied) != 1 || len(kernel.applied[0]) != 1 || kernel.applied[0][0].ID != "old" {
		t.Fatalf("applied = %+v", kernel.applied)
	}
	status, _, _ := c.status(context.Background())
	if status.Networks[0].Running || status.Networks[0].Alerts[0].Code != panel.MeshAlertNativeKeysUnsupported || !status.Networks[1].Running {
		t.Fatalf("status = %+v", status)
	}
	// An updated kernel: the next retry gives it the managed network too.
	kernel.noNativeKeys = false
	c.retry()
	if last := kernel.applied[len(kernel.applied)-1]; len(last) != 2 {
		t.Fatalf("applied = %+v", kernel.applied)
	}
	if status, _, _ := c.status(context.Background()); !status.Networks[0].Running || len(status.Networks[0].Alerts) != 0 {
		t.Fatalf("status = %+v", status)
	}
}

// A kernel restarted without native_keys (a downgrade) is not given the
// managed network again on replay: the report says so, and the Agent does
// not reapply every minute.
func TestMeshReportsAManagedNetworkAKernelDowngradeDropped(t *testing.T) {
	kernel := &fakeMesh{supported: true}
	c := testMeshComponent(t, kernel, nil)
	member := `,"mesh":{"networks":[` +
		`{"id":"cn","name":"mesh-cn","secret":"s","secure_mode":true,"address":"10.150.0.5/16","native_keys":[]},` +
		`{"id":"old","name":"old","kind":"legacy","secret":"s","address":"10.99.0.5/24"}]}`
	if err := c.apply(meshSnapshot(member)); err != nil {
		t.Fatal(err)
	}
	if len(kernel.applied) != 1 || len(kernel.applied[0]) != 2 {
		t.Fatalf("applied = %+v", kernel.applied)
	}
	// The older kernel restarts; replay gives it only the legacy network.
	kernel.noNativeKeys = true
	kernel.applied = append(kernel.applied, kernel.applied[0][1:])
	status, _, _ := c.status(context.Background())
	if status.Networks[0].Running || len(status.Networks[0].Alerts) != 1 || status.Networks[0].Alerts[0].Code != panel.MeshAlertNativeKeysUnsupported || !status.Networks[1].Running {
		t.Fatalf("status = %+v", status)
	}
	c.retry()
	if len(kernel.applied) != 2 {
		t.Fatalf("applied = %+v", kernel.applied)
	}
}

// A network of an unknown kind is held back with invalid_kind, the others
// run, and retry does not reapply for it.
func TestMeshHoldsANetworkOfAnUnknownKind(t *testing.T) {
	kernel := &fakeMesh{supported: true}
	c := testMeshComponent(t, kernel, nil)
	member := `,"mesh":{"networks":[` +
		`{"id":"cn","name":"mesh-cn","secret":"s","secure_mode":true,"address":"10.150.0.5/16","native_keys":[]},` +
		`{"id":"odd","name":"odd","kind":"open","secret":"s","address":"10.98.0.5/24"}]}`
	if err := c.apply(meshSnapshot(member)); err != nil {
		t.Fatal(err)
	}
	if len(kernel.applied) != 1 || len(kernel.applied[0]) != 1 || kernel.applied[0][0].ID != "cn" {
		t.Fatalf("applied = %+v", kernel.applied)
	}
	status, _, _ := c.status(context.Background())
	if !status.Networks[0].Running || status.Networks[1].Running || len(status.Networks[1].Alerts) != 1 || status.Networks[1].Alerts[0].Code != panel.MeshAlertInvalidKind {
		t.Fatalf("status = %+v", status)
	}
	c.retry()
	if len(kernel.applied) != 1 {
		t.Fatalf("applied = %+v", kernel.applied)
	}
}

// The kernel's externalBridge goes on for a network it runs, an explicit
// null too; while the Agent does not know the kernel's bridge (network
// held, apply failed, kernel unreadable) the key is left out, never sent
// as null.
func TestMeshExternalBridgeOnlyWhenKnown(t *testing.T) {
	kernel := &fakeMesh{supported: true, externalBridge: true, bridges: map[string]json.RawMessage{
		"cn": json.RawMessage(`{"allowCount":1,"allowDigest":"d","appliedAt":"2026-11-25T21:00:00Z","routesDigest":"r"}`),
		"eu": json.RawMessage(`null`),
	}}
	c := testMeshComponent(t, kernel, nil)
	member := `,"mesh":{"networks":[` +
		`{"id":"cn","name":"mesh-cn","secret":"s","secure_mode":true,"address":"10.150.0.5/16","native_keys":[]},` +
		`{"id":"eu","name":"mesh-eu","secret":"s","secure_mode":true,"address":"10.151.0.5/16","native_keys":[]},` +
		`{"id":"odd","name":"odd","kind":"open","secret":"s","address":"10.98.0.5/24"}]}`
	if err := c.apply(meshSnapshot(member)); err != nil {
		t.Fatal(err)
	}
	bridges := func() []string {
		status, _, _ := c.status(context.Background())
		var out []string
		for _, network := range status.Networks {
			entry, _ := json.Marshal(network)
			_, after, found := strings.Cut(string(entry), `"externalBridge":`)
			if !found {
				out = append(out, "-")
				continue
			}
			out = append(out, after[:4])
		}
		return out
	}
	if got := strings.Join(bridges(), " "); got != "{\"al null -" {
		t.Fatalf("bridges = %s", got)
	}
	kernel.statusErr = errors.New("down")
	if got := strings.Join(bridges(), " "); got != "- - -" {
		t.Fatalf("kernel unreadable: bridges = %s", got)
	}
	kernel.statusErr = nil
	c.mu.Lock()
	c.err = errors.New("apply failed")
	c.mu.Unlock()
	if got := strings.Join(bridges(), " "); got != "- - -" {
		t.Fatalf("apply failed: bridges = %s", got)
	}
}

// A network with a bridge on a kernel that does not take external_bridge
// runs without it and reports external_bridge_unsupported; once the
// kernel takes it, the alert goes.
func TestMeshAlertsAnExternalBridgeTheKernelDoesNotTake(t *testing.T) {
	kernel := &fakeMesh{supported: true}
	c := testMeshComponent(t, kernel, nil)
	member := `,"mesh":{"networks":[` +
		`{"id":"cn","name":"mesh-cn","secret":"s","secure_mode":true,"address":"10.150.0.5/16","native_keys":[],` +
		`"external_bridge":{"interface":"ext0","routes":["100.100.1.2/32"],"allow":[]}},` +
		`{"id":"eu","name":"mesh-eu","secret":"s","secure_mode":true,"address":"10.151.0.5/16","native_keys":[]}]}`
	if err := c.apply(meshSnapshot(member)); err != nil {
		t.Fatal(err)
	}
	status, _, _ := c.status(context.Background())
	if !status.Networks[0].Running || !hasAlert(status.Networks[0].Alerts, panel.MeshAlertExternalBridgeUnsupported) ||
		len(status.Networks[1].Alerts) != 0 {
		t.Fatalf("status = %+v", status)
	}
	kernel.externalBridge = true
	if status, _, _ := c.status(context.Background()); len(status.Networks[0].Alerts) != 0 {
		t.Fatalf("status = %+v", status)
	}
}

// A kernel that does not take external_bridge runs no bridge: every
// network reports an explicit null, the held one too, and still after the
// bridge is deleted, when Control no longer sends it and the alert stops;
// so Control can release what it held for that bridge. Unread, the key is
// left out.
func TestMeshReportsNoBridgeOnAKernelWithoutIt(t *testing.T) {
	kernel := &fakeMesh{supported: true}
	c := testMeshComponent(t, kernel, nil)
	withBridge := `,"mesh":{"networks":[` +
		`{"id":"cn","name":"mesh-cn","secret":"s","secure_mode":true,"address":"10.150.0.5/16","native_keys":[],` +
		`"external_bridge":{"interface":"ext0","routes":["100.100.1.2/32"],"allow":[]}},` +
		`{"id":"odd","name":"odd","kind":"open","secret":"s","address":"10.98.0.5/24"}]}`
	deleted := `,"mesh":{"networks":[` +
		`{"id":"cn","name":"mesh-cn","secret":"s","secure_mode":true,"address":"10.150.0.5/16","native_keys":[]},` +
		`{"id":"odd","name":"odd","kind":"open","secret":"s","address":"10.98.0.5/24"}]}`
	check := func(stage string, alert bool, want string) {
		t.Helper()
		status, _, _ := c.status(context.Background())
		if got := hasAlert(status.Networks[0].Alerts, panel.MeshAlertExternalBridgeUnsupported); got != alert {
			t.Fatalf("%s: alert = %v, status = %+v", stage, got, status)
		}
		for _, network := range status.Networks {
			entry, err := json.Marshal(network)
			if err != nil {
				t.Fatal(err)
			}
			_, after, found := strings.Cut(string(entry), `"externalBridge":`)
			got := "-"
			if found {
				got = after[:4]
			}
			if got != want {
				t.Fatalf("%s: %s externalBridge = %s, want %s", stage, network.ID, got, want)
			}
		}
	}
	if err := c.apply(meshSnapshot(withBridge)); err != nil {
		t.Fatal(err)
	}
	check("configured", true, "null")
	if err := c.apply(meshSnapshot(deleted)); err != nil {
		t.Fatal(err)
	}
	check("deleted", false, "null")
	kernel.statusErr = errors.New("down")
	check("unreadable", false, "-")
}

// A kernel that takes external_bridge but leaves externalBridge out of a
// network's status leaves it out of the report too: the Agent fills in
// null only for kernels without the feature.
func TestMeshLeavesOutABridgeTheKernelDoesNotReport(t *testing.T) {
	kernel := &fakeMesh{supported: true, externalBridge: true}
	c := testMeshComponent(t, kernel, nil)
	member := `,"mesh":{"networks":[` +
		`{"id":"cn","name":"mesh-cn","secret":"s","secure_mode":true,"address":"10.150.0.5/16","native_keys":[],` +
		`"external_bridge":{"interface":"ext0","routes":["100.100.1.2/32"],"allow":[]}},` +
		`{"id":"eu","name":"mesh-eu","secret":"s","secure_mode":true,"address":"10.151.0.5/16","native_keys":[]}]}`
	if err := c.apply(meshSnapshot(member)); err != nil {
		t.Fatal(err)
	}
	status, _, _ := c.status(context.Background())
	if len(status.Networks) != 2 {
		t.Fatalf("status = %+v", status)
	}
	for _, network := range status.Networks {
		if hasAlert(network.Alerts, panel.MeshAlertExternalBridgeUnsupported) {
			t.Fatalf("%s: unexpected alert, status = %+v", network.ID, status)
		}
		entry, err := json.Marshal(network)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(entry), `"externalBridge"`) {
			t.Fatalf("%s: externalBridge reported: %s", network.ID, entry)
		}
	}
}

// A node whose kernel applied a network's bridge and that then runs a
// kernel without external_bridge warns that the newer kernel's rules may
// remain (§15.12 item 9), also after the Agent restarts and once the
// bridge is deleted. Such a network reports neither null nor
// external_bridge_unsupported. A capable kernel reporting null, or
// removing the record, clears it.
func TestMeshWarnsOfBridgeRulesLeftByADowngrade(t *testing.T) {
	if !bridgeTracking {
		t.Skip("bridge rules exist on Linux only")
	}
	applied := json.RawMessage(`{"allowCount":0,"allowDigest":"d","appliedAt":"2026-11-25T21:00:00Z","routesDigest":"r"}`)
	kernel := &fakeMesh{supported: true, externalBridge: true, bridges: map[string]json.RawMessage{"cn": applied}}
	c := testMeshComponent(t, kernel, nil)
	withBridge := `,"mesh":{"networks":[` +
		`{"id":"cn","name":"mesh-cn","secret":"s","secure_mode":true,"address":"10.150.0.5/16","native_keys":[],` +
		`"external_bridge":{"interface":"ext0","routes":["100.100.1.2/32"],"allow":[]}},` +
		`{"id":"eu","name":"mesh-eu","secret":"s","secure_mode":true,"address":"10.151.0.5/16","native_keys":[],` +
		`"external_bridge":{"interface":"ext1","routes":["100.100.2.2/32"],"allow":[]}}]}`
	deleted := `,"mesh":{"networks":[` +
		`{"id":"cn","name":"mesh-cn","secret":"s","secure_mode":true,"address":"10.150.0.5/16","native_keys":[]},` +
		`{"id":"eu","name":"mesh-eu","secret":"s","secure_mode":true,"address":"10.151.0.5/16","native_keys":[]}]}`
	// check answers, per network, the residue alert (R), the unsupported
	// alert (U) and the externalBridge key ("-" left out).
	check := func(c *meshComponent) string {
		t.Helper()
		status, _, _ := c.status(context.Background())
		var out []string
		for _, network := range status.Networks {
			mark := network.ID + ":"
			if hasAlert(network.Alerts, panel.MeshAlertExternalBridgeDowngradeResidue) {
				mark += "R"
			}
			if hasAlert(network.Alerts, panel.MeshAlertExternalBridgeUnsupported) {
				mark += "U"
			}
			entry, err := json.Marshal(network)
			if err != nil {
				t.Fatal(err)
			}
			if _, after, found := strings.Cut(string(entry), `"externalBridge":`); found {
				mark += ":" + after[:4]
			} else {
				mark += ":-"
			}
			out = append(out, mark)
		}
		return strings.Join(out, " ")
	}
	if err := c.apply(meshSnapshot(withBridge)); err != nil {
		t.Fatal(err)
	}
	// eu was sent a bridge the kernel does not report as applied.
	if got := check(c); got != `cn::{"al eu::-` {
		t.Fatalf("capable kernel: %s", got)
	}
	// The kernel cannot be read: nothing changes.
	kernel.statusErr = errors.New("down")
	if got := check(c); got != "cn::- eu::-" {
		t.Fatalf("kernel unreadable: %s", got)
	}
	kernel.statusErr = nil
	// Downgraded: only the network whose bridge was applied warns, and its
	// bridge state stays unknown.
	kernel.externalBridge, kernel.bridges = false, nil
	if got := check(c); got != "cn:R:- eu:U:null" {
		t.Fatalf("downgraded: %s", got)
	}
	// A null the older kernel gives itself does not stand either.
	kernel.bridges = map[string]json.RawMessage{"cn": json.RawMessage("null"), "eu": json.RawMessage("null")}
	if got := check(c); got != "cn:R:- eu:U:null" {
		t.Fatalf("downgraded, kernel reports null: %s", got)
	}
	kernel.bridges = nil
	// The Agent restarts with the older kernel and the bridge is deleted.
	restarted := testMeshComponent(t, kernel, nil)
	restarted.bridgedPath = c.bridgedPath
	if err := restarted.apply(meshSnapshot(deleted)); err != nil {
		t.Fatal(err)
	}
	if got := check(restarted); got != "cn:R:- eu::null" {
		t.Fatalf("restarted, bridge deleted: %s", got)
	}
	// The operator cleared the rules and removed the record.
	if err := os.Remove(c.bridgedPath); err != nil {
		t.Fatal(err)
	}
	if got := check(restarted); got != "cn::null eu::null" {
		t.Fatalf("record removed: %s", got)
	}
	// A capable kernel applies the bridge again; one that leaves the key
	// out keeps the record, one that reports null clears it.
	kernel.externalBridge, kernel.bridges = true, map[string]json.RawMessage{"cn": applied}
	if err := c.apply(meshSnapshot(withBridge)); err != nil {
		t.Fatal(err)
	}
	check(c)
	kernel.bridges = nil
	if err := c.apply(meshSnapshot(deleted)); err != nil {
		t.Fatal(err)
	}
	check(c)
	if _, err := os.Stat(c.bridgedPath); err != nil {
		t.Fatalf("record dropped while the kernel did not report the bridge: %v", err)
	}
	kernel.bridges = map[string]json.RawMessage{"cn": json.RawMessage("null")}
	check(c)
	if _, err := os.Stat(c.bridgedPath); !os.IsNotExist(err) {
		t.Fatalf("record kept after the kernel reported no bridge: %v", err)
	}
	kernel.externalBridge, kernel.bridges = false, nil
	if got := check(c); got != "cn::null eu::null" {
		t.Fatalf("downgraded without a bridge: %s", got)
	}
}

// The record lives in the Agent's own state directory, which the Agent's
// user may write under the unit's sandbox, not in root's takeover
// directory; the write leaves no temporary file behind.
func TestMeshBridgedRecordIsTheAgentsOwn(t *testing.T) {
	path := defaultBridgedPath()
	if !strings.HasPrefix(path, layout.StateDir+string(filepath.Separator)) {
		t.Fatalf("record %s is outside %s", path, layout.StateDir)
	}
	if filepath.Dir(path) == filepath.Dir(mesh.DefaultStatePath) {
		t.Fatalf("record %s is in the takeover's directory", path)
	}
	dir := filepath.Join(t.TempDir(), "mesh")
	file := filepath.Join(dir, "bridged.json")
	if err := writeBridged(file, map[string]bool{"eu": true, "cn": true}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil || string(data) != `{"networks":["cn","eu"]}` {
		t.Fatalf("record = %s, %v", data, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("directory holds %v, %v", entries, err)
	}
	if got := readBridged(file); !got["cn"] || !got["eu"] || len(got) != 2 {
		t.Fatalf("read back %v", got)
	}
	if err := writeBridged(file, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("empty record kept: %v", err)
	}
}

// A kernel that could not take the host's bridge lock reports
// external_bridge_lock_held and does not list mesh_external_bridge.
// Another process may still run its bridge, so no network reports null
// nor external_bridge_unsupported: externalBridge stays out (§15.12 item
// 9). Once the lock is the kernel's, the usual report resumes.
func TestMeshLeavesBridgeStateUnknownWhileTheLockIsHeld(t *testing.T) {
	lock := []panel.MeshAlert{{Code: panel.MeshAlertExternalBridgeLockHeld, Detail: "another process holds the bridge lock"}}
	kernel := &fakeMesh{supported: true, alerts: map[string][]panel.MeshAlert{"cn": lock, "eu": lock}}
	c := testMeshComponent(t, kernel, nil)
	member := `,"mesh":{"networks":[` +
		`{"id":"cn","name":"mesh-cn","secret":"s","secure_mode":true,"address":"10.150.0.5/16","native_keys":[],` +
		`"external_bridge":{"interface":"ext0","routes":["100.100.1.2/32"],"allow":[]}},` +
		`{"id":"eu","name":"mesh-eu","secret":"s","secure_mode":true,"address":"10.151.0.5/16","native_keys":[]}]}`
	if err := c.apply(meshSnapshot(member)); err != nil {
		t.Fatal(err)
	}
	check := func() string {
		t.Helper()
		status, _, _ := c.status(context.Background())
		var out []string
		for _, network := range status.Networks {
			mark := network.ID + ":"
			if hasAlert(network.Alerts, panel.MeshAlertExternalBridgeLockHeld) {
				mark += "L"
			}
			if hasAlert(network.Alerts, panel.MeshAlertExternalBridgeUnsupported) {
				mark += "U"
			}
			entry, err := json.Marshal(network)
			if err != nil {
				t.Fatal(err)
			}
			if _, after, found := strings.Cut(string(entry), `"externalBridge":`); found {
				mark += ":" + after[:4]
			} else {
				mark += ":-"
			}
			out = append(out, mark)
		}
		return strings.Join(out, " ")
	}
	if got := check(); got != "cn:L:- eu:L:-" {
		t.Fatalf("lock held: %s", got)
	}
	// The alert on one network is enough.
	kernel.alerts = map[string][]panel.MeshAlert{"eu": lock}
	if got := check(); got != "cn::- eu:L:-" {
		t.Fatalf("lock held, reported on one network: %s", got)
	}
	// A null the kernel gives itself is dropped too.
	kernel.bridges = map[string]json.RawMessage{"cn": json.RawMessage("null"), "eu": json.RawMessage("null")}
	if got := check(); got != "cn::- eu:L:-" {
		t.Fatalf("lock held, kernel reports null: %s", got)
	}
	kernel.bridges = nil
	// The lock is released and the kernel still lacks the feature.
	kernel.alerts = nil
	if got := check(); got != "cn:U:null eu::null" {
		t.Fatalf("lock free: %s", got)
	}
}

// The kernel repeats external_bridge_lock_held in its node-level alerts,
// so the lock shows while the kernel runs no network: here every network
// is held back (the kernel does not take native_keys) and none reports
// null.
func TestMeshSeesTheBridgeLockWithoutNetworks(t *testing.T) {
	lock := []panel.MeshAlert{{Code: panel.MeshAlertExternalBridgeLockHeld, Detail: "another process holds the bridge lock"}}
	kernel := &fakeMesh{supported: true, noNativeKeys: true, nodeAlerts: lock}
	c := testMeshComponent(t, kernel, nil)
	member := `,"mesh":{"networks":[` +
		`{"id":"cn","name":"mesh-cn","secret":"s","secure_mode":true,"address":"10.150.0.5/16","native_keys":[]}]}`
	if err := c.apply(meshSnapshot(member)); err != nil {
		t.Fatal(err)
	}
	bridges := func() string {
		t.Helper()
		status, _, _ := c.status(context.Background())
		if len(status.Networks) == 0 {
			t.Fatalf("status = %+v", status)
		}
		var out []string
		for _, network := range status.Networks {
			if !hasAlert(network.Alerts, panel.MeshAlertNativeKeysUnsupported) {
				t.Fatalf("%s not held: %+v", network.ID, network.Alerts)
			}
			entry, err := json.Marshal(network)
			if err != nil {
				t.Fatal(err)
			}
			if _, after, found := strings.Cut(string(entry), `"externalBridge":`); found {
				out = append(out, after[:4])
			} else {
				out = append(out, "-")
			}
		}
		return strings.Join(out, " ")
	}
	if len(kernel.applied) > 0 && len(kernel.applied[len(kernel.applied)-1]) > 0 {
		t.Fatalf("kernel runs %+v", kernel.applied)
	}
	if got := bridges(); strings.Contains(got, "null") {
		t.Fatalf("lock held without networks: externalBridge = %s", got)
	}
	// Without the alert the held networks report null as before.
	kernel.nodeAlerts = nil
	if got := bridges(); strings.Contains(got, "-") {
		t.Fatalf("lock free: externalBridge = %s", got)
	}
}

// A network with custom paths on a kernel that does not take mesh_paths
// runs on default routing and reports paths_unsupported; a network without
// paths, or a kernel that takes them, raises none.
func TestMeshWarnsWhenTheKernelDoesNotTakePaths(t *testing.T) {
	kernel := &fakeMesh{supported: true}
	c := testMeshComponent(t, kernel, nil)
	member := `,"mesh":{"networks":[` +
		`{"id":"cn","name":"mesh-cn","secret":"s","secure_mode":true,"address":"10.150.0.5/16","native_keys":[],` +
		`"routing":{"policy":"latency","paths":[{"to_peer":"10.150.0.9","via":["10.150.0.2"]}]}},` +
		`{"id":"eu","name":"mesh-eu","secret":"s","secure_mode":true,"address":"10.151.0.5/16","native_keys":[],` +
		`"routing":{"policy":"latency","paths":[]}}]}`
	if err := c.apply(meshSnapshot(member)); err != nil {
		t.Fatal(err)
	}
	status, _, _ := c.status(context.Background())
	if !status.Networks[0].Running || !hasAlert(status.Networks[0].Alerts, panel.MeshAlertPathsUnsupported) ||
		len(status.Networks[1].Alerts) != 0 {
		t.Fatalf("status = %+v", status)
	}
	kernel.paths = true
	if status, _, _ := c.status(context.Background()); len(status.Networks[0].Alerts) != 0 {
		t.Fatalf("status = %+v", status)
	}
}

// A network the Agent holds back raises no paths_unsupported.
func TestMeshHeldNetworkRaisesNoPathsAlert(t *testing.T) {
	kernel := &fakeMesh{supported: true}
	c := testMeshComponent(t, kernel, nil)
	member := `,"mesh":{"networks":[` +
		`{"id":"odd","name":"odd","kind":"open","secret":"s","address":"10.98.0.5/24",` +
		`"routing":{"paths":[{"to_peer":"10.98.0.9","via":["10.98.0.2"]}]}}]}`
	if err := c.apply(meshSnapshot(member)); err != nil {
		t.Fatal(err)
	}
	status, _, _ := c.status(context.Background())
	if len(status.Networks[0].Alerts) != 1 || status.Networks[0].Alerts[0].Code != panel.MeshAlertInvalidKind {
		t.Fatalf("status = %+v", status)
	}
}

// The kernel's path state is reported as it gives it.
func TestMeshPassesPathStateThrough(t *testing.T) {
	state := json.RawMessage(`[{"id":"peer:10.150.0.9","target":{"peer":"x"},"via":["y"],"state":"active","unreachable":false,"reason":""}]`)
	kernel := &fakeMesh{supported: true, paths: true, pathState: map[string]json.RawMessage{"cn": state}}
	c := testMeshComponent(t, kernel, nil)
	member := `,"mesh":{"networks":[` +
		`{"id":"cn","name":"mesh-cn","secret":"s","secure_mode":true,"address":"10.150.0.5/16","native_keys":[]}]}`
	if err := c.apply(meshSnapshot(member)); err != nil {
		t.Fatal(err)
	}
	encoded := func() string {
		status, _, _ := c.status(context.Background())
		entry, err := json.Marshal(status.Networks[0])
		if err != nil {
			t.Fatal(err)
		}
		return string(entry)
	}
	if got := encoded(); !strings.Contains(got, `"paths":`+string(state)+`}`) && !strings.Contains(got, `"paths":`+string(state)+`,`) {
		t.Fatalf("paths: %s", got)
	}
	// A null the kernel gives goes on as null.
	kernel.pathState["cn"] = json.RawMessage(`null`)
	if got := encoded(); !strings.Contains(got, `"paths":null`) {
		t.Fatalf("null paths: %s", got)
	}
	// A kernel that cannot be read gives no path state at all.
	kernel.pathState["cn"] = state
	kernel.statusErr = errors.New("down")
	if got := encoded(); strings.Contains(got, `"paths"`) {
		t.Fatalf("kernel down: %s", got)
	}
}

func TestMeshPassesTheRegionOnAndDropsAnInvalidOne(t *testing.T) {
	networks := `{"networks":[{"id":"cn","name":"n","secret":"s","secure_mode":true,"address":"10.150.0.5/16"}]`
	kernel := &fakeMesh{supported: true, regionProbe: true}
	c := testMeshComponent(t, kernel, nil)
	object := `{"current":"cn","basis":"admin","directory":null}`
	if err := c.apply(meshSnapshot(`,"mesh":` + networks[:len(networks)-1] + `,"region":` + object + `}`)); err != nil {
		t.Fatal(err)
	}
	if string(kernel.region) != object {
		t.Fatalf("region = %s", kernel.region)
	}
	// Anything but an object or null is dropped, and the rest still runs.
	for _, bad := range []string{`"cn"`, `[1]`, `7`, `true`} {
		kernel.region = nil
		if err := c.apply(meshSnapshot(`,"mesh":` + networks[:len(networks)-1] + `,"region":` + bad + `}`)); err != nil {
			t.Fatalf("%s: %v", bad, err)
		}
		if kernel.region != nil {
			t.Fatalf("%s: region = %s", bad, kernel.region)
		}
		if status, _, ok := c.status(context.Background()); !ok || len(status.Networks) != 1 {
			t.Fatalf("%s: status = %+v", bad, status)
		}
	}
}

func TestMeshStatusCarriesTheRegionProbe(t *testing.T) {
	probe := json.RawMessage(`{"measured_at":null,"regions":[]}`)
	kernel := &fakeMesh{supported: true, regionProbe: true, probe: probe}
	c := testMeshComponent(t, kernel, nil)
	if err := c.apply(meshSnapshot(meshMember)); err != nil {
		t.Fatal(err)
	}
	status, _, _ := c.status(context.Background())
	if payload, _ := json.Marshal(status); !strings.Contains(string(payload), `"region_probe":{"measured_at":null,"regions":[]}`) {
		t.Fatalf("payload = %s", payload)
	}
	kernel.probe = json.RawMessage(`null`)
	status, _, _ = c.status(context.Background())
	if payload, _ := json.Marshal(status); !strings.Contains(string(payload), `"region_probe":null`) {
		t.Fatalf("payload = %s", payload)
	}
	// Without the feature, or when the kernel cannot be read: left out.
	kernel.regionProbe = false
	status, _, _ = c.status(context.Background())
	if payload, _ := json.Marshal(status); strings.Contains(string(payload), "region_probe") {
		t.Fatalf("payload = %s", payload)
	}
	kernel.regionProbe, kernel.statusErr = true, errors.New("down")
	status, _, _ = c.status(context.Background())
	if payload, _ := json.Marshal(status); strings.Contains(string(payload), "region_probe") {
		t.Fatalf("payload = %s", payload)
	}
}

func TestMeshSendsAWithdrawalAsItIs(t *testing.T) {
	kernel := &fakeMesh{supported: true, requests: []panel.MeshRegionRequest{
		{ID: "w1", Network: "cn", Withdraw: true},
		{ID: "r1", Region: "eu"},
	}}
	c := testMeshComponent(t, kernel, nil)
	var sent []*agentv1pb.PackageReport
	c.sendReport = func(report *agentv1pb.PackageReport) error {
		sent = append(sent, report)
		return nil
	}
	c.negotiated = true
	if err := c.apply(meshSnapshot(meshMember)); err != nil {
		t.Fatal(err)
	}
	c.report()
	if len(sent) != 3 || sent[1].GetKind() != agentapi.MeshRegionRequestKind || string(sent[1].GetPayloadJson()) != `{"withdraw":true}` {
		t.Fatalf("sent %d reports: %v", len(sent), sent)
	}
	if string(sent[2].GetPayloadJson()) != `{"region":"eu"}` {
		t.Fatalf("request = %s", sent[2].GetPayloadJson())
	}
	if strings.Join(kernel.done, ",") != "w1,r1" {
		t.Fatalf("done = %v", kernel.done)
	}
}
