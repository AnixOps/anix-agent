package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	"github.com/AnixOps/anix-agent/v4/conf"
	"github.com/AnixOps/anix-agent/v4/plugin"
)

func TestPluginSupervisorSpecNamespacesByFinalNodeID(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey := base64.StdEncoding.EncodeToString(publicKey)
	root := t.TempDir()
	socketRoot := t.TempDir()
	api := conf.ApiConfig{
		APIHost:                 "https://panel-a.example",
		PluginRoot:              root,
		PluginSocketDir:         socketRoot,
		PluginOfficialPublicKey: encodedKey,
		PluginSupervisorEnabled: true,
	}

	first, err := pluginSupervisorSpecForNode(101, api)
	if err != nil {
		t.Fatal(err)
	}
	second, err := pluginSupervisorSpecForNode(202, api)
	if err != nil {
		t.Fatal(err)
	}
	if first.rootDir == second.rootDir || first.socketDir == second.socketDir {
		t.Fatalf("node namespaces collided: first=(%q,%q), second=(%q,%q)", first.rootDir, first.socketDir, second.rootDir, second.socketDir)
	}
	if want := filepath.Join(root, "nodes", "101"); first.rootDir != want {
		t.Fatalf("first root = %q, want %q", first.rootDir, want)
	}
	if want := filepath.Join(socketRoot, "nodes", "101"); first.socketDir != want {
		t.Fatalf("first socket directory = %q, want %q", first.socketDir, want)
	}

	api.PluginSocketDir = ""
	derived, err := pluginSupervisorSpecForNode(101, api)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "nodes", "101", "sockets"); derived.socketDir != want {
		t.Fatalf("derived socket directory = %q, want %q", derived.socketDir, want)
	}
}

func TestNodePluginSupervisorsIsolateSamePluginRevisionAndClose(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	socketRoot := t.TempDir()
	api := conf.ApiConfig{
		PluginRoot:              root,
		PluginSocketDir:         socketRoot,
		PluginOfficialPublicKey: base64.StdEncoding.EncodeToString(publicKey),
		PluginSupervisorEnabled: true,
	}
	n := New()
	first, err := n.supervisorForNode(101, api)
	if err != nil {
		t.Fatal(err)
	}
	second, err := n.supervisorForNode(202, api)
	if err != nil {
		t.Fatal(err)
	}
	reused, err := n.supervisorForNode(101, api)
	if err != nil {
		t.Fatal(err)
	}
	if first != reused {
		t.Fatal("same final node ID did not reuse its Supervisor")
	}
	if first == second {
		t.Fatal("different final node IDs shared a Supervisor")
	}

	request := signedIsolationInstallRequest(t, privateKey, "isolation-plugin", "1.0.0", []byte("same signed artifact"))
	if _, err := first.HandleInstall(context.Background(), isolationEnvelope("install-one", "isolation-plugin", "1.0.0", 7, nil), func(context.Context) (plugin.InstallRequest, error) {
		return request, nil
	}); err != nil {
		t.Fatalf("install first node plugin: %v", err)
	}
	if _, err := second.HandleInstall(context.Background(), isolationEnvelope("install-two", "isolation-plugin", "1.0.0", 7, nil), func(context.Context) (plugin.InstallRequest, error) {
		return request, nil
	}); err != nil {
		t.Fatalf("install second node plugin: %v", err)
	}

	// Mutating the first node's revision/config must not alter the second
	// node's state even when plugin ID and version are identical.
	if _, err := first.Handle(context.Background(), "plugin.configure", isolationEnvelope("configure-one", "isolation-plugin", "1.0.0", 8, []byte(`{"owner":"one"}`))); err != nil {
		t.Fatalf("configure first node plugin: %v", err)
	}
	inspect, err := second.Handle(context.Background(), "plugin.inspect", isolationEnvelope("inspect-two", "isolation-plugin", "1.0.0", 7, nil))
	if err != nil {
		t.Fatalf("inspect second node plugin: %v", err)
	}
	var state plugin.PluginState
	if err := json.Unmarshal(inspect, &state); err != nil {
		t.Fatal(err)
	}
	if state.DesiredRevision != 7 {
		t.Fatalf("second node revision = %d, want 7; state crossed from first node", state.DesiredRevision)
	}

	if err := n.closeResources(); err != nil {
		t.Fatalf("close node-scoped Supervisors: %v", err)
	}
	for nodeID := range map[int]struct{}{101: {}, 202: {}} {
		spec, err := pluginSupervisorSpecForNode(nodeID, api)
		if err != nil {
			t.Fatal(err)
		}
		statePath := filepath.Join(spec.rootDir, "state.json")
		if _, err := os.Stat(statePath); err != nil {
			t.Fatalf("node %d state file missing after Close: %v", nodeID, err)
		}
	}
	if _, err := first.Handle(context.Background(), "plugin.inspect", isolationEnvelope("closed-one", "isolation-plugin", "1.0.0", 7, nil)); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed first Supervisor error = %v, want closed error", err)
	}
	if _, err := second.Handle(context.Background(), "plugin.inspect", isolationEnvelope("closed-two", "isolation-plugin", "1.0.0", 7, nil)); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed second Supervisor error = %v, want closed error", err)
	}
}

func TestPluginSupervisorSpecRejectsLegacyState(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "state.json"), []byte(`{"plugins":{},"journal":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = pluginSupervisorSpecForNode(303, conf.ApiConfig{
		PluginRoot:              root,
		PluginOfficialPublicKey: base64.StdEncoding.EncodeToString(publicKey),
		PluginSupervisorEnabled: true,
	})
	if err == nil || !strings.Contains(err.Error(), "legacy plugin supervisor data") {
		t.Fatalf("legacy layout error = %v, want migration failure", err)
	}
}

func TestSingleNodeSupervisorPreservesLegacyLayout(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	socketRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "state.json"), []byte(`{"plugins":{},"journal":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	n := New()
	n.allowLegacySingleNode = true
	supervisor, err := n.supervisorForNode(303, conf.ApiConfig{
		APIHost:                 "https://panel.example",
		PluginRoot:              root,
		PluginSocketDir:         socketRoot,
		PluginOfficialPublicKey: base64.StdEncoding.EncodeToString(publicKey),
		PluginSupervisorEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	spec := n.supervisorSpecs[303]
	if spec.rootDir != root || spec.socketDir != socketRoot || !spec.legacy {
		t.Fatalf("single-node legacy spec = %#v, want root=%q socket=%q legacy=true", spec, root, socketRoot)
	}
	if err := supervisor.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestFreshSingleNodeSupervisorStartsNamespaced(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	spec, err := pluginSupervisorSpecForNodeMode(404, conf.ApiConfig{
		APIHost:                 "https://panel.example",
		PluginRoot:              root,
		PluginOfficialPublicKey: base64.StdEncoding.EncodeToString(publicKey),
		PluginSupervisorEnabled: true,
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "nodes", "404"); spec.rootDir != want || spec.legacy {
		t.Fatalf("fresh single-node spec = %#v, want root=%q legacy=false", spec, want)
	}
}

func TestCountPluginSupervisorNodesDeduplicatesSameConfiguredNode(t *testing.T) {
	api := conf.ApiConfig{
		APIHost: "https://panel.example", NodeID: 7, Key: "node-key",
		PluginSupervisorEnabled: true,
	}
	if got := countPluginSupervisorNodes([]conf.NodeConfig{{ApiConfig: api}, {ApiConfig: api}}); got != 1 {
		t.Fatalf("duplicate configured node count = %d, want 1", got)
	}
	other := api
	other.NodeID = 8
	if got := countPluginSupervisorNodes([]conf.NodeConfig{{ApiConfig: api}, {ApiConfig: other}}); got != 2 {
		t.Fatalf("distinct configured node count = %d, want 2", got)
	}
}

func TestNodePluginSupervisorConfigValidation(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(publicKey)
	// Without PluginRoot and PluginSocketDir the O1 layout applies.
	spec, err := pluginSupervisorSpecForNode(1, conf.ApiConfig{PluginOfficialPublicKey: key})
	if err != nil {
		t.Fatalf("default plugin layout: %v", err)
	}
	if spec.rootDir != conf.DefaultPluginRoot+"/nodes/1" || spec.socketDir != conf.DefaultPluginSocketDir+"/nodes/1" {
		t.Fatalf("default plugin layout = %q, %q", spec.rootDir, spec.socketDir)
	}
	if _, err := pluginSupervisorSpecForNode(1, conf.ApiConfig{PluginRoot: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "PluginOfficialPublicKey") {
		t.Fatalf("missing official key error = %v", err)
	}

	n := New()
	firstRoot := t.TempDir()
	first, err := n.supervisorForNode(1, conf.ApiConfig{PluginRoot: firstRoot, PluginOfficialPublicKey: key, PluginSupervisorEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if first == nil {
		t.Fatal("first Supervisor is nil")
	}
	_, err = n.supervisorForNode(1, conf.ApiConfig{PluginRoot: t.TempDir(), PluginOfficialPublicKey: key, PluginSupervisorEnabled: true})
	if err == nil || !strings.Contains(err.Error(), "conflicting plugin-supervisor configuration") {
		t.Fatalf("same-node conflicting config error = %v", err)
	}
	if err := n.closeResources(); err != nil {
		t.Fatalf("close validation Supervisor: %v", err)
	}
}

func TestNodePluginSupervisorRejectsSameNodeIDFromDifferentControls(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(publicKey)
	root := t.TempDir()
	n := New()
	_, err = n.supervisorForNode(1, conf.ApiConfig{
		APIHost: "https://panel-a.example", Key: "node-key-a", PluginRoot: root,
		PluginOfficialPublicKey: key, PluginSupervisorEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = n.supervisorForNode(1, conf.ApiConfig{
		APIHost: "https://panel-b.example", Key: "node-key-b", PluginRoot: root,
		PluginOfficialPublicKey: key, PluginSupervisorEnabled: true,
	})
	if err == nil || !strings.Contains(err.Error(), "conflicting plugin-supervisor configuration") {
		t.Fatalf("mixed control identity error = %v", err)
	}
	if err := n.closeResources(); err != nil {
		t.Fatal(err)
	}
}

func TestFindNodeSupervisorControllerRequiresControlIdentity(t *testing.T) {
	first := &Controller{apiClient: &errorTestNodeAPI{}, pluginSupervisor: &plugin.Supervisor{}}
	second := &Controller{apiClient: &errorTestNodeAPI{}, pluginSupervisor: &plugin.Supervisor{}}
	identities := map[*Controller]string{first: "panel-a", second: "panel-b"}
	controllers := []*Controller{first, second}
	if got := findNodeSupervisorController(controllers, identities, 1, "panel-a"); got != first {
		t.Fatalf("matching control identity returned %p, want %p", got, first)
	}
	if got := findNodeSupervisorController(controllers, identities, 1, "panel-c"); got != nil {
		t.Fatalf("unmatched control identity returned %p, want nil", got)
	}
}

func signedIsolationInstallRequest(t *testing.T, privateKey ed25519.PrivateKey, id, version string, artifact []byte) plugin.InstallRequest {
	t.Helper()
	digest := sha256.Sum256(artifact)
	manifest := plugin.Manifest{
		ID: id, Name: id, Version: version, APIVersion: "v1", Publisher: "AnixOps",
		Targets: []string{"agent"}, ArtifactSHA256: hex.EncodeToString(digest[:]),
	}
	canonical, err := plugin.CanonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return plugin.InstallRequest{
		ManifestJSON: string(canonical),
		Signature:    base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)),
		Artifact:     artifact,
	}
}

func isolationEnvelope(operationID, pluginID, version string, revision uint64, config []byte) *agentapi.OperationEnvelope {
	digest := sha256.Sum256(config)
	return &agentapi.OperationEnvelope{
		Version: agentapi.OperationEnvelopeVersion, OperationID: operationID, IdempotencyKey: operationID,
		SessionID: "isolation-session", Revision: revision, PluginID: pluginID, TargetVersion: version,
		ConfigHash: hex.EncodeToString(digest[:]), Config: config,
	}
}
