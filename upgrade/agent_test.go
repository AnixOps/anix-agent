package upgrade

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
)

// mirror serves release zips by path, like Control's /install/agent.
type mirror struct {
	server *httptest.Server
	mu     sync.Mutex
	files  map[string][]byte
	hits   []string
}

func newMirror(t *testing.T) *mirror {
	m := &mirror{files: map[string][]byte{}}
	m.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.hits = append(m.hits, r.URL.Path)
		data, ok := m.files[r.URL.Path]
		m.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mirror) add(path string, data []byte) string {
	m.mu.Lock()
	m.files[path] = data
	m.mu.Unlock()
	return m.server.URL + path
}

func (m *mirror) requested() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.hits...)
}

type agentFixture struct {
	agent  *Agent
	key    releaseKey
	mirror *mirror
	dir    string
	lib    string
	active bool
}

func newAgentFixture(t *testing.T) *agentFixture {
	t.Helper()
	root := t.TempDir()
	f := &agentFixture{key: newReleaseKey(t), mirror: newMirror(t), dir: filepath.Join(root, "upgrade"), lib: filepath.Join(root, "lib"), active: true}
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.lib, 0o755); err != nil {
		t.Fatal(err)
	}
	f.agent = &Agent{
		Dir: f.dir, LibDir: f.lib, Version: "v4.1.0", Arch: "amd64", PublicKey: f.key.public,
		HTTPClient:    f.mirror.server.Client(),
		UpdaterActive: func(context.Context) bool { return f.active },
	}
	return f
}

// artifact publishes a signed release zip for arch.
func (f *agentFixture) artifact(t *testing.T, arch, version string) (agentcontrol.UpgradeArtifact, []byte) {
	t.Helper()
	data := releaseZip(t, zipEntry{name: BinaryName, data: fakeAgent(version, false)})
	asset := "anix-agent-linux-" + map[string]string{"amd64": "64", "arm64": "arm64-v8a"}[arch] + ".zip"
	url := f.mirror.add("/install/agent/"+version+"/"+asset, data)
	return agentcontrol.UpgradeArtifact{Arch: arch, Asset: asset, URL: url, SHA256: digest(data), Size: int64(len(data)), Signature: f.key.sign(data)}, data
}

func upgradeOperation(t *testing.T, request agentcontrol.UpgradeRequest) *agentv1pb.DesiredOperation {
	t.Helper()
	request.Schema = agentcontrol.UpgradeSchemaV1
	if request.CampaignID == "" {
		request.CampaignID = "campaign-1"
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1pb.DesiredOperation{OperationId: "op-1", Kind: agentcontrol.OperationKindAgentUpgrade, Revision: 1, PayloadJson: payload}
}

// run handles operation in an operation context and records the progress.
type run struct {
	state    agentcontrol.UpgradeState
	err      error
	progress []string
	finish   func(agentv1pb.ObservedPhase)
}

func (f *agentFixture) handle(t *testing.T, operation *agentv1pb.DesiredOperation) *run {
	t.Helper()
	r := &run{}
	ctx, finish := agentapi.NewOperationContext(context.Background(), func(data []byte) error {
		var state agentcontrol.UpgradeState
		if err := json.Unmarshal(data, &state); err != nil {
			t.Fatal(err)
		}
		r.progress = append(r.progress, state.Phase)
		return nil
	})
	r.finish = finish
	data, err := f.agent.Handle(ctx, operation)
	r.err = err
	if len(data) > 0 {
		if err := json.Unmarshal(data, &r.state); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func TestUpgradeVerifiesAndReportsHandedOffBeforeTheRequestAppears(t *testing.T) {
	f := newAgentFixture(t)
	amd64, data := f.artifact(t, "amd64", "v4.2.0")
	arm64, _ := f.artifact(t, "arm64", "v4.2.0")
	r := f.handle(t, upgradeOperation(t, agentcontrol.UpgradeRequest{
		Action: agentcontrol.UpgradeActionUpgrade, TargetVersion: "v4.2.0", PreviousVersion: "v4.1.0",
		Artifacts: []agentcontrol.UpgradeArtifact{arm64, amd64},
	}))
	if r.err != nil {
		t.Fatalf("handle: %v", r.err)
	}
	if r.state.Phase != agentcontrol.UpgradePhaseHandedOff || r.state.Version != "v4.2.0" {
		t.Fatalf("state: %+v", r.state)
	}
	if strings.Join(r.progress, ",") != "downloading,verifying" {
		t.Fatalf("progress: %v", r.progress)
	}
	// The architecture's artifact, and only it, was downloaded.
	if hits := f.mirror.requested(); len(hits) != 1 || !strings.HasSuffix(hits[0], amd64.Asset) {
		t.Fatalf("downloads: %v", hits)
	}
	staged := filepath.Join(f.dir, amd64.Asset)
	if string(readFile(t, staged)) != string(data) {
		t.Fatal("the staged release differs from the download")
	}
	request := filepath.Join(f.dir, RequestFile)
	if exists(request) {
		t.Fatal("request.json must appear only after the terminal state was sent")
	}
	if err := f.agent.Admit(upgradeOperation(t, agentcontrol.UpgradeRequest{Action: agentcontrol.UpgradeActionRollback, TargetVersion: "v4.0.0"})); ErrorCode(err, "") != agentcontrol.UpgradeErrorBusy {
		t.Fatalf("an upgrade waiting for its terminal state keeps the Agent busy: %v", err)
	}
	r.finish(agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED)
	var handOff HandOff
	if err := json.Unmarshal(readFile(t, request), &handOff); err != nil {
		t.Fatal(err)
	}
	want := HandOff{Schema: HandOffSchema, OperationID: "op-1", CampaignID: "campaign-1", Action: "upgrade", TargetVersion: "v4.2.0",
		PreviousVersion: "v4.1.0", Arch: "amd64", File: amd64.Asset, Size: amd64.Size, SHA256: amd64.SHA256, Signature: amd64.Signature,
		RequestedAtMS: handOff.RequestedAtMS}
	if handOff != want {
		t.Fatalf("hand-off:\n got %+v\nwant %+v", handOff, want)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(f.dir, ".*.tmp")); len(leftovers) != 0 {
		t.Fatalf("temporary files left: %v", leftovers)
	}
	// The pending request keeps the Agent busy until the updater takes it.
	err := f.agent.Admit(upgradeOperation(t, agentcontrol.UpgradeRequest{Action: agentcontrol.UpgradeActionRollback, TargetVersion: "v4.0.0"}))
	if ErrorCode(err, "") != agentcontrol.UpgradeErrorBusy || !strings.HasPrefix(err.Error(), "upgrade_in_progress: ") {
		t.Fatalf("admit while pending: %v", err)
	}
}

func TestUpgradeDropsTheRequestWhenTheTerminalIsNotSuccess(t *testing.T) {
	f := newAgentFixture(t)
	artifact, _ := f.artifact(t, "amd64", "v4.2.0")
	r := f.handle(t, upgradeOperation(t, agentcontrol.UpgradeRequest{
		Action: agentcontrol.UpgradeActionUpgrade, TargetVersion: "v4.2.0", Artifacts: []agentcontrol.UpgradeArtifact{artifact},
	}))
	if r.err != nil {
		t.Fatal(r.err)
	}
	r.finish(agentv1pb.ObservedPhase_OBSERVED_PHASE_FAILED)
	entries, _ := os.ReadDir(f.dir)
	if len(entries) != 0 {
		t.Fatalf("a deadline-failed upgrade leaves nothing: %v", entries)
	}
	if err := f.agent.Admit(upgradeOperation(t, agentcontrol.UpgradeRequest{Action: agentcontrol.UpgradeActionRollback, TargetVersion: "v4.0.0"})); err != nil {
		t.Fatalf("the Agent is free again: %v", err)
	}
}

func TestUpgradeRefusesABadDigestOrSignatureAndRemovesTheDownload(t *testing.T) {
	for name, mutate := range map[string]func(*agentcontrol.UpgradeArtifact, []byte){
		"digest": func(a *agentcontrol.UpgradeArtifact, _ []byte) { a.SHA256 = strings.Repeat("0", 64) },
		"size":   func(a *agentcontrol.UpgradeArtifact, _ []byte) { a.Size-- },
		"signature": func(a *agentcontrol.UpgradeArtifact, data []byte) {
			a.Signature = newReleaseKey(t).sign(append(data, 0))
		},
		// The right bytes, signed by a key other than the release key.
		"key": func(a *agentcontrol.UpgradeArtifact, data []byte) { a.Signature = newReleaseKey(t).sign(data) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newAgentFixture(t)
			artifact, data := f.artifact(t, "amd64", "v4.2.0")
			mutate(&artifact, data)
			r := f.handle(t, upgradeOperation(t, agentcontrol.UpgradeRequest{
				Action: agentcontrol.UpgradeActionUpgrade, TargetVersion: "v4.2.0", Artifacts: []agentcontrol.UpgradeArtifact{artifact},
			}))
			want := agentcontrol.UpgradeErrorSignature
			if name == "digest" || name == "size" {
				want = agentcontrol.UpgradeErrorDigest
			}
			if r.err == nil || r.state.ErrorCode != want || !strings.HasPrefix(r.err.Error(), want+": ") {
				t.Fatalf("got %+v %v, want %s", r.state, r.err, want)
			}
			entries, _ := os.ReadDir(f.dir)
			if len(entries) != 0 {
				t.Fatalf("the refused download is removed: %v", entries)
			}
			r.finish(agentv1pb.ObservedPhase_OBSERVED_PHASE_FAILED)
			if exists(filepath.Join(f.dir, RequestFile)) {
				t.Fatal("no request for a refused release")
			}
		})
	}
}

func TestUpgradeAnswersCurrentWhenItRunsTheTarget(t *testing.T) {
	f := newAgentFixture(t)
	f.agent.Version = "4.2.0" // a replay after the updater restarted it
	artifact, _ := f.artifact(t, "amd64", "v4.2.0")
	r := f.handle(t, upgradeOperation(t, agentcontrol.UpgradeRequest{
		Action: agentcontrol.UpgradeActionUpgrade, TargetVersion: "v4.2.0", Artifacts: []agentcontrol.UpgradeArtifact{artifact},
	}))
	if r.err != nil || r.state.Phase != agentcontrol.UpgradePhaseCurrent || len(r.progress) != 0 {
		t.Fatalf("got %+v %v %v", r.state, r.err, r.progress)
	}
	if len(f.mirror.requested()) != 0 {
		t.Fatal("current downloads nothing")
	}
	r.finish(agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED)
	if exists(filepath.Join(f.dir, RequestFile)) {
		t.Fatal("current hands nothing off")
	}
}

func TestUpgradeWithoutAnArtifactForTheArchitecture(t *testing.T) {
	f := newAgentFixture(t)
	f.agent.Arch = "riscv64"
	artifact, _ := f.artifact(t, "amd64", "v4.2.0")
	r := f.handle(t, upgradeOperation(t, agentcontrol.UpgradeRequest{
		Action: agentcontrol.UpgradeActionUpgrade, TargetVersion: "v4.2.0", Artifacts: []agentcontrol.UpgradeArtifact{artifact},
	}))
	if r.state.ErrorCode != agentcontrol.UpgradeErrorNoArtifact || len(f.mirror.requested()) != 0 {
		t.Fatalf("got %+v %v", r.state, r.err)
	}
}

func TestUpgradeWithoutTheUpdater(t *testing.T) {
	f := newAgentFixture(t)
	f.active = false
	if f.agent.Available(context.Background()) {
		t.Fatal("no upgrade.v1 without the updater")
	}
	artifact, _ := f.artifact(t, "amd64", "v4.2.0")
	r := f.handle(t, upgradeOperation(t, agentcontrol.UpgradeRequest{
		Action: agentcontrol.UpgradeActionUpgrade, TargetVersion: "v4.2.0", Artifacts: []agentcontrol.UpgradeArtifact{artifact},
	}))
	if r.state.ErrorCode != agentcontrol.UpgradeErrorUpdater {
		t.Fatalf("got %+v %v", r.state, r.err)
	}
	f.active = true
	if !f.agent.Available(context.Background()) {
		t.Fatal("upgrade.v1 with the updater")
	}
}

func TestAvailableAsksSystemctlForThePathUnit(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	agent := &Agent{Systemctl: fakeSystemctl(t, dir, dir, log)}
	if !agent.Available(context.Background()) {
		t.Fatal("the fake path unit is active")
	}
	if got := strings.TrimSpace(string(readFile(t, log))); got != "is-active "+UpdaterPathUnit {
		t.Fatalf("systemctl %q", got)
	}
	agent = &Agent{Systemctl: filepath.Join(dir, "missing")}
	if agent.Available(context.Background()) {
		t.Fatal("no systemctl, no upgrade.v1")
	}
}

func TestAdmitRefusesAnInvalidRequest(t *testing.T) {
	f := newAgentFixture(t)
	operation := &agentv1pb.DesiredOperation{OperationId: "op-x", Kind: agentcontrol.OperationKindAgentUpgrade, Revision: 1, PayloadJson: []byte(`{"schema":"other"}`)}
	err := f.agent.Admit(operation)
	if ErrorCode(err, "") != agentcontrol.UpgradeErrorInvalidRequest || !strings.HasPrefix(err.Error(), "upgrade_invalid_request: ") {
		t.Fatalf("admit: %v", err)
	}
	if err := f.agent.Admit(&agentv1pb.DesiredOperation{Kind: "agent.ping"}); err != nil {
		t.Fatalf("other kinds pass: %v", err)
	}
}

func TestAStaleRequestNoLongerKeepsTheAgentBusy(t *testing.T) {
	f := newAgentFixture(t)
	request := filepath.Join(f.dir, RequestFile)
	writeFile(t, request, []byte(`{}`), 0o600)
	operation := upgradeOperation(t, agentcontrol.UpgradeRequest{Action: agentcontrol.UpgradeActionRollback, TargetVersion: "v4.0.0"})
	if ErrorCode(f.agent.Admit(operation), "") != agentcontrol.UpgradeErrorBusy {
		t.Fatal("a fresh request keeps the Agent busy")
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(request, old, old); err != nil {
		t.Fatal(err)
	}
	if err := f.agent.Admit(operation); err != nil || exists(request) {
		t.Fatalf("a stale request is removed: %v", err)
	}
}

func TestRollbackNeedsTheKeptRelease(t *testing.T) {
	f := newAgentFixture(t)
	operation := upgradeOperation(t, agentcontrol.UpgradeRequest{Action: agentcontrol.UpgradeActionRollback, TargetVersion: "v4.0.0", PreviousVersion: "v4.1.0"})
	r := f.handle(t, operation)
	if r.state.ErrorCode != agentcontrol.UpgradeErrorNoPrevious {
		t.Fatalf("without anix-agent.prev.json: %+v %v", r.state, r.err)
	}
	writeFile(t, filepath.Join(f.lib, PrevRecord), []byte(`{"version":"v3.9.0","sha256":"`+strings.Repeat("a", 64)+`"}`), 0o644)
	if r := f.handle(t, operation); r.state.ErrorCode != agentcontrol.UpgradeErrorNoPrevious {
		t.Fatalf("another kept release: %+v %v", r.state, r.err)
	}
	writeFile(t, filepath.Join(f.lib, PrevRecord), []byte(`{"version":"v4.0.0","sha256":"`+strings.Repeat("a", 64)+`"}`), 0o644)
	r = f.handle(t, operation)
	if r.err != nil || r.state.Phase != agentcontrol.UpgradePhaseHandedOff || len(r.progress) != 0 {
		t.Fatalf("rollback: %+v %v %v", r.state, r.err, r.progress)
	}
	if exists(filepath.Join(f.dir, RequestFile)) {
		t.Fatal("the request waits for the terminal state")
	}
	r.finish(agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED)
	var handOff HandOff
	if err := json.Unmarshal(readFile(t, filepath.Join(f.dir, RequestFile)), &handOff); err != nil {
		t.Fatal(err)
	}
	if handOff.Action != agentcontrol.UpgradeActionRollback || handOff.TargetVersion != "v4.0.0" || handOff.File != "" {
		t.Fatalf("hand-off: %+v", handOff)
	}
}

func TestLogLastResultSetsItAside(t *testing.T) {
	f := newAgentFixture(t)
	writeFile(t, filepath.Join(f.dir, ResultFile), []byte(`{"outcome":"installed","target_version":"v4.1.0"}`), 0o644)
	f.agent.LogLastResult()
	if exists(filepath.Join(f.dir, ResultFile)) || !exists(filepath.Join(f.dir, ResultFile+".seen")) {
		t.Fatal("result.json is logged once")
	}
}
