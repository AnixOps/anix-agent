package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
)

// applyFixture is an installed Agent (lib), its staging directory and a
// fake systemctl: nothing touches the host's system.
type applyFixture struct {
	applier *Applier
	key     releaseKey
	dir     string
	lib     string
	log     string
	old     []byte
}

func newApplyFixture(t *testing.T) *applyFixture {
	t.Helper()
	root := t.TempDir()
	f := &applyFixture{key: newReleaseKey(t), dir: filepath.Join(root, "upgrade"), lib: filepath.Join(root, "lib"), log: filepath.Join(root, "systemctl.log")}
	for _, dir := range []string{f.dir, f.lib} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.old = fakeAgent("v4.1.0", false)
	writeFile(t, filepath.Join(f.lib, BinaryName), f.old, 0o755)
	writeFile(t, filepath.Join(f.lib, GostBinary), []byte("old gost"), 0o755)
	f.applier = &Applier{
		Request: filepath.Join(f.dir, RequestFile), LibDir: f.lib, Version: "v4.1.0", Arch: "amd64", PublicKey: f.key.public,
		Systemctl: fakeSystemctl(t, root, f.lib, f.log), StayUp: 30 * time.Millisecond, Poll: 5 * time.Millisecond,
	}
	return f
}

// stage writes a signed release zip and the request naming it.
func (f *applyFixture) stage(t *testing.T, target string, zipData []byte, mutate ...func(*HandOff)) HandOff {
	t.Helper()
	asset := "anix-agent-linux-64.zip"
	writeFile(t, filepath.Join(f.dir, asset), zipData, 0o600)
	handOff := HandOff{
		Schema: HandOffSchema, OperationID: "op-1", CampaignID: "c-1", Action: agentcontrol.UpgradeActionUpgrade,
		TargetVersion: target, PreviousVersion: "v4.1.0", Arch: "amd64", File: asset, Size: int64(len(zipData)),
		SHA256: digest(zipData), Signature: f.key.sign(zipData),
	}
	for _, m := range mutate {
		m(&handOff)
	}
	f.request(t, handOff)
	return handOff
}

func (f *applyFixture) request(t *testing.T, handOff HandOff) {
	t.Helper()
	data, err := json.Marshal(handOff)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(f.dir, RequestFile), data, 0o600)
}

func (f *applyFixture) systemctlCalls(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(f.log)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func (f *applyFixture) restarts(t *testing.T) int {
	n := 0
	for _, call := range f.systemctlCalls(t) {
		if strings.Contains(call, GostUnit) {
			t.Fatalf("the updater never touches gost's unit: %q", call)
		}
		if call == "restart "+AgentUnit {
			n++
		}
	}
	return n
}

func (f *applyFixture) result(t *testing.T) Result {
	t.Helper()
	var result Result
	if err := json.Unmarshal(readFile(t, filepath.Join(f.dir, ResultFile)), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func withPinnedGost(t *testing.T, sum string) {
	t.Helper()
	previous := PinnedGostSHA256["amd64"]
	PinnedGostSHA256["amd64"] = sum
	t.Cleanup(func() { PinnedGostSHA256["amd64"] = previous })
}

func TestApplyInstallsKeepsThePreviousAndRestartsOnlyTheAgent(t *testing.T) {
	f := newApplyFixture(t)
	newAgent := fakeAgent("v4.2.0", false)
	gost := []byte("pinned gost 3.2.6")
	withPinnedGost(t, digest(gost))
	f.stage(t, "v4.2.0", releaseZip(t,
		zipEntry{name: "LICENSE", data: []byte("license")},
		zipEntry{name: "V2bX", data: []byte(BinaryName), symlink: true},
		zipEntry{name: BinaryName, data: newAgent},
		zipEntry{name: GostBinary, data: gost},
	))
	result, err := f.applier.Apply(context.Background())
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if result.Outcome != OutcomeInstalled || !result.GostStaged {
		t.Fatalf("result: %+v", result)
	}
	if string(readFile(t, filepath.Join(f.lib, BinaryName))) != string(newAgent) {
		t.Fatal("the new binary is installed")
	}
	if string(readFile(t, filepath.Join(f.lib, PrevBinary))) != string(f.old) {
		t.Fatal("the previous binary is kept")
	}
	record, err := ReadPrevRecord(f.lib)
	if err != nil || record.Version != "v4.1.0" || record.SHA256 != digest(f.old) {
		t.Fatalf("prev record: %+v %v", record, err)
	}
	if string(readFile(t, filepath.Join(f.lib, GostBinary))) != string(gost) {
		t.Fatal("the pinned gost is staged for gost's next start")
	}
	if f.restarts(t) != 1 {
		t.Fatalf("one restart: %v", f.systemctlCalls(t))
	}
	if written := f.result(t); written.Outcome != OutcomeInstalled || written.OperationID != "op-1" || written.TargetVersion != "v4.2.0" {
		t.Fatalf("result.json: %+v", written)
	}
	for _, name := range []string{RequestFile, RequestFile + ".applying", "anix-agent-linux-64.zip"} {
		if exists(filepath.Join(f.dir, name)) {
			t.Fatalf("%s is consumed", name)
		}
	}
	if leftovers, _ := filepath.Glob(filepath.Join(f.lib, ".*")); len(leftovers) != 0 {
		t.Fatalf("temporary files left in the lib dir: %v", leftovers)
	}
	// Nothing left to apply: the path unit firing again is harmless.
	if _, err := f.applier.Apply(context.Background()); !errors.Is(err, ErrNoRequest) {
		t.Fatalf("second apply: %v", err)
	}
}

func TestApplyKeepsTheInstalledGostUnlessTheReleaseCarriesThePinnedOne(t *testing.T) {
	f := newApplyFixture(t)
	withPinnedGost(t, digest([]byte("the pinned one")))
	f.stage(t, "v4.2.0", releaseZip(t, zipEntry{name: BinaryName, data: fakeAgent("v4.2.0", false)}, zipEntry{name: GostBinary, data: []byte("another gost")}))
	result, err := f.applier.Apply(context.Background())
	if err != nil || result.GostStaged {
		t.Fatalf("apply: %+v %v", result, err)
	}
	if string(readFile(t, filepath.Join(f.lib, GostBinary))) != "old gost" {
		t.Fatal("an unpinned gost is not installed")
	}
}

func TestApplyReinstatesThePreviousBinaryWhenTheNewAgentDoesNotStayUp(t *testing.T) {
	f := newApplyFixture(t)
	gost := []byte("pinned gost")
	withPinnedGost(t, digest(gost))
	f.stage(t, "v4.2.0", releaseZip(t, zipEntry{name: BinaryName, data: fakeAgent("v4.2.0", true)}, zipEntry{name: GostBinary, data: gost}))
	result, err := f.applier.Apply(context.Background())
	if err == nil || result.Outcome != OutcomeRestored || ErrorCode(err, "") != ErrorStartFailed {
		t.Fatalf("apply: %+v %v", result, err)
	}
	if string(readFile(t, filepath.Join(f.lib, BinaryName))) != string(f.old) {
		t.Fatal("the previous binary is reinstated")
	}
	if f.restarts(t) != 2 {
		t.Fatalf("restarted, then restarted with the previous binary: %v", f.systemctlCalls(t))
	}
	if string(readFile(t, filepath.Join(f.lib, GostBinary))) != "old gost" {
		t.Fatal("gost is staged only with an Agent that stayed up")
	}
	if written := f.result(t); written.Outcome != OutcomeRestored || written.ErrorCode != ErrorStartFailed {
		t.Fatalf("result.json: %+v", written)
	}
}

func TestApplyRefusesADowngrade(t *testing.T) {
	f := newApplyFixture(t)
	f.stage(t, "v4.0.0", releaseZip(t, zipEntry{name: BinaryName, data: fakeAgent("v4.0.0", false)}))
	result, err := f.applier.Apply(context.Background())
	if ErrorCode(err, "") != agentcontrol.UpgradeErrorDowngrade || result.Outcome != OutcomeRefused {
		t.Fatalf("apply: %+v %v", result, err)
	}
	if string(readFile(t, filepath.Join(f.lib, BinaryName))) != string(f.old) || exists(filepath.Join(f.lib, PrevBinary)) {
		t.Fatal("a refused downgrade changes nothing")
	}
	if len(f.systemctlCalls(t)) != 0 {
		t.Fatal("a refused downgrade restarts nothing")
	}
	if exists(filepath.Join(f.dir, "anix-agent-linux-64.zip")) {
		t.Fatal("the staged release is removed")
	}
}

func TestApplyVerifiesTheStagedReleaseAgain(t *testing.T) {
	other := newReleaseKey(t)
	for name, c := range map[string]struct {
		mutate func(*HandOff)
		code   string
	}{
		"signature": {func(h *HandOff) { h.Signature = other.sign([]byte("x")) }, agentcontrol.UpgradeErrorSignature},
		"digest":    {func(h *HandOff) { h.SHA256 = strings.Repeat("1", 64) }, agentcontrol.UpgradeErrorDigest},
		"size":      {func(h *HandOff) { h.Size++ }, agentcontrol.UpgradeErrorDigest},
		"path":      {func(h *HandOff) { h.File = "../lib/anix-agent-linux-64.zip" }, agentcontrol.UpgradeErrorInvalidRequest},
	} {
		t.Run(name, func(t *testing.T) {
			f := newApplyFixture(t)
			f.stage(t, "v4.2.0", releaseZip(t, zipEntry{name: BinaryName, data: fakeAgent("v4.2.0", false)}), c.mutate)
			if _, err := f.applier.Apply(context.Background()); ErrorCode(err, "") != c.code {
				t.Fatalf("apply: %v, want %s", err, c.code)
			}
			if string(readFile(t, filepath.Join(f.lib, BinaryName))) != string(f.old) || len(f.systemctlCalls(t)) != 0 {
				t.Fatal("an unverified release changes nothing")
			}
		})
	}
}

func TestApplyRefusesAStagedLink(t *testing.T) {
	f := newApplyFixture(t)
	data := releaseZip(t, zipEntry{name: BinaryName, data: fakeAgent("v4.2.0", false)})
	f.stage(t, "v4.2.0", data)
	elsewhere := filepath.Join(t.TempDir(), "release.zip")
	writeFile(t, elsewhere, data, 0o600)
	staged := filepath.Join(f.dir, "anix-agent-linux-64.zip")
	if err := os.Remove(staged); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, staged); err != nil {
		t.Fatal(err)
	}
	if _, err := f.applier.Apply(context.Background()); err == nil {
		t.Fatal("a staged symbolic link is refused")
	}
	if string(readFile(t, filepath.Join(f.lib, BinaryName))) != string(f.old) {
		t.Fatal("nothing installed")
	}
}

func TestApplyRefusesABinaryThatDoesNotPrintTheTarget(t *testing.T) {
	f := newApplyFixture(t)
	f.stage(t, "v4.2.0", releaseZip(t, zipEntry{name: BinaryName, data: fakeAgent("v4.3.0", false)}))
	if _, err := f.applier.Apply(context.Background()); ErrorCode(err, "") != ErrorVersionMismatch {
		t.Fatalf("apply: %v", err)
	}
	if string(readFile(t, filepath.Join(f.lib, BinaryName))) != string(f.old) || len(f.systemctlCalls(t)) != 0 {
		t.Fatal("nothing installed")
	}
}

func TestApplyAnswersCurrentForTheInstalledRelease(t *testing.T) {
	f := newApplyFixture(t)
	f.stage(t, "v4.1.0", releaseZip(t, zipEntry{name: BinaryName, data: fakeAgent("v4.1.0", false)}))
	result, err := f.applier.Apply(context.Background())
	if err != nil || result.Outcome != OutcomeCurrent || len(f.systemctlCalls(t)) != 0 {
		t.Fatalf("apply: %+v %v", result, err)
	}
}

func TestApplyRollsBackToTheKeptRelease(t *testing.T) {
	f := newApplyFixture(t)
	kept := fakeAgent("v4.0.0", false)
	writeFile(t, filepath.Join(f.lib, PrevBinary), kept, 0o755)
	writeFile(t, filepath.Join(f.lib, PrevRecord), []byte(`{"version":"v4.0.0","sha256":"`+digest(kept)+`"}`), 0o644)
	f.request(t, HandOff{Schema: HandOffSchema, OperationID: "op-r", CampaignID: "c-1", Action: agentcontrol.UpgradeActionRollback, TargetVersion: "v4.0.0", PreviousVersion: "v4.1.0"})
	result, err := f.applier.Apply(context.Background())
	if err != nil || result.Outcome != OutcomeRolledBack {
		t.Fatalf("rollback: %+v %v", result, err)
	}
	if string(readFile(t, filepath.Join(f.lib, BinaryName))) != string(kept) {
		t.Fatal("the kept release is reinstated: a rollback may go back")
	}
	if string(readFile(t, filepath.Join(f.lib, PrevBinary))) != string(f.old) {
		t.Fatal("the release left is kept in turn")
	}
	if record, err := ReadPrevRecord(f.lib); err != nil || record.Version != "v4.1.0" || record.SHA256 != digest(f.old) {
		t.Fatalf("prev record: %+v %v", record, err)
	}
	if f.restarts(t) != 1 {
		t.Fatalf("one restart: %v", f.systemctlCalls(t))
	}
}

func TestApplyRollbackChecksTheKeptBinary(t *testing.T) {
	f := newApplyFixture(t)
	kept := fakeAgent("v4.0.0", false)
	writeFile(t, filepath.Join(f.lib, PrevBinary), kept, 0o755)
	writeFile(t, filepath.Join(f.lib, PrevRecord), []byte(`{"version":"v4.0.0","sha256":"`+strings.Repeat("b", 64)+`"}`), 0o644)
	rollback := HandOff{Schema: HandOffSchema, OperationID: "op-r", CampaignID: "c-1", Action: agentcontrol.UpgradeActionRollback, TargetVersion: "v4.0.0"}
	f.request(t, rollback)
	if _, err := f.applier.Apply(context.Background()); ErrorCode(err, "") != agentcontrol.UpgradeErrorDigest {
		t.Fatalf("an altered kept binary: %v", err)
	}
	rollback.TargetVersion = "v3.9.0"
	f.request(t, rollback)
	if _, err := f.applier.Apply(context.Background()); ErrorCode(err, "") != agentcontrol.UpgradeErrorNoPrevious {
		t.Fatalf("another release than the kept one: %v", err)
	}
	if string(readFile(t, filepath.Join(f.lib, BinaryName))) != string(f.old) || len(f.systemctlCalls(t)) != 0 {
		t.Fatal("a refused rollback changes nothing")
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"v4.2.0", "v4.1.0", 1}, {"4.1.0", "v4.1.0", 0}, {"v4.1.0-rc.5", "v4.1.0", -1},
		{"v4.1.0-alpha.2", "v4.1.0-beta.1", -1}, {"v4.1.0-rc.10", "v4.1.0-rc.9", 1}, {"v4.10.0", "v4.9.9", 1},
	} {
		if got, ok := CompareVersions(c.a, c.b); !ok || got != c.want {
			t.Errorf("CompareVersions(%s, %s) = %d %v, want %d", c.a, c.b, got, ok, c.want)
		}
	}
	if _, ok := CompareVersions("abc123", "v4.1.0"); ok {
		t.Error("a commit is not a release")
	}
}

// The compiled-in release key and gost digests are the ones the release
// workflow pins.
func TestPinsMatchTheReleaseWorkflow(t *testing.T) {
	workflow := string(readFile(t, filepath.Join("..", ".github", "workflows", "release.yml")))
	pin := func(name string) string {
		match := regexp.MustCompile(name + `:\s*'([^']+)'`).FindStringSubmatch(workflow)
		if match == nil {
			t.Fatalf("release.yml has no %s", name)
		}
		return match[1]
	}
	if got := pin("ANIXOPS_OFFICIAL_PUBLIC_KEY"); got != OfficialPublicKey {
		t.Errorf("release key %s, release.yml %s", OfficialPublicKey, got)
	}
	if PinnedGostSHA256["amd64"] != pin("GOST_LINUX_AMD64_BINARY_SHA256") || PinnedGostSHA256["arm64"] != pin("GOST_LINUX_ARM64_BINARY_SHA256") {
		t.Errorf("pinned gost %v differs from release.yml", PinnedGostSHA256)
	}
	if key := officialKey(); len(key) != 32 {
		t.Error("the official key decodes to a raw Ed25519 key")
	}
}
