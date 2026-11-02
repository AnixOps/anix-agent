package forward

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v5/api/agent"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"github.com/AnixOps/anix-control/sdk/forward/wire"
)

const rr = forwardv1.BalanceStrategy_BALANCE_STRATEGY_ROUND_ROBIN

func TestSnapshotGenerations(t *testing.T) {
	h := newHarness(t)
	one := state(1, hashOf(1), hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0)))

	// A v1 snapshot carries no forwarding and changes nothing.
	v1 := &agentv1pb.ConfigSnapshot{ConfigRevision: 1, Format: agentapi.ConfigFormatNodeConfigV1, ConfigJson: []byte(`{"kind":"forward"}`)}
	if err := h.c.ApplySnapshot(context.Background(), v1); err != nil {
		t.Fatal(err)
	}
	// Generation 0: Control has no state yet; keep what there is.
	if err := h.apply(2, state(0, "")); err != nil {
		t.Fatal(err)
	}
	if st := h.c.Status(); st.Generation != 0 || st.Applied {
		t.Fatalf("status %+v: a v1 snapshot and generation 0 must change nothing", st)
	}

	if err := h.apply(3, one); err != nil {
		t.Fatal(err)
	}
	if st := h.c.Status(); st.Generation != 1 || !st.Applied || st.Hops != 1 {
		t.Fatalf("after generation 1: status %+v", st)
	}
	// The same generation with another hash: a conflict, ignored.
	conflict := state(1, hashOf(9), hop("R1", 0, 30002, rr, up("192.0.2.10", 443, 0)))
	if err := h.apply(5, conflict); err != nil {
		t.Fatal(err)
	}
	if h.c.Status().StateHash != hashOf(1) {
		t.Fatalf("status %+v: a conflicting hash must be ignored", h.c.Status())
	}

	two := state(2, hashOf(2), hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0)), hop("R2", 0, 30002, rr, up("192.0.2.20", 80, 0)))
	if err := h.apply(7, two); err != nil {
		t.Fatal(err)
	}
	older := state(1, hashOf(1), hop("R9", 0, 30009, rr, up("192.0.2.90", 80, 0)))
	if err := h.apply(8, older); err != nil {
		t.Fatal(err)
	}
	if st := h.c.Status(); st.Generation != 2 || st.Hops != 2 {
		t.Fatalf("status %+v after an older generation", st)
	}

	// The state is persisted, readable by the Agent only.
	info, err := os.Stat(filepath.Join(h.dir, stateFileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %v, want 0600", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("state directory mode %v, want 0700", dirInfo.Mode().Perm())
	}
}

func TestEmptyStateAndV1KeepsIt(t *testing.T) {
	h := newHarness(t)
	if err := h.apply(1, state(1, hashOf(1), hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0)))); err != nil {
		t.Fatal(err)
	}
	v1 := &agentv1pb.ConfigSnapshot{ConfigRevision: 2, Format: agentapi.ConfigFormatNodeConfigV1, ConfigJson: []byte(`{}`)}
	if err := h.c.ApplySnapshot(context.Background(), v1); err != nil {
		t.Fatal(err)
	}
	if st := h.c.Status(); st.Generation != 1 || st.Hops != 1 {
		t.Fatalf("status %+v: a v1 snapshot changed the forwarding state", st)
	}
	if err := h.apply(3, state(2, hashOf(2))); err != nil {
		t.Fatal(err)
	}
	if st := h.c.Status(); st.Generation != 2 || !st.Applied || st.Hops != 0 || st.HopErrors != 0 {
		t.Fatalf("status %+v after the empty state", st)
	}
}

func TestInvalidForwardMember(t *testing.T) {
	h := newHarness(t)
	bad := &agentv1pb.ConfigSnapshot{ConfigRevision: 1, Format: wire.NodeConfigFormat, ConfigJson: []byte(`{"forward":{"generation":"x"}}`)}
	if err := h.c.ApplySnapshot(context.Background(), bad); !errors.Is(err, agentapi.ErrConfigInvalid) {
		t.Fatalf("malformed member: %v, want ErrConfigInvalid", err)
	}
	other := state(1, hashOf(1))
	other.NodeRef = "forward-42"
	if err := h.apply(2, other); !errors.Is(err, agentapi.ErrConfigInvalid) {
		t.Fatalf("another node's state: %v, want ErrConfigInvalid", err)
	}
}

func TestRestartLoadsPersistedState(t *testing.T) {
	h := newHarness(t)
	if err := h.apply(1, state(3, hashOf(3), hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0)))); err != nil {
		t.Fatal(err)
	}
	h.c.Close()
	h.start()
	if st := h.c.Status(); st.Generation != 3 || !st.Applied || st.HopErrors != 1 {
		t.Fatalf("after restart: status %+v", st)
	}
	// Another node's persisted state is discarded.
	other := newHarness(t)
	other.c.Close()
	data, err := os.ReadFile(filepath.Join(h.dir, stateFileName))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other.dir, stateFileName), []byte(strings.Replace(string(data), testNode.String(), "forward-99", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	other.start()
	if st := other.c.Status(); st.Generation != 0 {
		t.Fatalf("another node's state was loaded: %+v", st)
	}
}

// No engine runs a hop on the Agent any more: every hop of the state is a
// hop error naming its engine.
func TestEveryHopIsAHopError(t *testing.T) {
	h := newHarness(t)
	gost := hop("R2", 0, 30002, rr, up("192.0.2.20", 80, 0))
	gost.Engine = forwardv1.Engine_ENGINE_GOST
	if err := h.apply(1, state(1, hashOf(1), gost, hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0)))); err != nil {
		t.Fatalf("hops no engine runs must not fail the configuration: %v", err)
	}
	if st := h.c.Status(); !st.Applied || st.HopErrors != 2 {
		t.Fatalf("status %+v", st)
	}
	e := h.c.Report(context.Background()).GetErrors()
	if len(e) != 2 || e[0].GetRouteId() != "R1" || e[0].GetEngine() != forwardv1.Engine_ENGINE_NFTABLES ||
		e[1].GetRouteId() != "R2" || e[1].GetEngine() != forwardv1.Engine_ENGINE_GOST ||
		!strings.Contains(e[1].GetMessage(), "no driver for engine ENGINE_GOST") {
		t.Fatalf("hop errors %v", e)
	}
}

func TestReportsCadenceAndContent(t *testing.T) {
	h := newHarness(t, func(o *Options) {
		o.ReportInterval = 400 * time.Millisecond
		o.ReportMinGap = 150 * time.Millisecond
	})
	if err := h.apply(1, state(1, hashOf(1), hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0)))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(h.sent.all()); n != 0 {
		t.Fatalf("%d reports before a session negotiated forward.v1", n)
	}
	h.c.ForwardSession(true)
	eventually(t, "a report at session start", func() bool { return len(h.sent.all()) == 1 })
	first := h.sent.last()
	if first.GetNodeRef() != testNode.String() || first.GetGeneration() != 1 || first.GetStateHash() != hashOf(1) || !first.GetApplied() ||
		len(first.GetErrors()) != 1 || len(first.GetCounters()) != 0 || len(first.GetHealth()) != 0 {
		t.Fatalf("first report: %v", first)
	}

	// An apply asks for a report, but not sooner than the minimum gap.
	if err := h.apply(2, state(2, hashOf(2))); err != nil {
		t.Fatal(err)
	}
	eventually(t, "a report after the apply", func() bool { return len(h.sent.all()) >= 2 })
	h.sent.mu.Lock()
	gap := h.sent.at[1].Sub(h.sent.at[0])
	h.sent.mu.Unlock()
	if gap < 140*time.Millisecond {
		t.Fatalf("reports %v apart; at most one every 150ms", gap)
	}
	if last := h.sent.last(); last.GetGeneration() != 2 || len(last.GetErrors()) != 0 {
		t.Fatalf("report after the apply: %v", last)
	}
	// And one every interval without anything happening.
	n := len(h.sent.all())
	eventually(t, "a periodic report", func() bool { return len(h.sent.all()) > n })

	// A session that does not negotiate stops the reports.
	h.c.ForwardSession(false)
	h.sent.mu.Lock()
	h.sent.err = agentapi.ErrSessionGone
	h.sent.mu.Unlock()
	time.Sleep(500 * time.Millisecond)
	if got := len(h.sent.all()); got > n+2 {
		t.Fatalf("%d reports without a negotiated session", got-n)
	}
}

func TestHelloCapability(t *testing.T) {
	h := newHarness(t)
	capability, err := h.c.HelloCapability()
	if err != nil {
		t.Fatal(err)
	}
	caps, listed, err := wire.NodeCapabilitiesFromHello([]*agentv1pb.Capability{capability}, testNode.String())
	if err != nil || !listed {
		t.Fatalf("capability %v: listed %v, %v", capability, listed, err)
	}
	if caps.GetKernelVersion() != "6.12.0" || caps.GetAgentVersion() != "test" || len(caps.GetEngines()) != len(retiredEngines) {
		t.Fatalf("node capabilities %v", caps)
	}
	for _, engine := range caps.GetEngines() {
		if engine.GetAvailable() || !strings.HasPrefix(engine.GetUnavailableReason(), "removed:") {
			t.Fatalf("engine %v must be listed as removed", engine)
		}
	}
}
