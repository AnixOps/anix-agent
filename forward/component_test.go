package forward

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"github.com/AnixOps/anix-control/sdk/forward/driver"
	"github.com/AnixOps/anix-control/sdk/forward/driver/fake"
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
	// Generation 0: Control has no state yet; keep what runs.
	if err := h.apply(2, state(0, "")); err != nil {
		t.Fatal(err)
	}
	if h.host.Applies() != 0 || h.c.Status().Generation != 0 {
		t.Fatalf("applies %d, status %+v: a v1 snapshot and generation 0 must change nothing", h.host.Applies(), h.c.Status())
	}

	if err := h.apply(3, one); err != nil {
		t.Fatal(err)
	}
	if st := h.c.Status(); st.Generation != 1 || !st.Applied || st.Hops != 1 || h.host.Applies() != 1 {
		t.Fatalf("after generation 1: status %+v, applies %d", st, h.host.Applies())
	}
	// The same generation and hash again (a forced sync): nothing to do.
	if err := h.apply(4, one); err != nil {
		t.Fatal(err)
	}
	// The same generation with another hash: a conflict, ignored.
	conflict := state(1, hashOf(9), hop("R1", 0, 30002, rr, up("192.0.2.10", 443, 0)))
	if err := h.apply(5, conflict); err != nil {
		t.Fatal(err)
	}
	if h.host.Applies() != 1 || h.c.Status().StateHash != hashOf(1) {
		t.Fatalf("applies %d, status %+v: repeats, conflicts and older generations must not apply", h.host.Applies(), h.c.Status())
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

	// The applied state is persisted, readable by the Agent only.
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

func TestEmptyStateRemovesEverythingAndV1KeepsIt(t *testing.T) {
	h := newHarness(t)
	if err := h.apply(1, state(1, hashOf(1), hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0)))); err != nil {
		t.Fatal(err)
	}
	v1 := &agentv1pb.ConfigSnapshot{ConfigRevision: 2, Format: agentapi.ConfigFormatNodeConfigV1, ConfigJson: []byte(`{}`)}
	if err := h.c.ApplySnapshot(context.Background(), v1); err != nil {
		t.Fatal(err)
	}
	if len(h.host.Owned()) == 0 {
		t.Fatal("a v1 snapshot removed the forwarding state")
	}
	if err := h.apply(3, state(2, hashOf(2))); err != nil {
		t.Fatal(err)
	}
	for _, o := range h.host.Owned() {
		if strings.HasPrefix(o, "hop ") {
			t.Fatalf("an empty state left %q", o)
		}
	}
	if st := h.c.Status(); st.Generation != 2 || !st.Applied || st.Hops != 0 {
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

func TestRestartReappliesPersistedState(t *testing.T) {
	h := newHarness(t)
	if err := h.apply(1, state(3, hashOf(3), hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0)))); err != nil {
		t.Fatal(err)
	}
	h.c.Close()
	// A reboot: the host lost its rules; the Agent starts again on the same
	// state directory and re-applies before Control speaks.
	h.host = fake.NewHost(nil)
	h.start()
	if st := h.c.Status(); st.Generation != 3 || !st.Applied || h.host.Applies() != 1 {
		t.Fatalf("after restart: status %+v, applies %d", st, h.host.Applies())
	}
	obs, err := h.driver.Observe(context.Background())
	if err != nil || !obs.Applied || obs.Generation != 3 || len(obs.Counters) != 1 {
		t.Fatalf("host after restart: %+v, %v", obs, err)
	}
	// Control then sends the same generation: nothing to apply.
	if err := h.apply(1, state(3, hashOf(3), hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0)))); err != nil {
		t.Fatal(err)
	}
	if h.host.Applies() != 1 {
		t.Fatalf("applies %d: the same generation applied again", h.host.Applies())
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
	other.host = fake.NewHost(nil)
	other.start()
	if st := other.c.Status(); st.Generation != 0 || other.host.Applies() != 0 {
		t.Fatalf("another node's state was applied: %+v", st)
	}
}

func TestFailedApplyIsReportedAndRetried(t *testing.T) {
	h := newHarness(t)
	h.host.FailNext(fake.OpApply, errors.New("nft: transaction refused"))
	if err := h.apply(1, state(1, hashOf(1), hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0)))); err != nil {
		t.Fatalf("a failed driver apply must not fail the configuration: %v", err)
	}
	if st := h.c.Status(); st.Applied || st.HopErrors != 1 {
		t.Fatalf("status %+v after a failed apply", st)
	}
	report := h.c.Report(context.Background())
	if report.GetApplied() || len(report.GetErrors()) != 1 || !strings.Contains(report.GetErrors()[0].GetMessage(), "transaction refused") {
		t.Fatalf("report after a failed apply: %v", report)
	}
	eventually(t, "the retry", func() bool { return h.c.Status().Applied })
	if st := h.c.Status(); st.HopErrors != 0 || h.host.Applies() != 1 {
		t.Fatalf("status %+v, applies %d after the retry", st, h.host.Applies())
	}
}

func TestRenderHopErrorsKeepOtherHops(t *testing.T) {
	h := newHarness(t)
	gost := hop("R2", 0, 30002, rr, up("192.0.2.20", 80, 0))
	gost.Engine = forwardv1.Engine_ENGINE_GOST
	if err := h.apply(1, state(1, hashOf(1), hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0)), gost)); err != nil {
		t.Fatal(err)
	}
	st := h.c.Status()
	if !st.Applied || st.HopErrors != 1 {
		t.Fatalf("status %+v: a hop without a driver must be a hop error next to the applied hops", st)
	}
	report := h.c.Report(context.Background())
	if e := report.GetErrors(); len(e) != 1 || e[0].GetRouteId() != "R2" || e[0].GetEngine() != forwardv1.Engine_ENGINE_GOST {
		t.Fatalf("hop errors %v", e)
	}
}

func TestLinkCertificateHint(t *testing.T) {
	host := fake.NewHost(nil)
	caps := fake.NFTablesCapabilities()
	caps.LinkSecurities = []forwardv1.LinkSecurity{forwardv1.LinkSecurity_LINK_SECURITY_RAW}
	gostDriver := fake.New(host, fake.Options{Engine: forwardv1.Engine_ENGINE_GOST, Capabilities: caps})
	h := newHarness(t, func(o *Options) {
		if err := o.Registry.Register(gostDriver); err != nil {
			t.Fatal(err)
		}
	})
	tls := hop("R3", 1, 30003, rr, up("192.0.2.30", 30004, 0))
	tls.Engine = forwardv1.Engine_ENGINE_GOST
	tls.Role = forwardv1.HopRole_HOP_ROLE_RELAY
	tls.Ingress = &forwardv1.LinkTransport{Security: forwardv1.LinkSecurity_LINK_SECURITY_TLS}
	tls.IngressSources = []string{"192.0.2.1/32"}
	if err := h.apply(1, state(1, hashOf(1), tls)); err != nil {
		t.Fatal(err)
	}
	report := h.c.Report(context.Background())
	if e := report.GetErrors(); len(e) != 1 || !strings.Contains(e[0].GetMessage(), "H28") {
		t.Fatalf("an encrypted gost hop without link certificates: %v", e)
	}
}

func TestHealthFailoverKeepsLastUpstreamAndRecovers(t *testing.T) {
	h := newHarness(t)
	failover := forwardv1.BalanceStrategy_BALANCE_STRATEGY_FAILOVER
	if err := h.apply(1, state(1, hashOf(1), hop("R1", 0, 30001, failover, up("192.0.2.10", 443, 0), up("192.0.2.11", 443, 1)))); err != nil {
		t.Fatal(err)
	}
	only := func(addresses ...string) func() bool {
		return func() bool {
			rot := h.rotation("R1", 0)
			if len(rot) != len(addresses) {
				return false
			}
			for i, a := range addresses {
				if rot[i].Address != a {
					return false
				}
			}
			return true
		}
	}
	// The primary fails twice in a row: its breaker opens and the hop
	// fails over to the backup.
	h.dial.set("192.0.2.10:443", true)
	eventually(t, "failover to the backup", only("192.0.2.11"))
	eventually(t, "a report of the open breaker", func() bool {
		for _, hl := range h.c.Report(context.Background()).GetHealth() {
			if hl.GetAddress() == "192.0.2.10" && hl.GetState() == forwardv1.HealthState_HEALTH_STATE_CIRCUIT_OPEN && hl.GetCircuitOpenUntilUnixMs() > 0 {
				return true
			}
		}
		return false
	})
	// Every upstream down: the hop keeps the last one in rotation.
	h.dial.set("192.0.2.11:443", true)
	eventually(t, "both breakers open", func() bool {
		open := 0
		for _, hl := range h.c.Report(context.Background()).GetHealth() {
			if hl.GetState() == forwardv1.HealthState_HEALTH_STATE_CIRCUIT_OPEN {
				open++
			}
		}
		return open == 2
	})
	time.Sleep(100 * time.Millisecond)
	if !only("192.0.2.11")() {
		t.Fatalf("rotation %v: the hop must keep its last upstream", h.rotation("R1", 0))
	}
	// The primary recovers: after open_ms one trial brings it back.
	h.dial.set("192.0.2.10:443", false)
	eventually(t, "the primary back in rotation", only("192.0.2.10"))
}

func TestReassertRotationAfterChangingApply(t *testing.T) {
	h := newHarness(t)
	ups := []*forwardv1.Upstream{up("192.0.2.10", 443, 0), up("192.0.2.11", 443, 0)}
	h.dial.set("192.0.2.10:443", true)
	if err := h.apply(1, state(1, hashOf(1), hop("R1", 0, 30001, rr, ups...))); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the failing upstream out of rotation", func() bool { return len(h.rotation("R1", 0)) == 1 })
	// A changing apply (another route added) puts every upstream back in
	// the fake, as the drivers do; the loop takes the open one out again.
	if err := h.apply(2, state(2, hashOf(2), hop("R1", 0, 30001, rr, ups...), hop("R2", 0, 30002, rr, up("192.0.2.20", 80, 0)))); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the selection re-asserted", func() bool {
		rot := h.rotation("R1", 0)
		return len(rot) == 1 && rot[0].Address == "192.0.2.11"
	})
}

func TestSetUpstreamsErrorIsRetried(t *testing.T) {
	h := newHarness(t)
	h.dial.set("192.0.2.10:443", true)
	h.host.FailNext(fake.OpSetUpstreams, errors.New("gost is down"))
	if err := h.apply(1, state(1, hashOf(1), hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0), up("192.0.2.11", 443, 0)))); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the selection after a failed SetUpstreams", func() bool { return len(h.rotation("R1", 0)) == 1 })
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
	if err := h.host.AddTraffic(driver.HopKey{RouteID: "R1"}, fake.Traffic{UpBytes: 1000, DownBytes: 2000, NewConns: 3}); err != nil {
		t.Fatal(err)
	}
	h.c.ForwardSession(true)
	eventually(t, "a report at session start", func() bool { return len(h.sent.all()) == 1 })
	first := h.sent.last()
	if first.GetNodeRef() != testNode.String() || first.GetGeneration() != 1 || first.GetStateHash() != hashOf(1) || !first.GetApplied() {
		t.Fatalf("report identity: %v", first)
	}
	if c := first.GetCounters(); len(c) != 1 || c[0].GetUpBytes() != 1000 || c[0].GetDownBytes() != 2000 || c[0].GetTotalConns() != 3 ||
		c[0].GetNodeRef() != testNode.String() || c[0].GetCounterEpoch() == "" {
		t.Fatalf("report counters: %v", c)
	}

	// An apply asks for a report, but not sooner than the minimum gap.
	if err := h.apply(2, state(2, hashOf(2), hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0)))); err != nil {
		t.Fatal(err)
	}
	eventually(t, "a report after the apply", func() bool { return len(h.sent.all()) >= 2 })
	h.sent.mu.Lock()
	gap := h.sent.at[1].Sub(h.sent.at[0])
	h.sent.mu.Unlock()
	if gap < 140*time.Millisecond {
		t.Fatalf("reports %v apart; at most one every 150ms", gap)
	}
	if h.sent.last().GetGeneration() != 2 {
		t.Fatalf("report after the apply: generation %d", h.sent.last().GetGeneration())
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

func TestQuotasEnforcedAfterObserveAndApply(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.ReconcileInterval = time.Hour })
	before := h.driver.enforceCalls.Load()
	if err := h.apply(1, state(1, hashOf(1), hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0)))); err != nil {
		t.Fatal(err)
	}
	afterApply := h.driver.enforceCalls.Load()
	if afterApply <= before {
		t.Fatal("EnforceQuotas was not called after Apply")
	}
	h.c.Report(context.Background())
	if h.driver.enforceCalls.Load() <= afterApply {
		t.Fatal("EnforceQuotas was not called after Observe")
	}
}

func TestRetiredCountersRideInReports(t *testing.T) {
	h := newHarness(t)
	if err := h.apply(1, state(1, hashOf(1), hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0)), hop("R2", 0, 30002, rr, up("192.0.2.20", 80, 0)))); err != nil {
		t.Fatal(err)
	}
	if err := h.host.AddTraffic(driver.HopKey{RouteID: "R2"}, fake.Traffic{UpBytes: 77, DownBytes: 88}); err != nil {
		t.Fatal(err)
	}
	// R2 removed: its last counters leave with the apply ...
	if err := h.apply(2, state(2, hashOf(2), hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0)))); err != nil {
		t.Fatal(err)
	}
	report := h.c.Report(context.Background())
	if err := wire.CheckReport(report, testNode.String()); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, c := range report.GetCounters() {
		if c.GetRouteId() == "R2" && c.GetUpBytes() == 77 && c.GetDownBytes() == 88 {
			found = true
		}
	}
	if !found {
		t.Fatalf("the removed hop's last counters are not in the report: %v", report.GetCounters())
	}
	// ... and ride along in the next reports too (no ack exists).
	if !strings.Contains(h.c.Report(context.Background()).String(), "R2") {
		t.Fatal("the retired counters left after one report")
	}
}

func TestLeastConnReweighting(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.ReweightInterval = 50 * time.Millisecond })
	lc := forwardv1.BalanceStrategy_BALANCE_STRATEGY_LEAST_CONN
	if err := h.apply(1, state(1, hashOf(1), hop("R1", 0, 30001, lc, up("192.0.2.10", 443, 0), up("192.0.2.11", 443, 0), up("192.0.2.12", 443, 0)))); err != nil {
		t.Fatal(err)
	}
	h.host.SetUpstreamConns(map[netip.AddrPort]uint64{netip.MustParseAddrPort("192.0.2.10:443"): 9})
	weight := func(address string) uint32 {
		for _, u := range h.rotation("R1", 0) {
			if u.Address == address {
				return u.Weight
			}
		}
		return 0
	}
	eventually(t, "least-connections weights", func() bool { return weight("192.0.2.10") > 0 && weight("192.0.2.10") < weight("192.0.2.11") })
	// A failing upstream leaves rotation, and the weighting covers only the
	// healthy ones.
	h.dial.set("192.0.2.12:443", true)
	eventually(t, "the failing upstream out of the least-connections hop", func() bool { return len(h.rotation("R1", 0)) == 2 && weight("192.0.2.12") == 0 })
}

func TestHelloCapability(t *testing.T) {
	h := newHarness(t, func(o *Options) {
		o.Unavailable = []*forwardv1.EngineCapabilities{{Engine: forwardv1.Engine_ENGINE_GOST, UnavailableReason: "gost is not installed"}}
	})
	capability, err := h.c.HelloCapability()
	if err != nil {
		t.Fatal(err)
	}
	caps, listed, err := wire.NodeCapabilitiesFromHello([]*agentv1pb.Capability{capability}, testNode.String())
	if err != nil || !listed {
		t.Fatalf("capability %v: listed %v, %v", capability, listed, err)
	}
	if len(caps.GetEngines()) != 2 || !caps.GetEngines()[0].GetAvailable() || caps.GetEngines()[1].GetAvailable() ||
		caps.GetEngines()[1].GetUnavailableReason() != "gost is not installed" || caps.GetKernelVersion() != "6.12.0" || caps.GetAgentVersion() != "test" {
		t.Fatalf("node capabilities %v", caps)
	}
}
