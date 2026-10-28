package forward

import (
	"context"
	"testing"

	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
)

func vantageProbe(address string, port uint32) *forwardv1.VantageProbe {
	return &forwardv1.VantageProbe{
		BindingId: 4, RouteId: "R9", NodeRef: "forward-11", Address: address, Port: port, IntervalMs: 20, TimeoutMs: 20,
	}
}

// Vantage probes: only the probes the state names are dialled, never a
// private address; a probe is judged after three dials in a row and every
// report carries the judged probes.
func TestVantageProbesAreDialledAndReported(t *testing.T) {
	h := newHarness(t)
	h.dial.set("192.0.2.51:31000", true)
	s := state(1, hashOf(1), hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0)))
	s.VantageProbes = []*forwardv1.VantageProbe{
		vantageProbe("192.0.2.50", 31000), vantageProbe("192.0.2.51", 31000), vantageProbe("10.0.0.1", 31000),
	}
	if err := h.apply(1, s); err != nil {
		t.Fatal(err)
	}
	judged := func() map[string]forwardv1.HealthState {
		out := map[string]forwardv1.HealthState{}
		for _, r := range h.c.Report(context.Background()).GetVantage() {
			out[r.GetAddress()] = r.GetState()
		}
		return out
	}
	eventually(t, "both public probes judged", func() bool {
		got := judged()
		return got["192.0.2.50"] == forwardv1.HealthState_HEALTH_STATE_HEALTHY && got["192.0.2.51"] == forwardv1.HealthState_HEALTH_STATE_UNHEALTHY
	})
	if got := judged(); len(got) != 2 {
		t.Fatalf("judged %v: a private address is never probed", got)
	}
	if n := h.dial.dials("10.0.0.1:31000"); n != 0 {
		t.Fatalf("dialled a private address %d times", n)
	}
	h.c.ForwardSession(true)
	eventually(t, "a sent report with the results", func() bool {
		return len(h.sent.last().GetVantage()) == 2
	})
	for _, r := range h.sent.last().GetVantage() {
		if r.GetBindingId() != 4 || r.GetRouteId() != "R9" || r.GetNodeRef() != "forward-11" || r.GetPort() != 31000 || r.GetCheckedAtUnixMs() == 0 {
			t.Fatalf("result %v", r)
		}
	}

	// The target recovers: three successes bring it back.
	h.dial.set("192.0.2.51:31000", false)
	eventually(t, "the recovered probe healthy", func() bool {
		return judged()["192.0.2.51"] == forwardv1.HealthState_HEALTH_STATE_HEALTHY
	})

	// A state without the probes forgets them.
	if err := h.apply(2, state(2, hashOf(2), hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0)))); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the probes forgotten", func() bool { return len(judged()) == 0 })
}

func TestVantageTargetIsGlobalUnicastOnly(t *testing.T) {
	for address, ok := range map[string]bool{
		"203.0.113.7": true, "2001:db8::1": true, "::ffff:198.51.100.1": true,
		"10.1.2.3": false, "192.168.1.1": false, "127.0.0.1": false, "169.254.1.1": false, "224.0.0.1": false,
		"fe80::1%eth0": false, "fd00::1": false, "example.com": false, "0.0.0.0": false,
	} {
		if _, got := vantageTarget(vantageProbe(address, 443)); got != ok {
			t.Errorf("%s: %v, want %v", address, got, ok)
		}
	}
	if _, got := vantageTarget(vantageProbe("203.0.113.7", 0)); got {
		t.Error("port 0 accepted")
	}
}
