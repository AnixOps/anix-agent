package forward

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"github.com/AnixOps/anix-control/sdk/forward/driver/fake"
)

// hostCommands answers ss and nft from canned output.
type hostCommands struct {
	mu    sync.Mutex
	ss    string
	ssP   string
	nft   string
	nftOK bool
	calls []string
}

func (h *hostCommands) run(_ context.Context, name string, args ...string) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, name+" "+strings.Join(args, " "))
	switch name {
	case "ss":
		if len(args) > 0 && args[len(args)-1] == "-p" {
			return []byte(h.ssP), nil
		}
		return []byte(h.ss), nil
	case "nft":
		if !h.nftOK {
			return nil, errors.New("nft: command not found")
		}
		return []byte(h.nft), nil
	}
	return nil, errors.New("unexpected command " + name)
}

func diagHarness(t *testing.T, commands *hostCommands, mutate ...func(*Options)) *harness {
	t.Helper()
	return newHarness(t, append([]func(*Options){func(o *Options) {
		o.Run = commands.run
		o.Lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
			switch host {
			case "public.example":
				return []netip.Addr{netip.MustParseAddr("198.51.100.20")}, nil
			case "intranet.example":
				return []netip.Addr{netip.MustParseAddr("198.51.100.21"), netip.MustParseAddr("10.1.2.3")}, nil
			}
			return nil, errors.New("no such host")
		}
	}}, mutate...)...)
}

func params(route string, hop uint32, extra ...any) map[string]any {
	p := map[string]any{"route_id": route, "hop_index": float64(hop), "timeout_ms": float64(300)}
	for i := 0; i+1 < len(extra); i += 2 {
		p[extra[i].(string)] = extra[i+1]
	}
	return p
}

func TestDiagnoseRefusals(t *testing.T) {
	h := diagHarness(t, &hostCommands{})
	_, err := h.c.Diagnose(context.Background(), "service_status", params("r1", 0))
	if err == nil {
		t.Fatal("a generic action is not a forward check")
	}
	for name, p := range map[string]map[string]any{
		"no route":   {"hop_index": float64(0)},
		"bad hop":    {"route_id": "r1", "hop_index": float64(9)},
		"bad policy": {"route_id": "r1", "hop_index": float64(0), "target_policy": "any"},
	} {
		if _, err := h.c.Diagnose(context.Background(), CheckConnect, p); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	// A hop the state does not hold.
	result, err := h.c.Diagnose(context.Background(), CheckListen, params("r1", 0))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != VerdictFailed || result.Code != "hop_not_applied" {
		t.Fatalf("got %+v", result)
	}
}

func TestDiagnoseListenAndConflicts(t *testing.T) {
	commands := &hostCommands{
		ss: "tcp LISTEN 0 4096 *:31001 *:*\n",
		ssP: "tcp LISTEN 0 4096 0.0.0.0:31000 0.0.0.0:* users:((\"nginx\",pid=812,fd=6))\n" +
			"tcp LISTEN 0 4096 *:31001 *:* users:((\"gost\",pid=900,fd=7))\n",
		nftOK: true,
		nft: `{"nftables":[{"metainfo":{"version":"1.0.9"}},
 {"rule":{"family":"ip","table":"nat","chain":"PREROUTING","handle":4,"expr":[
   {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"set":[80,{"range":[30990,31010]}]}}},
   {"dnat":{"addr":"10.0.0.2"}}]}},
 {"rule":{"family":"inet","table":"anixops_fwd","chain":"prerouting","handle":9,"expr":[
   {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":31000}},{"dnat":{"addr":"198.51.100.1"}}]}},
 {"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":2,"expr":[
   {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":31000}},{"accept":null}]}}]}`,
	}
	h := diagHarness(t, commands, func(o *Options) {
		if err := o.Registry.Register(fake.New(fake.NewHost(nil), fake.Options{Engine: forwardv1.Engine_ENGINE_GOST})); err != nil {
			t.Fatal(err)
		}
	})
	nft := hop("r1", 0, 31000, forwardv1.BalanceStrategy_BALANCE_STRATEGY_ROUND_ROBIN, up("192.0.2.2", 32000, 0))
	gost := hop("r2", 0, 31001, forwardv1.BalanceStrategy_BALANCE_STRATEGY_ROUND_ROBIN, up("192.0.2.2", 32001, 0))
	gost.Engine = forwardv1.Engine_ENGINE_GOST
	if err := h.apply(1, state(5, hashOf(1), nft, gost)); err != nil {
		t.Fatal(err)
	}

	listen, err := h.c.Diagnose(context.Background(), CheckListen, params("r1", 0, "generation", float64(5)))
	if err != nil {
		t.Fatal(err)
	}
	if listen.Status != VerdictOK || len(listen.Items) != 1 || listen.Items[0].Code != "listening" || listen.Generation != 5 {
		t.Fatalf("nftables listen: %+v", listen)
	}
	gostListen, _ := h.c.Diagnose(context.Background(), CheckListen, params("r2", 0))
	if gostListen.Status != VerdictOK || gostListen.Items[0].Target != "*:31001" {
		t.Fatalf("gost listen: %+v", gostListen)
	}
	commands.ss = ""
	gostListen, _ = h.c.Diagnose(context.Background(), CheckListen, params("r2", 0))
	if gostListen.Status != VerdictFailed || gostListen.Items[0].Code != "not_listening" {
		t.Fatalf("gost not listening: %+v", gostListen)
	}

	conflicts, _ := h.c.Diagnose(context.Background(), CheckPortConflict, params("r1", 0))
	if conflicts.Status != VerdictFailed || len(conflicts.Items) != 2 {
		t.Fatalf("conflicts: %+v", conflicts)
	}
	if conflicts.Items[0].Code != "foreign_listener" || !strings.Contains(conflicts.Items[0].Message, "nginx") {
		t.Errorf("listener: %+v", conflicts.Items[0])
	}
	if conflicts.Items[1].Code != "foreign_nat_rule" || !strings.Contains(conflicts.Items[1].Message, "table ip nat chain PREROUTING") {
		t.Errorf("nat rule: %+v", conflicts.Items[1])
	}
	// gost's own socket is not a conflict; the nat rule's range does not
	// reach 31001? It does (30990-31010): reported.
	gostConflicts, _ := h.c.Diagnose(context.Background(), CheckPortConflict, params("r2", 0))
	if len(gostConflicts.Items) != 1 || gostConflicts.Items[0].Code != "foreign_nat_rule" {
		t.Fatalf("gost conflicts: %+v", gostConflicts)
	}
	commands.nft = `{"nftables":[]}`
	commands.ssP = ""
	clean, _ := h.c.Diagnose(context.Background(), CheckPortConflict, params("r1", 0))
	if clean.Status != VerdictOK || len(clean.Items) != 0 {
		t.Fatalf("clean: %+v", clean)
	}
	commands.nftOK = false
	missing, _ := h.c.Diagnose(context.Background(), CheckPortConflict, params("r1", 0))
	if missing.Status != VerdictInconclusive || missing.Items[0].Code != "nft_unavailable" {
		t.Fatalf("no nft: %+v", missing)
	}
}

func TestDiagnoseConnect(t *testing.T) {
	h := diagHarness(t, &hostCommands{})
	h.dial.set("198.51.100.11:443", true)
	exit := hop("r1", 1, 31000, forwardv1.BalanceStrategy_BALANCE_STRATEGY_ROUND_ROBIN,
		up("198.51.100.10", 443, 0), up("198.51.100.11", 443, 0), up("public.example", 443, 0), up("intranet.example", 443, 0), up("10.0.0.9", 22, 0))
	exit.Role = forwardv1.HopRole_HOP_ROLE_EXIT
	if err := h.apply(1, state(3, hashOf(2), exit)); err != nil {
		t.Fatal(err)
	}
	result, err := h.c.Diagnose(context.Background(), CheckConnect, params("r1", 1))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != VerdictFailed || len(result.Items) != 5 {
		t.Fatalf("connect: %+v", result)
	}
	want := []struct{ status, code string }{
		{VerdictOK, "reachable"}, {VerdictFailed, "unreachable"}, {VerdictOK, "reachable"},
		{VerdictSkipped, "target_not_allowed"}, {VerdictSkipped, "target_not_allowed"},
	}
	for i, w := range want {
		if result.Items[i].Status != w.status || result.Items[i].Code != w.code {
			t.Errorf("item %d: got %+v, want %s/%s", i, result.Items[i], w.status, w.code)
		}
	}
	if result.Items[0].RTTMicro == 0 || result.Message != "2 of 5 upstreams reachable" {
		t.Errorf("rtt and summary: %+v", result)
	}
	// Control's allow_private does not override the hop's public policy.
	again, _ := h.c.Diagnose(context.Background(), CheckConnect, params("r1", 1, "target_policy", "allow_private", "upstream", "10.0.0.9:22"))
	if len(again.Items) != 1 || again.Items[0].Code != "target_not_allowed" || again.Status != VerdictSkipped {
		t.Fatalf("narrowed: %+v", again)
	}
	// Narrowing to an address that is not an upstream dials nothing.
	unknown, _ := h.c.Diagnose(context.Background(), CheckConnect, params("r1", 1, "upstream", "203.0.113.5:22"))
	if unknown.Code != "unknown_upstream" || h.dial.dials("203.0.113.5:22") != 0 {
		t.Fatalf("unknown upstream: %+v", unknown)
	}

	// An administrator's ALLOW_PRIVATE hop, and Control allowing it.
	exit.TargetPolicy = forwardv1.TargetPolicy_TARGET_POLICY_ALLOW_PRIVATE
	if err := h.apply(2, state(4, hashOf(3), exit)); err != nil {
		t.Fatal(err)
	}
	private, _ := h.c.Diagnose(context.Background(), CheckConnect, params("r1", 1, "target_policy", "allow_private", "upstream", "10.0.0.9:22"))
	if private.Status != VerdictOK || private.Items[0].Code != "reachable" {
		t.Fatalf("allowed private: %+v", private)
	}
	public, _ := h.c.Diagnose(context.Background(), CheckConnect, params("r1", 1, "upstream", "10.0.0.9:22"))
	if public.Items[0].Code != "target_not_allowed" {
		t.Fatalf("Control's public_only wins: %+v", public)
	}
}

// udpEcho answers every datagram on a loopback port.
func udpEcho(t *testing.T) (answering, silent uint32) {
	t.Helper()
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	quiet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close(); _ = quiet.Close() })
	go func() {
		buffer := make([]byte, 512)
		for {
			n, from, err := echo.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(buffer[:n], from)
		}
	}()
	port := func(c net.PacketConn) uint32 {
		_, p, _ := net.SplitHostPort(c.LocalAddr().String())
		n, _ := strconv.Atoi(p)
		return uint32(n) // #nosec G115 -- a port.
	}
	return port(echo), port(quiet)
}

func TestDiagnoseUDPProbe(t *testing.T) {
	answering, silent := udpEcho(t)
	h := diagHarness(t, &hostCommands{}, func(o *Options) {
		var d net.Dialer
		o.Dial = d.DialContext
	})
	// Next-hop nodes (node_ref set) are dialled as planned: loopback is fine.
	entry := hop("r1", 0, 31000, forwardv1.BalanceStrategy_BALANCE_STRATEGY_ROUND_ROBIN,
		&forwardv1.Upstream{Address: "127.0.0.1", Port: answering, Weight: 1, NodeRef: "forward-42"},
		&forwardv1.Upstream{Address: "127.0.0.1", Port: silent, Weight: 1, NodeRef: "forward-43"})
	entry.Listen.Protocol = forwardv1.L4Protocol_L4_PROTOCOL_UDP
	if err := h.apply(1, state(2, hashOf(4), entry)); err != nil {
		t.Fatal(err)
	}
	began := time.Now()
	result, err := h.c.Diagnose(context.Background(), CheckUDPProbe, params("r1", 0))
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(began) > 2*time.Second {
		t.Error("the probes run at once, within the timeout")
	}
	if len(result.Items) != 2 || result.Items[0].Code != "reply" || result.Items[0].Protocol != "udp" {
		t.Fatalf("udp: %+v", result)
	}
	if result.Items[1].Status != VerdictInconclusive || result.Items[1].Code != "no_reply" {
		t.Fatalf("no reply is inconclusive: %+v", result.Items[1])
	}
	if result.Status != VerdictInconclusive {
		t.Fatalf("verdict: %+v", result)
	}
}

// A next hop is probed on its link's carrier only.
func TestDiagnoseLinkCarriers(t *testing.T) {
	h := diagHarness(t, &hostCommands{})
	quic := &forwardv1.Upstream{Address: "192.0.2.42", Port: 32000, Weight: 1, NodeRef: "forward-42",
		Egress: &forwardv1.LinkTransport{Security: forwardv1.LinkSecurity_LINK_SECURITY_QUIC}}
	tls := &forwardv1.Upstream{Address: "192.0.2.43", Port: 32001, Weight: 1, NodeRef: "forward-43",
		Egress: &forwardv1.LinkTransport{Security: forwardv1.LinkSecurity_LINK_SECURITY_TLS}}
	entry := hop("r1", 0, 31000, forwardv1.BalanceStrategy_BALANCE_STRATEGY_ROUND_ROBIN, quic, tls)
	entry.Engine = forwardv1.Engine_ENGINE_NFTABLES
	h.c.mu.Lock()
	h.c.desired = state(2, hashOf(5), entry)
	h.c.mu.Unlock()
	connect, _ := h.c.Diagnose(context.Background(), CheckConnect, params("r1", 0))
	if connect.Items[0].Code != "link_not_tcp" || connect.Items[1].Code != "reachable" {
		t.Fatalf("connect: %+v", connect)
	}
	probe, _ := h.c.Diagnose(context.Background(), CheckUDPProbe, params("r1", 0, "upstream", "192.0.2.43:32001"))
	if probe.Items[0].Code != "link_not_udp" || probe.Status != VerdictSkipped {
		t.Fatalf("udp: %+v", probe)
	}
}
