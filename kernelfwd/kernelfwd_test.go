package kernelfwd

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
)

func forwards() ([]*networkv1.KernelForward, map[string][]*target) {
	addr := netip.MustParseAddr
	list := []*networkv1.KernelForward{
		{Id: "R1", Listen: &networkv1.Endpoint{Address: "::", Port: 20022}, Protocols: []string{"tcp", "udp"},
			Policy: &networkv1.ForwardPolicy{Balance: "ip_hash"}},
		{Id: "R2", Listen: &networkv1.Endpoint{Address: "10.0.0.1", Port: 443}, Protocols: []string{"tcp"}},
	}
	targets := map[string][]*target{
		"R1": {
			{host: "a", port: 30022, weight: 2, addrs: []netip.Addr{addr("203.0.113.1"), addr("2001:db8::1")}},
			{host: "b", port: 30022, weight: 1, addrs: []netip.Addr{addr("203.0.113.2")}},
		},
		"R2": {
			{host: "c", port: 8443, weight: 1, addrs: []netip.Addr{addr("198.51.100.9")}},
			{host: "d", port: 8443, weight: 1, addrs: []netip.Addr{addr("198.51.100.10")},
				health: health{state: networkv1.TargetHealthState_TARGET_HEALTH_STATE_UNHEALTHY}},
		},
	}
	return list, targets
}

func TestRender(t *testing.T) {
	list, targets := forwards()
	rules, v6 := render(list, targets)
	if !v6 {
		t.Fatal("R1 has an IPv6 target")
	}
	for _, want := range []string{
		"meta l4proto { tcp, udp } th dport 20022 fib daddr type local dnat ip addr . port to jhash ip saddr mod 3 map { 0 : 203.0.113.1 . 30022, 1 : 203.0.113.1 . 30022, 2 : 203.0.113.2 . 30022 }",
		"meta l4proto { tcp, udp } th dport 20022 fib daddr type local dnat ip6 to [2001:db8::1]:30022",
		// The unhealthy target is left out; the listen address is matched.
		"ip daddr 10.0.0.1 meta l4proto tcp th dport 443 fib daddr type local dnat ip to 198.51.100.9:8443",
		"meta l4proto tcp ct status dnat ct original proto-dst 443 masquerade",
		"ct original proto-dst 20022 ct direction reply counter name d_R1",
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("missing %q in\n%s", want, rules)
		}
	}
	if strings.Contains(rules, "ip6 daddr") || strings.Count(rules, "dnat ip") != 3 {
		t.Errorf("R2 listens on IPv4 only:\n%s", rules)
	}
	// Every target down: all of them are used.
	targets["R2"][0].health.state = networkv1.TargetHealthState_TARGET_HEALTH_STATE_UNHEALTHY
	if rules, _ := render(list, targets); !strings.Contains(rules, "numgen inc mod 2") {
		t.Errorf("every target is down, so both are used:\n%s", rules)
	}
}

func TestApplyKeepsCountersAndDeletesTheTable(t *testing.T) {
	proc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "net/ipv4"), 0o755); err != nil {
		t.Fatal(err)
	}
	var scripts []string
	m := &Manager{Proc: proc, NFT: func(stdin string, args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "-j list counters table inet " + Table:
			return []byte(`{"nftables":[{"metainfo":{}},{"counter":{"family":"inet","name":"u_R2","table":"edge_nat","packets":3,"bytes":700}}]}`), nil
		case "-f -":
			scripts = append(scripts, stdin)
		default:
			scripts = append(scripts, strings.Join(args, " "))
		}
		return nil, nil
	}}
	list, _ := forwards()
	list[1].Targets = []*networkv1.ForwardTarget{{Host: "198.51.100.9", Port: 8443}}
	list[1].Policy = &networkv1.ForwardPolicy{Health: &networkv1.ForwardHealth{Disabled: true}}
	if err := m.Apply(list[1:]); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if len(scripts) != 1 || !strings.Contains(scripts[0], "counter u_R2 { packets 3 bytes 700 }") ||
		!strings.Contains(scripts[0], "dnat ip to 198.51.100.9:8443") {
		t.Fatalf("scripts: %q", scripts)
	}
	if on, _ := os.ReadFile(filepath.Join(proc, "net/ipv4/ip_forward")); string(on) != "1" {
		t.Fatal("IPv4 forwarding is not on")
	}
	status := m.Status()
	if len(status) != 1 || status[0].GetUpBytes() != 700 || status[0].GetState() != networkv1.ComponentState_COMPONENT_STATE_APPLIED ||
		len(status[0].GetTargets()) != 1 || status[0].GetTargets()[0].GetHost() != "198.51.100.9" {
		t.Fatalf("status: %v", status)
	}
	if err := m.Apply(nil); err != nil || scripts[len(scripts)-1] != "delete table inet "+Table {
		t.Fatalf("no forwards delete the table: %v %q", err, scripts)
	}
}
