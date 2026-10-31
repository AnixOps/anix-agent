package networkroute

import (
	"net/netip"
	"strings"
	"testing"

	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func routedPlan() *networkv1.NetworkPlan {
	return &networkv1.NetworkPlan{
		Lines: []*networkv1.Line{
			{Id: "ln-cn2", Interface: "eth1", GatewayV4: "198.51.100.1", GatewayV6: "2001:db8::1"},
			{Id: "ln-def", Interface: "eth0", GatewayV4: "192.0.2.1"},
		},
		Egresses: []*networkv1.Egress{
			{Id: "eg-b", LineId: "ln-cn2", Source: "198.51.100.10"},
			{Id: "eg-a", LineId: "ln-cn2", Source: "2001:db8::10", Routing: &networkv1.Routing{Table: 20000}},
			{Id: "eg-auto", LineId: "ln-def", Source: "auto"},
			{Id: "eg-c", LineId: "ln-cn2", Source: "198.51.100.11", Gateway: "198.51.100.254", Routing: &networkv1.Routing{RulePriority: 20005}},
		},
	}
}

func TestRoutesAllocateInTheRange(t *testing.T) {
	routes, err := Routes(routedPlan(), 20000, 20999)
	require.NoError(t, err)
	require.Len(t, routes, 3, "an auto source needs no route")
	assert.Equal(t, Route{Egress: "eg-a", Source: netip.MustParseAddr("2001:db8::10"), Interface: "eth1",
		Gateway: netip.MustParseAddr("2001:db8::1"), Table: 20000, Priority: 20000}, routes[0])
	assert.Equal(t, Route{Egress: "eg-b", Source: netip.MustParseAddr("198.51.100.10"), Interface: "eth1",
		Gateway: netip.MustParseAddr("198.51.100.1"), Table: 20001, Priority: 20001}, routes[1])
	assert.Equal(t, Route{Egress: "eg-c", Source: netip.MustParseAddr("198.51.100.11"), Interface: "eth1",
		Gateway: netip.MustParseAddr("198.51.100.254"), Table: 20002, Priority: 20005}, routes[2])

	_, err = Routes(routedPlan(), 20001, 20001)
	require.Error(t, err)
	plan := routedPlan()
	plan.Egresses = plan.Egresses[:2]
	_, err = Routes(plan, 20000, 20000)
	require.ErrorContains(t, err, "full")
	plan.Lines[0].Interface = ""
	_, err = Routes(plan, 20000, 20999)
	require.ErrorContains(t, err, "no interface")
}

// fakeIP answers `ip -j rule show` from rules and records the other calls.
type fakeIP struct {
	rules map[string]string
	calls []string
}

func (f *fakeIP) run(name string, args ...string) ([]byte, error) {
	call := strings.Join(args, " ")
	if strings.HasPrefix(call, "-j ") {
		return []byte(f.rules[args[1]]), nil
	}
	f.calls = append(f.calls, call)
	return nil, nil
}

// Apply adds the missing rules and every default route, keeps the rules
// already there, and removes the range's other rules with their tables,
// leaving rules outside the range alone.
func TestApplyReconcilesTheRange(t *testing.T) {
	ip := &fakeIP{rules: map[string]string{
		"-4": `[{"priority":0,"src":"all","table":"local"},
			{"priority":20001,"src":"198.51.100.10","srclen":32,"table":"20001"},
			{"priority":20009,"src":"198.51.100.99","srclen":32,"table":"20009"},
			{"priority":32766,"src":"all","table":"main"}]`,
		"-6": `[]`,
	}}
	manager := &Manager{IP: "ip", Run: ip.run, First: 20000, Last: 20999}
	routes, err := Routes(routedPlan(), 20000, 20999)
	require.NoError(t, err)
	require.NoError(t, manager.Apply(routes))
	assert.Equal(t, []string{
		"-4 rule delete priority 20009 from 198.51.100.99/32 table 20009",
		"-4 route flush table 20009",
		"-4 route replace default via 198.51.100.1 dev eth1 src 198.51.100.10 table 20001",
		"-4 route replace default via 198.51.100.254 dev eth1 src 198.51.100.11 table 20002",
		"-4 rule add from 198.51.100.11/32 table 20002 priority 20005",
		"-6 route replace default via 2001:db8::1 dev eth1 src 2001:db8::10 table 20000",
		"-6 rule add from 2001:db8::10/128 table 20000 priority 20000",
	}, ip.calls)

	// No routes removes every rule of the range.
	ip.calls = nil
	require.NoError(t, manager.Apply(nil))
	assert.Equal(t, []string{
		"-4 rule delete priority 20001 from 198.51.100.10/32 table 20001",
		"-4 route flush table 20001",
		"-4 rule delete priority 20009 from 198.51.100.99/32 table 20009",
		"-4 route flush table 20009",
	}, ip.calls)
}

// A dual-NIC entry: two uplink egresses towards one next device share
// their uplink's table with any other egress on the same source, and the
// dialing transport's peer is routed through the chosen uplink, after
// every from rule; a moved peer rule goes without flushing a table still
// in use.
func TestRoutesSendTransportPeersThroughTheirEgress(t *testing.T) {
	lookups, lookup := 0, LookupHost
	LookupHost = func(host string) ([]netip.Addr, error) {
		lookups++
		require.Equal(t, "jp.example.com", host)
		return []netip.Addr{netip.MustParseAddr("203.0.113.50"), netip.MustParseAddr("2001:db8::50")}, nil
	}
	t.Cleanup(func() { LookupHost = lookup })
	plan := &networkv1.NetworkPlan{
		Lines: []*networkv1.Line{
			{Id: "up-cn2", Interface: "eth0", GatewayV4: "10.0.0.1"},
			{Id: "up-cu", Interface: "eth1", GatewayV4: "10.0.1.1"},
		},
		Egresses: []*networkv1.Egress{
			{Id: "auto-proxy-62-up-cn2-proxy-50", LineId: "up-cn2", Source: "10.0.0.2"},
			{Id: "auto-proxy-62-up-cn2-proxy-57", LineId: "up-cn2", Source: "10.0.0.2"},
			{Id: "auto-proxy-62-up-cu-proxy-50", LineId: "up-cu", Source: "10.0.1.2"},
		},
		Transports: []*networkv1.Transport{
			{Id: "auto-proxy-62-proxy-50", Role: networkv1.TransportRole_TRANSPORT_ROLE_DIAL, FromEgressId: "auto-proxy-62-up-cu-proxy-50",
				Settings: &networkv1.Transport_AnxLine{AnxLine: &networkv1.AnxLineSettings{TcpAddr: "jp.example.com:24443"}}},
			{Id: "auto-proxy-62-proxy-57", Role: networkv1.TransportRole_TRANSPORT_ROLE_DIAL, FromEgressId: "auto-proxy-62-up-cn2-proxy-57",
				Settings: &networkv1.Transport_AnxLine{AnxLine: &networkv1.AnxLineSettings{TcpAddr: "198.51.100.57:24443"}}},
			{Id: "rev", Role: networkv1.TransportRole_TRANSPORT_ROLE_DIAL, FromEgressId: "auto-proxy-62-up-cn2-proxy-50",
				Settings: &networkv1.Transport_AnxLine{AnxLine: &networkv1.AnxLineSettings{Reverse: true, ReverseListen: "0.0.0.0:24444"}}},
		},
	}
	routes, err := Routes(plan, 20000, 20999)
	require.NoError(t, err)
	require.Equal(t, 1, lookups)
	require.Len(t, routes, 2, "one route per uplink")
	assert.Equal(t, Route{Egress: "auto-proxy-62-up-cn2-proxy-50", Source: netip.MustParseAddr("10.0.0.2"), Interface: "eth0",
		Gateway: netip.MustParseAddr("10.0.0.1"), Table: 20000, Priority: 20000,
		To: []netip.Prefix{netip.MustParsePrefix("198.51.100.57/32")}, ToPriority: 20999}, routes[0])
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("203.0.113.50/32")}, routes[1].To, "only the egress's family")

	ip := &fakeIP{rules: map[string]string{
		"-4": `[{"priority":20000,"src":"10.0.0.2","srclen":32,"table":"20000"},
			{"priority":20999,"src":"all","dst":"203.0.113.50","dstlen":32,"table":"20000"}]`,
		"-6": `[]`,
	}}
	manager := &Manager{IP: "ip", Run: ip.run, First: 20000, Last: 20999}
	require.NoError(t, manager.Apply(routes))
	assert.Equal(t, []string{
		"-4 rule delete priority 20999 to 203.0.113.50/32 table 20000",
		"-4 route replace default via 10.0.0.1 dev eth0 src 10.0.0.2 table 20000",
		"-4 rule add to 198.51.100.57/32 table 20000 priority 20999",
		"-4 route replace default via 10.0.1.1 dev eth1 src 10.0.1.2 table 20001",
		"-4 rule add from 10.0.1.2/32 table 20001 priority 20001",
		"-4 rule add to 203.0.113.50/32 table 20001 priority 20999",
	}, ip.calls)
}
