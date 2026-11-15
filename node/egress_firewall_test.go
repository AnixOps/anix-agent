package node

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/stretchr/testify/require"
)

func TestRelayFirewallLetsOnlyTheSourcesReachARelay(t *testing.T) {
	lookup := lookupHost
	t.Cleanup(func() { lookupHost = lookup })
	lookupHost = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "hk.example" {
			return []netip.Addr{netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("2001:db8::9")}, nil
		}
		return nil, errors.New("no such host")
	}

	script, rules, err := relayFirewallScript(context.Background(), []panel.EgressRelay{
		{ID: 1, Port: 24680, Allow: []string{"hk.example", "198.51.100.7"}},
		{ID: 2, Port: 24681, Allow: []string{"198.51.100.7"}},
		{ID: 3, Port: 24682}, // no sources: left open
	})
	require.NoError(t, err)
	require.True(t, rules)
	require.Equal(t, "table inet anixops_egress {}\ndelete table inet anixops_egress\n"+
		"table inet anixops_egress {\n\tchain input {\n\t\ttype filter hook input priority -5; policy accept;\n"+
		"\t\tmeta nfproto ipv4 meta l4proto { tcp, udp } th dport 24680 ip saddr != { 198.51.100.7, 203.0.113.9 } drop\n"+
		"\t\tmeta nfproto ipv6 meta l4proto { tcp, udp } th dport 24680 ip6 saddr != { 2001:db8::9 } drop\n"+
		"\t\tmeta nfproto ipv4 meta l4proto { tcp, udp } th dport 24681 ip saddr != { 198.51.100.7 } drop\n"+
		"\t\tmeta nfproto ipv6 meta l4proto { tcp, udp } th dport 24681 drop\n"+
		"\t}\n}\n", script)

	_, _, err = relayFirewallScript(context.Background(), []panel.EgressRelay{{ID: 1, Port: 24680, Allow: []string{"gone.example"}}})
	require.ErrorContains(t, err, "resolve gone.example")
}

func TestRelayFirewallRemovesOnlyATableItInstalled(t *testing.T) {
	run := runNFT
	t.Cleanup(func() { runNFT = run })
	var scripts []string
	runNFT = func(_ context.Context, script string) error {
		scripts = append(scripts, script)
		return nil
	}
	plane := newNodeDataPlane(57, nil)
	open := &panel.EgressConfig{Relays: []panel.EgressRelay{{ID: 1, Port: 24680}}}
	require.NoError(t, plane.applyRelayFirewall(open))
	require.Empty(t, scripts)

	allow := &panel.EgressConfig{Relays: []panel.EgressRelay{{ID: 1, Port: 24680, Allow: []string{"203.0.113.9"}}}}
	require.NoError(t, plane.applyRelayFirewall(allow))
	require.NoError(t, plane.applyRelayFirewall(nil))
	require.Len(t, scripts, 2)
	require.Equal(t, "table inet anixops_egress {}\ndelete table inet anixops_egress\n", scripts[1])
	require.NoError(t, plane.applyRelayFirewall(nil))
	require.Len(t, scripts, 2)
}

func TestEgressRelayAllowMustBeAnAddressOrHostName(t *testing.T) {
	config := &panel.EgressConfig{Relays: []panel.EgressRelay{{ID: 1, Port: 24680, Method: "2022-blake3-aes-128-gcm", Password: "k", Allow: []string{"1.2.3.4 } accept"}}}}
	require.ErrorContains(t, config.Validate(), "not an address or host name")
}
