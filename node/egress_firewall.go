package node

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
)

// relayFirewallTable is the nftables table that lets only an egress relay's
// source nodes reach its port: every other address is dropped, TCP and UDP.
// It runs before the host's own firewall, whose policy it does not change.
const relayFirewallTable = "anixops_egress"

// lookupHost resolves a source node's host name; a variable for tests.
var lookupHost = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// runNFT runs an nft script; a variable for tests.
var runNFT = func(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// applyRelayFirewall replaces the table with the rules of the relays that
// name their sources (panel.EgressRelay.Allow); with none it removes a table
// it installed before.
func (n *nodeDataPlane) applyRelayFirewall(egress *panel.EgressConfig) error {
	var relays []panel.EgressRelay
	if egress != nil {
		relays = egress.Relays
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	script, rules, err := relayFirewallScript(ctx, relays)
	if err != nil || (!rules && !n.relayFirewall) {
		return err
	}
	if err := runNFT(ctx, script); err != nil {
		return err
	}
	n.relayFirewall = rules
	return nil
}

// relayFirewallScript is the nft script that replaces the table in one
// transaction, and whether it holds rules (without, it only removes the
// table).
func relayFirewallScript(ctx context.Context, relays []panel.EgressRelay) (string, bool, error) {
	var rules []string
	for _, relay := range relays {
		if len(relay.Allow) == 0 {
			continue
		}
		var v4, v6 []string
		for _, source := range relay.Allow {
			addrs, err := sourceAddrs(ctx, source)
			if err != nil {
				return "", false, fmt.Errorf("relay %d: %w", relay.ID, err)
			}
			for _, addr := range addrs {
				if addr = addr.Unmap(); addr.Is4() {
					v4 = append(v4, addr.String())
				} else {
					v6 = append(v6, addr.String())
				}
			}
		}
		rules = append(rules, dropRule("ip", relay.Port, v4), dropRule("ip6", relay.Port, v6))
	}
	var b strings.Builder
	// "add" then "delete" so the delete never fails on a missing table.
	fmt.Fprintf(&b, "table inet %s {}\ndelete table inet %s\n", relayFirewallTable, relayFirewallTable)
	if len(rules) == 0 {
		return b.String(), false, nil
	}
	fmt.Fprintf(&b, "table inet %s {\n\tchain input {\n\t\ttype filter hook input priority -5; policy accept;\n", relayFirewallTable)
	for _, rule := range rules {
		fmt.Fprintf(&b, "\t\t%s\n", rule)
	}
	b.WriteString("\t}\n}\n")
	return b.String(), true, nil
}

func sourceAddrs(ctx context.Context, source string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(source); err == nil {
		return []netip.Addr{addr}, nil
	}
	addrs, err := lookupHost(ctx, source)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", source, err)
	}
	return addrs, nil
}

// dropRule drops the family's packets to port from anyone outside sources
// (from everyone when there are none).
func dropRule(family string, port int, sources []string) string {
	nfproto := map[string]string{"ip": "ipv4", "ip6": "ipv6"}[family]
	rule := fmt.Sprintf("meta nfproto %s meta l4proto { tcp, udp } th dport %d", nfproto, port)
	if len(sources) > 0 {
		slices.Sort(sources)
		rule += fmt.Sprintf(" %s saddr != { %s }", family, strings.Join(slices.Compact(sources), ", "))
	}
	return rule + " drop"
}
