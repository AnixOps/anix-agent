package anixcore

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
)

func TestMainlandCIDRsParse(t *testing.T) {
	blocks := mainlandCIDRs()
	if len(blocks) <= 1000 {
		t.Fatalf("mainland_cidrs.txt has %d blocks; run scripts/update-mainland-cidrs.sh", len(blocks))
	}
	for _, block := range blocks {
		if _, err := netip.ParsePrefix(block); err != nil {
			t.Fatalf("block %q: %v", block, err)
		}
	}
}

func TestExitPolicySendsMainlandBlocksToKernelsThatTakeThem(t *testing.T) {
	for _, c := range []struct {
		name     string
		features []string
		on       bool
		want     bool
	}{
		{"on with the feature", []string{"block_rules", blockCIDRsFeature}, true, true},
		{"off", []string{"block_rules", blockCIDRsFeature}, false, false},
		{"on without the feature", []string{"block_rules"}, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			api, server := newFakeAPI(t)
			api.features = c.features
			core := externalCore(t, server)
			defer core.Close()
			if err := core.AddNode("vmess", &panel.NodeInfo{Type: "vmess", Common: &panel.CommonNode{ServerPort: 443}, VAllss: &panel.VAllssNode{Network: "tcp"}}, &conf.Options{}); err != nil {
				t.Fatal(err)
			}
			if err := core.ApplyExitPolicy(panel.ExitPolicy{BlockMainland: c.on}); err != nil {
				t.Fatal(err)
			}
			sent := len(api.rules) > 0 && slices.Equal(api.rules[len(api.rules)-1].BlockCIDRs, mainlandCIDRs())
			if sent != c.want {
				t.Fatalf("rules = %+v, want the mainland blocks %v", api.rules, c.want)
			}
			blocked, err := core.MainlandBlocked(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if want := map[bool]uint64{true: 3}[c.want]; blocked != want {
				t.Fatalf("MainlandBlocked = %d, want %d", blocked, want)
			}
			read := slices.Contains(api.calls, "GET /v1/rules/counters?reset=true")
			if read != c.want {
				t.Fatalf("counter read = %v, calls %v", read, api.calls)
			}
			if !c.want {
				return
			}
			// Turning it off clears the blocks.
			if err := core.ApplyExitPolicy(panel.ExitPolicy{}); err != nil {
				t.Fatal(err)
			}
			if last := api.rules[len(api.rules)-1]; len(last.BlockCIDRs) != 0 {
				t.Fatalf("blocks after turning the policy off = %v", last.BlockCIDRs)
			}
		})
	}
}
