package anixcore

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	log "github.com/sirupsen/logrus"
)

// blockCIDRsFeature is the anixcore feature of address blocks in PUT
// /v1/rules (block_cidrs) and their counter (GET /v1/rules/counters).
const blockCIDRsFeature = "block_cidrs"

// rulesConfig is the body of PUT /v1/rules: the panel's block routes and
// the address blocks of the exit policy.
type rulesConfig struct {
	BlockDomains   []string `json:"block_domains"`
	BlockProtocols []string `json:"block_protocols"`
	BlockCIDRs     []string `json:"block_cidrs,omitempty"`
}

func (r rulesConfig) empty() bool {
	return len(r.BlockDomains) == 0 && len(r.BlockProtocols) == 0 && len(r.BlockCIDRs) == 0
}

//go:embed mainland_cidrs.txt
var mainlandCIDRsFile string

// mainlandCIDRs are the mainland-China address blocks an exit refuses when
// its exit policy says so (scripts/update-mainland-cidrs.sh).
var mainlandCIDRs = sync.OnceValue(func() []string {
	var blocks []string
	for line := range strings.Lines(mainlandCIDRsFile) {
		if line, _, _ = strings.Cut(line, "#"); strings.TrimSpace(line) != "" {
			blocks = append(blocks, strings.TrimSpace(line))
		}
	}
	return blocks
})

var (
	_ vCore.ExitPolicyApplier = (*Core)(nil)
	_ vCore.MainlandCounter   = (*Core)(nil)
)

// ApplyExitPolicy implements vCore.ExitPolicyApplier: with BlockMainland
// anixcore refuses mainland-China addresses (block_cidrs). An anixcore
// without the feature is told nothing and a warning is logged.
func (c *Core) ApplyExitPolicy(policy panel.ExitPolicy) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blockMainland = policy.BlockMainland
	return c.syncRules()
}

// MainlandBlocked reads and resets the connections anixcore refused to
// mainland-China addresses; 0 while the exit policy is off or the kernel
// cannot count them.
func (c *Core) MainlandBlocked(ctx context.Context) (uint64, error) {
	c.mu.Lock()
	api, on := c.client, c.blockMainland
	c.mu.Unlock()
	if api == nil || !on || !api.blockCIDRs.Load() {
		return 0, nil
	}
	var counters struct {
		BlockedCIDRs uint64 `json:"blocked_cidrs"`
	}
	if err := api.do(ctx, http.MethodGet, "/v1/rules/counters?reset=true", nil, &counters); err != nil {
		return 0, fmt.Errorf("anixcore rule counters: %w", err)
	}
	return counters.BlockedCIDRs, nil
}

// sniffedProtocols are the block protocols anixcore recognizes in a
// client's first bytes.
var sniffedProtocols = map[string]string{"bittorrent": "bittorrent", "bt": "bittorrent", "http": "http", "tls": "tls"}

// wantedRules joins the block rules of every node: anixcore applies one
// set to all of its inbounds. Panel domain rules are regular expressions,
// as the other cores' limiter reads them; an expression that does not
// compile and a protocol anixcore cannot recognize are left out, so one bad
// entry does not refuse the rest. c.mu is held.
func (c *Core) wantedRules() rulesConfig {
	tags := make([]string, 0, len(c.nodes))
	for tag := range c.nodes {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	rules := rulesConfig{BlockDomains: []string{}, BlockProtocols: []string{}}
	for _, tag := range tags {
		info := c.nodes[tag].info
		if info == nil {
			continue
		}
		for _, expression := range info.Rules.Regexp {
			if expression == "" {
				continue
			}
			if _, err := regexp.Compile(expression); err != nil {
				log.WithFields(log.Fields{"core": coreType, "tag": tag, "rule": expression}).WithError(err).Warn("skip a block rule that is not a valid regular expression")
				continue
			}
			if entry := "regexp:" + expression; !slices.Contains(rules.BlockDomains, entry) {
				rules.BlockDomains = append(rules.BlockDomains, entry)
			}
		}
		for _, name := range info.Rules.Protocol {
			protocol, ok := sniffedProtocols[strings.ToLower(strings.TrimSpace(name))]
			if !ok {
				log.WithFields(log.Fields{"core": coreType, "tag": tag, "protocol": name}).Warn("anixcore cannot block this protocol; skipped")
				continue
			}
			if !slices.Contains(rules.BlockProtocols, protocol) {
				rules.BlockProtocols = append(rules.BlockProtocols, protocol)
			}
		}
	}
	if c.blockMainland && c.client != nil && c.client.blockCIDRs.Load() {
		rules.BlockCIDRs = mainlandCIDRs()
	}
	return rules
}

// syncRules sends the nodes' block rules to anixcore when they changed. An
// anixcore without block rules is told nothing and a warning is logged.
// c.mu is held.
func (c *Core) syncRules() error {
	if c.client == nil {
		return nil
	}
	if c.blockMainland && !c.client.blockCIDRs.Load() && !c.warnedCIDRs {
		c.warnedCIDRs = true
		log.WithField("core", coreType).Warn("this anixcore cannot refuse mainland-China destinations; the exit policy is not applied until it is updated")
	}
	want := c.wantedRules()
	if c.rules != nil && slices.Equal(c.rules.BlockDomains, want.BlockDomains) && slices.Equal(c.rules.BlockProtocols, want.BlockProtocols) &&
		slices.Equal(c.rules.BlockCIDRs, want.BlockCIDRs) {
		return nil
	}
	if c.rules == nil && want.empty() {
		c.rules = &want
		return nil
	}
	if !c.client.blockRules.Load() {
		if !want.empty() {
			log.WithField("core", coreType).Warn("this anixcore has no block rules; the panel's block routes are not applied until it is updated")
		}
		c.rules = &want
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	if err := c.client.putRules(ctx, want); err != nil {
		return fmt.Errorf("anixcore rules: %w", err)
	}
	c.rules = &want
	return nil
}
