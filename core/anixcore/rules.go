package anixcore

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
)

// rulesConfig is the body of PUT /v1/rules: the panel's block routes.
type rulesConfig struct {
	BlockDomains   []string `json:"block_domains"`
	BlockProtocols []string `json:"block_protocols"`
}

func (r rulesConfig) empty() bool {
	return len(r.BlockDomains) == 0 && len(r.BlockProtocols) == 0
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
	return rules
}

// syncRules sends the nodes' block rules to anixcore when they changed. An
// anixcore without block rules is told nothing and a warning is logged.
// c.mu is held.
func (c *Core) syncRules() error {
	if c.client == nil {
		return nil
	}
	want := c.wantedRules()
	if c.rules != nil && slices.Equal(c.rules.BlockDomains, want.BlockDomains) && slices.Equal(c.rules.BlockProtocols, want.BlockProtocols) {
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
