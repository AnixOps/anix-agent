package xray

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features/routing"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

var _ vCore.EgressApplier = (*Xray)(nil)

// Tags of what an egress route or relay adds to the core.
func egressOutboundTag(id uint64) string { return "egress-out-" + strconv.FormatUint(id, 10) }
func egressRuleTag(id uint64) string     { return "egress-rule-" + strconv.FormatUint(id, 10) }
func egressRelayTag(id uint64) string    { return "egress-in-" + strconv.FormatUint(id, 10) }
func egressRelayOutTag(id uint64) string { return "egress-direct-" + strconv.FormatUint(id, 10) }
func egressRelayRule(id uint64) string   { return "egress-relay-rule-" + strconv.FormatUint(id, 10) }

// egressState is what the last ApplyEgress added: each route's and relay's
// fingerprint by id, so an unchanged entry stays as it runs.
type egressState struct {
	routes map[uint64]string
	relays map[uint64]string
}

// ApplyEgress implements vCore.EgressApplier. A route adds a Shadowsocks
// outbound to the exit node's relay and a routing rule that sends its
// domains there; a relay adds a Shadowsocks inbound and a direct outbound
// its traffic leaves through. Entries that are gone or changed are removed
// first, then the new and changed ones are added; the rules are put back
// whole.
func (c *Xray) ApplyEgress(config *panel.EgressConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if config != nil {
		for _, route := range config.Routes {
			if protocol := panel.EgressProtocol(route.Server.Protocol); protocol != panel.EgressProtocolShadowsocks {
				return fmt.Errorf("egress route %d: the xray core has no relay protocol %q", route.ID, protocol)
			}
		}
		for _, relay := range config.Relays {
			if protocol := panel.EgressProtocol(relay.Protocol); protocol != panel.EgressProtocolShadowsocks {
				return fmt.Errorf("egress relay %d: the xray core has no relay protocol %q", relay.ID, protocol)
			}
		}
	}
	c.access.Lock()
	defer c.access.Unlock()
	if c.ihm == nil || c.ohm == nil || c.Server == nil {
		return errors.New("the xray core is not started")
	}
	router, ok := c.Server.GetFeature(routing.RouterType()).(routing.Router)
	if !ok || router == nil {
		return errors.New("the xray core has no router")
	}
	if c.egress == nil {
		c.egress = &egressState{routes: map[uint64]string{}, relays: map[uint64]string{}}
	}
	wantRoutes := map[uint64]panel.EgressRoute{}
	wantRelays := map[uint64]panel.EgressRelay{}
	if config != nil {
		for _, route := range config.Routes {
			wantRoutes[route.ID] = route
		}
		for _, relay := range config.Relays {
			wantRelays[relay.ID] = relay
		}
	}

	// The rules go first and come back last, in order: each relay's rule
	// ahead of every route's, so a relay's traffic never takes a route of
	// this node (it leaves here).
	for id := range c.egress.relays {
		_ = router.RemoveRule(egressRelayRule(id))
	}
	for id := range c.egress.routes {
		_ = router.RemoveRule(egressRuleTag(id))
	}
	var errs []error
	for id, print := range c.egress.routes {
		if want, ok := wantRoutes[id]; ok && fingerprint(want) == print {
			continue
		}
		if err := c.removeOutbound(egressOutboundTag(id)); err != nil {
			log.WithError(err).WithField("egress_route", id).Debug("Remove the egress outbound")
		}
		delete(c.egress.routes, id)
	}
	for id, print := range c.egress.relays {
		if want, ok := wantRelays[id]; ok && fingerprint(want) == print {
			continue
		}
		if err := c.removeInbound(egressRelayTag(id)); err != nil {
			log.WithError(err).WithField("egress_relay", id).Debug("Remove the egress relay inbound")
		}
		if err := c.removeOutbound(egressRelayOutTag(id)); err != nil {
			log.WithError(err).WithField("egress_relay", id).Debug("Remove the egress relay outbound")
		}
		delete(c.egress.relays, id)
	}

	for _, id := range sortedKeys(wantRelays) {
		if _, running := c.egress.relays[id]; running {
			continue
		}
		relay := wantRelays[id]
		if err := c.addEgressRelay(relay); err != nil {
			errs = append(errs, fmt.Errorf("egress relay %d: %w", id, err))
			continue
		}
		c.egress.relays[id] = fingerprint(relay)
	}
	for _, id := range sortedKeys(wantRoutes) {
		if _, running := c.egress.routes[id]; running {
			continue
		}
		route := wantRoutes[id]
		if err := c.addEgressOutbound(route); err != nil {
			errs = append(errs, fmt.Errorf("egress route %d: %w", id, err))
			continue
		}
		c.egress.routes[id] = fingerprint(route)
	}

	var rules []json.RawMessage
	for _, id := range sortedKeys(c.egress.relays) {
		rule, err := json.Marshal(map[string]any{
			"type": "field", "ruleTag": egressRelayRule(id), "outboundTag": egressRelayOutTag(id),
			"inboundTag": []string{egressRelayTag(id)},
		})
		if err != nil {
			return err
		}
		rules = append(rules, rule)
	}
	for _, id := range sortedKeys(c.egress.routes) {
		rule, err := json.Marshal(map[string]any{
			"type": "field", "ruleTag": egressRuleTag(id), "outboundTag": egressOutboundTag(id),
			"domain": egressDomains(wantRoutes[id].Domains),
		})
		if err != nil {
			return err
		}
		rules = append(rules, rule)
	}
	if len(rules) > 0 {
		routerConfig := &coreConf.RouterConfig{RuleList: rules}
		built, err := routerConfig.Build()
		if err == nil {
			err = router.AddRule(serial.ToTypedMessage(built), true)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("egress routing rules: %w", err))
		}
	}
	return errors.Join(errs...)
}

func (c *Xray) addEgressRelay(relay panel.EgressRelay) error {
	document, err := json.Marshal(map[string]any{
		"tag":      egressRelayTag(relay.ID),
		"protocol": "shadowsocks",
		"listen":   "0.0.0.0",
		"port":     relay.Port,
		"settings": map[string]any{"method": relay.Method, "password": relay.Password, "network": "tcp,udp"},
	})
	if err != nil {
		return err
	}
	var detour coreConf.InboundDetourConfig
	if err := json.Unmarshal(document, &detour); err != nil {
		return fmt.Errorf("decode the inbound: %w", err)
	}
	built, err := detour.Build()
	if err != nil {
		return fmt.Errorf("build the inbound: %w", err)
	}
	var direct coreConf.OutboundDetourConfig
	if err := json.Unmarshal([]byte(`{"protocol":"freedom","settings":{}}`), &direct); err != nil {
		return err
	}
	direct.Tag = egressRelayOutTag(relay.ID)
	builtDirect, err := direct.Build()
	if err != nil {
		return fmt.Errorf("build the relay outbound: %w", err)
	}
	if err := c.addOutbound(builtDirect); err != nil {
		return fmt.Errorf("add the relay outbound: %w", err)
	}
	if err := c.addInbound(built); err != nil {
		_ = c.removeOutbound(direct.Tag)
		return fmt.Errorf("add the inbound: %w", err)
	}
	return nil
}

func (c *Xray) addEgressOutbound(route panel.EgressRoute) error {
	document, err := json.Marshal(map[string]any{
		"tag":      egressOutboundTag(route.ID),
		"protocol": "shadowsocks",
		"settings": map[string]any{"servers": []map[string]any{{
			"address": route.Server.Host, "port": route.Server.Port,
			"method": route.Server.Method, "password": route.Server.Password,
		}}},
	})
	if err != nil {
		return err
	}
	var detour coreConf.OutboundDetourConfig
	if err := json.Unmarshal(document, &detour); err != nil {
		return fmt.Errorf("decode the outbound: %w", err)
	}
	built, err := detour.Build()
	if err != nil {
		return fmt.Errorf("build the outbound: %w", err)
	}
	return c.addOutbound(built)
}

// egressDomains turns Control's domains into Xray domain matchers: a bare
// name matches the domain and its subdomains (domain:), a name with a
// matcher prefix (full:, domain:, keyword:, regexp:, geosite:) is kept.
func egressDomains(domains []string) []string {
	matchers := make([]string, 0, len(domains))
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		if strings.Contains(domain, ":") {
			matchers = append(matchers, domain)
			continue
		}
		matchers = append(matchers, "domain:"+strings.TrimPrefix(strings.ToLower(domain), "."))
	}
	return matchers
}

func fingerprint(value any) string {
	encoded, _ := json.Marshal(value)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func sortedKeys[V any](entries map[uint64]V) []uint64 {
	keys := make([]uint64, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}
