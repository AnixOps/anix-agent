package anixcore

import (
	"context"
	"errors"
	"fmt"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	vCore "github.com/AnixOps/anix-agent/v5/core"
)

var _ vCore.EgressApplier = (*Core)(nil)

// ApplyEgress implements vCore.EgressApplier: anixcore replaces its egress
// routes and relays with config (PUT /v1/egress); nil or an empty
// configuration removes them. anixcore routes the domains of every inbound
// and serves the relays beside the inbounds. The configuration is kept, so
// a restarted anixcore gets it again.
func (c *Core) ApplyEgress(config *panel.EgressConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}
	body := &panel.EgressConfig{Routes: []panel.EgressRoute{}, Relays: []panel.EgressRelay{}}
	if config != nil {
		for _, route := range config.Routes {
			if protocol := panel.EgressProtocol(route.Server.Protocol); protocol != panel.EgressProtocolShadowsocks {
				return fmt.Errorf("egress route %d: the anixcore core has no relay protocol %q", route.ID, protocol)
			}
		}
		for _, relay := range config.Relays {
			if protocol := panel.EgressProtocol(relay.Protocol); protocol != panel.EgressProtocolShadowsocks {
				return fmt.Errorf("egress relay %d: the anixcore core has no relay protocol %q", relay.ID, protocol)
			}
		}
		body.Routes = append(body.Routes, config.Routes...)
		body.Relays = append(body.Relays, config.Relays...)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client == nil {
		return errors.New("anixcore: the core is not started")
	}
	c.egress = nil
	if !body.Empty() {
		c.egress = body
	}
	return c.putEgress(body)
}

// putEgress sends body to anixcore; c.mu is held.
func (c *Core) putEgress(body *panel.EgressConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	err := c.client.putEgress(ctx, body)
	if isStatus(err, 404) {
		return errors.New("anixcore: this anixcore has no egress routes; update it")
	}
	if err != nil {
		return fmt.Errorf("anixcore egress: %w", err)
	}
	return nil
}
