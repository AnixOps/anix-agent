package anixcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	vCore "github.com/AnixOps/anix-agent/v5/core"
	log "github.com/sirupsen/logrus"
)

// qosFeature is the anixcore feature of PUT /v1/qos.
const qosFeature = "qos"

var _ vCore.QoSApplier = (*Core)(nil)

// offQoS is the body that turns the kernel's priorities off.
var offQoS = json.RawMessage(`{}`)

// ApplyQoS implements vCore.QoSApplier: anixcore replaces its traffic
// priorities and per-user class caps with config (PUT /v1/qos); nil turns
// them off. The configuration is kept, so a restarted anixcore gets it
// again. An anixcore without the feature is told nothing and a warning is
// logged: traffic flows without priorities until it is updated.
func (c *Core) ApplyQoS(config json.RawMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client == nil {
		return errors.New("anixcore: the core is not started")
	}
	body := offQoS
	if len(config) > 0 {
		body = append(json.RawMessage(nil), config...)
	}
	if c.qos != nil && bytes.Equal(c.qos, body) {
		return nil
	}
	if c.qos == nil && bytes.Equal(body, offQoS) {
		c.qos = body
		return nil
	}
	return c.putQoS(body)
}

// putQoS sends body to anixcore and remembers it; c.mu is held.
func (c *Core) putQoS(body json.RawMessage) error {
	if !c.client.qos.Load() {
		if !bytes.Equal(body, offQoS) {
			log.WithField("core", coreType).Warn("this anixcore has no traffic priorities; the panel's QoS settings are not applied until it is updated")
		}
		c.qos = body
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	if err := c.client.putQoS(ctx, body); err != nil {
		return fmt.Errorf("anixcore qos: %w", err)
	}
	c.qos = body
	return nil
}
