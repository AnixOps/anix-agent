package anixcore

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	vCore "github.com/AnixOps/anix-agent/v5/core"
)

var _ vCore.TemporaryProxyApplier = (*Core)(nil)

// Each temporary proxy runs as an anixcore `socks` inbound tagged
// temporaryProxyTagPrefix + id, with the proxy's one user and its
// expires_at_ms: anixcore closes it at that time by itself, so the proxy
// ends even when this Agent or Control is down. The kernel also refuses a
// socks inbound on a non-internal address or without an expiry.

// temporaryProxyTagPrefix starts the inbound tag of a temporary proxy.
const temporaryProxyTagPrefix = "tmp-socks-"

// socksType is the anixcore inbound type of temporary proxies.
const socksType = "socks"

// inboundExpiryFeature is the anixcore feature of the inbound key
// expires_at_ms.
const inboundExpiryFeature = "inbound_expiry"

// temporaryProxyNow is the clock of expiry decisions; tests replace it.
var temporaryProxyNow = time.Now

// ApplyTemporaryProxies implements vCore.TemporaryProxyApplier: anixcore
// runs exactly the proxies that have not expired. A proxy that is gone or
// changed is removed first (its port may be another's now), then the new
// and changed ones are added. The set is kept, so a restarted anixcore
// gets the proxies that are still running.
func (c *Core) ApplyTemporaryProxies(proxies []panel.TemporaryProxy) error {
	if err := panel.ValidateTemporaryProxies(proxies); err != nil {
		return err
	}
	current := temporaryProxyNow()
	wanted := make(map[string]panel.TemporaryProxy, len(proxies))
	for _, proxy := range proxies {
		if proxy.Expired(current) {
			continue
		}
		if time.UnixMilli(proxy.ExpiresAtUnixMs).Sub(current) > panel.TemporaryProxyMaxLifetime {
			return fmt.Errorf("temporary proxy %d: it ends more than seven days from now", proxy.ID)
		}
		wanted[temporaryProxyTag(proxy.ID)] = proxy
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client == nil {
		return errors.New("anixcore: the core is not started")
	}
	if len(wanted) > 0 && !c.client.temporaryProxies.Load() {
		return errors.New("anixcore: this anixcore has no socks inbound or inbound expiry; update it")
	}
	c.wantedProxies = wanted
	return c.syncTemporaryProxies()
}

// syncTemporaryProxies brings anixcore to c.wantedProxies, leaving out the
// ones that expired meanwhile; c.mu is held.
func (c *Core) syncTemporaryProxies() error {
	current := temporaryProxyNow()
	for tag, proxy := range c.wantedProxies {
		if proxy.Expired(current) {
			delete(c.wantedProxies, tag)
		}
	}
	var failed error
	for tag, running := range c.proxies {
		if wanted, ok := c.wantedProxies[tag]; ok && wanted == running && !running.Expired(current) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		err := c.client.removeInbound(ctx, tag)
		cancel()
		// anixcore drops an expired inbound itself.
		if err != nil && !isStatus(err, 404) {
			failed = errors.Join(failed, fmt.Errorf("remove temporary proxy %s: %w", tag, err))
			continue
		}
		delete(c.proxies, tag)
	}
	for tag, proxy := range c.wantedProxies {
		if _, ok := c.proxies[tag]; ok {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		err := c.client.addInbound(ctx, temporaryProxyInbound(tag, proxy))
		cancel()
		if err != nil {
			failed = errors.Join(failed, fmt.Errorf("temporary proxy %d: %w", proxy.ID, err))
			continue
		}
		if c.proxies == nil {
			c.proxies = map[string]panel.TemporaryProxy{}
		}
		c.proxies[tag] = proxy
	}
	return failed
}

// replayTemporaryProxies adds the proxies still running to a fresh
// anixcore; c.mu is held.
func (c *Core) replayTemporaryProxies() error {
	c.proxies = nil
	if len(c.wantedProxies) == 0 {
		return nil
	}
	return c.syncTemporaryProxies()
}

func temporaryProxyTag(id uint64) string {
	return temporaryProxyTagPrefix + strconv.FormatUint(id, 10)
}

// temporaryProxyInbound is the anixcore inbound of proxy.
func temporaryProxyInbound(tag string, proxy panel.TemporaryProxy) map[string]any {
	return map[string]any{
		"tag":           tag,
		"type":          socksType,
		"listen":        proxy.Listen,
		"listen_port":   proxy.Port,
		"expires_at_ms": proxy.ExpiresAtUnixMs,
		"users": []map[string]any{{
			"name":     strconv.FormatUint(proxy.ID, 10),
			"username": proxy.Username,
			"password": proxy.Password,
		}},
	}
}
