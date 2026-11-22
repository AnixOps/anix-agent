package node

import (
	"strconv"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	log "github.com/sirupsen/logrus"
)

// syncCoreUserRateLimits pushes every user's rate limit to a core that
// applies them itself.
func (c *Controller) syncCoreUserRateLimits() {
	updater, ok := c.server.(vCore.RateLimitUpdater)
	if !ok {
		return
	}
	c.reconcileMu.Lock()
	rates, users := c.rates, c.userList
	c.reconcileMu.Unlock()
	if rates == nil {
		return
	}
	for _, user := range users {
		if err := updater.UpdateUserRateLimit(c.tag, user.Uuid, rates.rate(user.Uuid)); err != nil {
			log.WithFields(log.Fields{"tag": c.tag, "uuid": user.Uuid, "err": err}).Warn("Sync WireGuard rate limit failed")
		}
	}
}

func (c *Controller) getCoreOnlineDevice() ([]panel.OnlineUser, error) {
	provider, ok := c.server.(vCore.OnlineDeviceProvider)
	if !ok {
		return nil, nil
	}
	return provider.GetOnlineDevice(c.tag)
}

func mergeOnlineDevices(users []panel.OnlineUser) []panel.OnlineUser {
	seen := make(map[string]struct{}, len(users))
	merged := make([]panel.OnlineUser, 0, len(users))
	for _, user := range users {
		if user.UID == 0 || user.IP == "" {
			continue
		}
		key := strconv.Itoa(user.UID) + "\x00" + user.IP
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, user)
	}
	return merged
}

// submitTraffic hands the window to the node's control stream.
func (c *Controller) submitTraffic(userTraffic []panel.UserTraffic, online map[int][]string) error {
	if c.stream == nil {
		return errNoStream
	}
	return c.stream.submitTraffic(c, userTraffic, online)
}
