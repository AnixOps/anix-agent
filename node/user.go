package node

import (
	"strconv"

	"github.com/AnixOps/anix-agent/v4/api/panel"
	vCore "github.com/AnixOps/anix-agent/v4/core"
	log "github.com/sirupsen/logrus"
)

func (c *Controller) reportUserTrafficTask() (err error) {
	userTraffic, err := c.server.GetUserTrafficSlice(c.tag, true)
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Warn("Get user traffic failed")
		userTraffic = nil
	}
	if c.LimitConfig.EnableDynamicSpeedLimit && c.traffic != nil {
		for _, traffic := range userTraffic {
			for _, user := range c.userList {
				if user.Id == traffic.UID {
					c.traffic[user.Uuid] += traffic.Upload + traffic.Download
					break
				}
			}
		}
	}
	online, onlineTotal := c.onlineToReport(userTraffic)

	if c.stream.streamReports() {
		// The stream (or its spool, while it is briefly down) carries the
		// window as one batch: once spooled it never goes to a legacy
		// transport, which could count it twice.
		if err := c.stream.submitTraffic(c, userTraffic, online); err != nil {
			c.rollbackTraffic(userTraffic)
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Could not spool the user traffic report")
		} else if len(userTraffic) > 0 || len(online) > 0 {
			log.WithField("tag", c.tag).Infof("Report %d users traffic, %d of %d online users on the control stream", len(userTraffic), len(online), onlineTotal)
		}
		c.syncCoreUserRateLimits()
		return nil
	}

	if len(userTraffic) > 0 {
		err = c.apiClient.ReportUserTraffic(userTraffic)
		if err != nil {
			c.rollbackTraffic(userTraffic)
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Info("Report user traffic failed")
		} else {
			log.WithField("tag", c.tag).Infof("Report %d users traffic", len(userTraffic))
			log.WithField("tag", c.tag).Debugf("User traffic: %+v", userTraffic)
		}
	}

	if onlineTotal > 0 {
		if err = c.apiClient.ReportNodeOnlineUsers(&online); err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Info("Report online users failed")
		} else {
			log.WithField("tag", c.tag).Infof("Total %d online users, %d Reported", onlineTotal, len(online))
			log.WithField("tag", c.tag).Debugf("Online users: %+v", online)
		}
	}

	userTraffic = nil
	c.syncCoreUserRateLimits()
	return nil
}

// onlineToReport returns the online IPs to report, by user id, and how
// many online devices were seen. Users whose traffic in the window is
// below DeviceOnlineMinTraffic are left out (a ping test is not a device).
func (c *Controller) onlineToReport(userTraffic []panel.UserTraffic) (map[int][]string, int) {
	onlineDevice, err := c.limiter.GetOnlineDevice()
	if err != nil {
		log.Print(err)
		onlineDevice = &[]panel.OnlineUser{}
	}
	coreOnlineDevice, err := c.getCoreOnlineDevice()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Info("Get core online users failed")
	}
	mergedOnlineDevice := mergeOnlineDevices(append(*onlineDevice, coreOnlineDevice...))
	data := make(map[int][]string)
	if len(mergedOnlineDevice) == 0 {
		return data, 0
	}
	nocountUID := make(map[int]struct{})
	for _, traffic := range userTraffic {
		total := traffic.Upload + traffic.Download
		if total < int64(c.Options.DeviceOnlineMinTraffic*1000) {
			nocountUID[traffic.UID] = struct{}{}
		}
	}
	for _, online := range mergedOnlineDevice {
		if _, ok := nocountUID[online.UID]; !ok {
			// json structure: { UID1:["ip1","ip2"],UID2:["ip3","ip4"] }
			data[online.UID] = append(data[online.UID], online.IP)
		}
	}
	return data, len(mergedOnlineDevice)
}

// rollbackTraffic gives a window that could not be reported back to the
// core's counters and the dynamic speed limit.
func (c *Controller) rollbackTraffic(userTraffic []panel.UserTraffic) {
	if rollbacker, ok := c.server.(vCore.TrafficRollbacker); ok {
		if rollbackErr := rollbacker.RollbackUserTrafficSlice(c.tag, userTraffic); rollbackErr != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": rollbackErr,
			}).Warn("Rollback user traffic cursor failed")
		}
	}
	if c.LimitConfig.EnableDynamicSpeedLimit && c.traffic != nil {
		for _, traffic := range userTraffic {
			for _, user := range c.userList {
				if user.Id != traffic.UID {
					continue
				}
				amount := traffic.Upload + traffic.Download
				c.traffic[user.Uuid] -= amount
				if c.traffic[user.Uuid] < 0 {
					c.traffic[user.Uuid] = 0
				}
				break
			}
		}
	}
}

func (c *Controller) syncCoreUserRateLimits() {
	if c.limiter == nil {
		return
	}
	updater, ok := c.server.(vCore.RateLimitUpdater)
	if !ok {
		return
	}
	for _, user := range c.userList {
		if err := updater.UpdateUserRateLimit(c.tag, user.Uuid, c.limiter.GetUserSpeedLimit(c.tag, user.Uuid)); err != nil {
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

func compareUserList(old, new []panel.UserInfo) (deleted, added []panel.UserInfo) {
	oldMap := make(map[string]int)
	for i, user := range old {
		key := userSyncKey(user)
		oldMap[key] = i
	}

	for _, user := range new {
		key := userSyncKey(user)
		if _, exists := oldMap[key]; !exists {
			added = append(added, user)
		} else {
			delete(oldMap, key)
		}
	}

	for _, index := range oldMap {
		deleted = append(deleted, old[index])
	}

	return deleted, added
}

func userSyncKey(user panel.UserInfo) string {
	return user.Uuid + "\x00" + strconv.Itoa(user.SpeedLimit) + "\x00" +
		strconv.Itoa(user.DeviceLimit) + "\x00" + user.WireGuardPeerIP + "\x00" +
		user.WireGuardPublicKey + "\x00" + user.WireGuardPresharedKey
}
