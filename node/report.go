package node

import (
	"github.com/AnixOps/anix-agent/v5/api/panel"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	log "github.com/sirupsen/logrus"
)

// reportUserTrafficTask is one run of the report job: it reads the
// traffic window and the online devices, and submits them to Control. A
// window that cannot be submitted is given back. It never fails.
func (c *Controller) reportUserTrafficTask() error {
	traffic, err := c.server.UserTraffic(c.tag, true)
	if err != nil {
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).Warn("Get user traffic failed")
		traffic = nil
	}
	dynamic := c.dynamicSpeedLimit()
	if dynamic {
		c.countTraffic(traffic, 1)
	}
	online, total := c.onlineToReport(traffic)
	c.reportDestinations()
	if err := c.submitTraffic(traffic, online); err != nil {
		c.rollbackTraffic(traffic, dynamic)
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).Error("Report user traffic failed")
	} else if len(traffic) > 0 || len(online) > 0 {
		log.WithField("tag", c.tag).Infof("Reported traffic of %d users, %d of %d online users", len(traffic), len(online), total)
	}
	c.syncCoreUserRateLimits()
	return nil
}

// countTraffic adds sign times each entry of traffic to the speed counter,
// keyed by the user's uuid; the counter never goes below 0.
func (c *Controller) countTraffic(traffic []panel.UserTraffic, sign int64) {
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()
	if c.traffic == nil {
		c.traffic = make(map[string]int64)
	}
	uuids := make(map[int]string, len(c.userList))
	for _, user := range c.userList {
		uuids[user.Id] = user.Uuid
	}
	for _, entry := range traffic {
		uuid, ok := uuids[entry.UID]
		if !ok {
			continue
		}
		c.traffic[uuid] = max(c.traffic[uuid]+sign*(entry.Upload+entry.Download), 0)
	}
}

// onlineToReport is the core's online devices by user id, without the
// users whose traffic in the window is too low to count as a device, and
// the number of devices before that filter.
func (c *Controller) onlineToReport(traffic []panel.UserTraffic) (map[int][]string, int) {
	devices, err := c.getCoreOnlineDevice()
	if err != nil {
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).Info("Get online devices failed")
		devices = nil
	}
	devices = mergeOnlineDevices(devices)
	used := make(map[int]int64, len(traffic))
	for _, entry := range traffic {
		used[entry.UID] += entry.Upload + entry.Download
	}
	minimum := c.DeviceOnlineMinTraffic * 1000
	online := make(map[int][]string)
	for _, device := range devices {
		if bytes, ok := used[device.UID]; ok && bytes < minimum {
			continue
		}
		online[device.UID] = append(online[device.UID], device.IP)
	}
	return online, len(devices)
}

// rollbackTraffic gives a window that could not be reported back to the
// core and the speed counter.
func (c *Controller) rollbackTraffic(traffic []panel.UserTraffic, dynamic bool) {
	if rollbacker, ok := c.server.(vCore.TrafficRollbacker); ok && len(traffic) > 0 {
		if err := rollbacker.RollbackUserTraffic(c.tag, traffic); err != nil {
			log.WithFields(log.Fields{"tag": c.tag, "err": err}).Warn("Roll back user traffic failed")
		}
	}
	if dynamic {
		c.countTraffic(traffic, -1)
	}
}
