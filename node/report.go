package node

import (
	"github.com/AnixOps/anix-agent/v5/api/panel"
	log "github.com/sirupsen/logrus"
)

// reportUserTrafficTask is one run of the report job: it reads the
// traffic window and the online devices, and submits them to Control. The
// core's counters are reset by the read, so traffic that could not be
// spooled is kept here and added to the next window (unsent). It never
// fails.
func (c *Controller) reportUserTrafficTask() error {
	traffic, err := c.server.UserTraffic(c.tag, true)
	if err != nil {
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).Warn("Get user traffic failed")
		traffic = nil
	}
	if c.dynamicSpeedLimit() {
		c.countTraffic(traffic)
	}
	online, total := c.onlineToReport(traffic)
	c.reportDestinations()
	window := addTraffic(c.unsent, traffic)
	c.unsent, err = c.submitTraffic(window, online)
	if err != nil {
		log.WithFields(log.Fields{"tag": c.tag, "err": err, "kept_users": len(c.unsent)}).Error("Report user traffic failed; the traffic not spooled is kept for the next window")
	} else if len(window) > 0 || len(online) > 0 {
		log.WithField("tag", c.tag).Infof("Reported traffic of %d users, %d of %d online users", len(window), len(online), total)
	}
	c.syncCoreUserRateLimits()
	return nil
}

// addTraffic adds up kept and traffic by user.
func addTraffic(kept, traffic []panel.UserTraffic) []panel.UserTraffic {
	if len(kept) == 0 {
		return traffic
	}
	sum := append([]panel.UserTraffic(nil), kept...)
	index := make(map[int]int, len(sum))
	for i, entry := range sum {
		index[entry.UID] = i
	}
	for _, entry := range traffic {
		if i, ok := index[entry.UID]; ok {
			sum[i].Upload += entry.Upload
			sum[i].Download += entry.Download
			continue
		}
		index[entry.UID] = len(sum)
		sum = append(sum, entry)
	}
	return sum
}

// countTraffic adds each entry of traffic to the speed counter, keyed by
// the user's uuid.
func (c *Controller) countTraffic(traffic []panel.UserTraffic) {
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
		c.traffic[uuid] += entry.Upload + entry.Download
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
