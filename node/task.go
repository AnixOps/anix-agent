package node

import (
	"fmt"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	apiclient "github.com/AnixOps/anix-agent/v4/api/client"
	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/common/monitor"
	"github.com/AnixOps/anix-agent/v4/common/task"
	vCore "github.com/AnixOps/anix-agent/v4/core"
	"github.com/AnixOps/anix-agent/v4/limiter"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	log "github.com/sirupsen/logrus"
)

func (c *Controller) startTasks(node *panel.NodeInfo) {
	// fetch node info task
	c.nodeInfoMonitorPeriodic = &task.Task{
		Interval: node.PullInterval,
		Execute:  c.nodeInfoMonitor,
	}
	// fetch user list task
	c.userReportPeriodic = &task.Task{
		Interval: node.PushInterval,
		Execute:  c.reportUserTrafficTask,
	}
	log.WithField("tag", c.tag).Info("Start monitor node status")
	// delay to start nodeInfoMonitor
	_ = c.nodeInfoMonitorPeriodic.Start(false)
	log.WithField("tag", c.tag).Info("Start report node status")
	_ = c.userReportPeriodic.Start(false)
	c.reportRuntimeHealth()
	if node.Security == panel.Tls {
		switch c.CertConfig.CertMode {
		case "none", "", "file", "self":
		default:
			c.renewCertPeriodic = &task.Task{
				Interval: time.Hour * 24,
				Execute:  c.renewCertTask,
			}
			log.WithField("tag", c.tag).Info("Start renew cert")
			// delay to start renewCert
			_ = c.renewCertPeriodic.Start(true)
		}
	}
	if c.LimitConfig.EnableDynamicSpeedLimit && c.LimitConfig.DynamicSpeedLimitConfig != nil {
		c.traffic = make(map[string]int64)
		periodic := c.LimitConfig.DynamicSpeedLimitConfig.Periodic
		if periodic <= 0 {
			periodic = 60
		}
		c.dynamicSpeedLimitPeriodic = &task.Task{
			Interval: time.Duration(periodic) * time.Second,
			Execute:  c.SpeedChecker,
		}
		_ = c.dynamicSpeedLimitPeriodic.Start(false)
		log.Printf("[NodeID: %d] Start dynamic speed limit", c.apiClient.GetNodeID())
	}
}

func (c *Controller) nodeInfoMonitor() (err error) {
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()

	// The configuration comes from the control stream's snapshots while
	// it carries config.v1, and through the legacy pull otherwise.
	var newN *panel.NodeInfo
	configMode := c.stream.mode(agentcontrol.CapabilityConfig)
	if configMode == agentapi.DataPlaneLegacy {
		if c.lastConfigMode != agentapi.DataPlaneLegacy {
			// Back on the legacy pull after the stream: the next answer
			// is taken in full, not compared with the one before.
			if resetter, ok := c.apiClient.(pullCacheResetter); ok {
				resetter.ResetPullCache()
			}
		}
		newN, err = c.apiClient.GetNodeInfo()
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Get node info failed")
			return fmt.Errorf("get node info: %w", err)
		}
		if newN != nil && newN.Type != "" {
			c.apiClient.SetNodeType(newN.Type)
		}
	}
	c.lastConfigMode = configMode
	// The users come from the stream's deltas while it carries users.v1;
	// the alive list has no stream counterpart and is not pulled then.
	var newU []panel.UserInfo
	var newA map[int]int
	usersMode := c.stream.mode(agentcontrol.CapabilityUsers)
	if usersMode == agentapi.DataPlaneLegacy {
		if c.lastUsersMode != agentapi.DataPlaneLegacy {
			if resetter, ok := c.apiClient.(pullCacheResetter); ok {
				resetter.ResetPullCache()
			}
		}
		newU, err = c.apiClient.GetUserList()
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Get user list failed")
			return fmt.Errorf("get user list: %w", err)
		}
		newA, err = c.apiClient.GetUserAlive()
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Get alive list failed")
			return fmt.Errorf("get alive list: %w", err)
		}
	}
	c.lastUsersMode = usersMode
	if c.streamCarriesNodeData() {
		c.retireLegacySync()
	}
	return c.reconcileLocked(newN, newU, newA)
}

// pullCacheResetter is a legacy transport that remembers its last answers
// (ETag, body hash) to skip unchanged ones.
type pullCacheResetter interface {
	ResetPullCache()
}

// reconcileLocked brings the node to newN (a changed configuration: the
// node restarts), newU (a changed user list: users are added and removed
// in place) and newA (the alive list); nil leaves that part as it is.
// reconcileMu is held.
func (c *Controller) reconcileLocked(newN *panel.NodeInfo, newU []panel.UserInfo, newA map[int]int) (err error) {
	if newN != nil {
		c.info = newN
		// nodeInfo changed
		if newU != nil {
			c.userList = newU
		}
		c.traffic = make(map[string]int64)
		// Remove old node
		log.WithField("tag", c.tag).Info("Node changed, reload")
		err = c.server.DelNode(c.tag)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Delete node failed")
			return fmt.Errorf("delete node %s: %w", c.tag, err)
		}

		// Update limiter
		if len(c.Options.Name) == 0 {
			oldTag := c.tag
			c.tag = c.buildNodeTag(newN)
			// Remove the limiter under the old tag before replacing the tag.
			limiter.DeleteLimiter(oldTag)
			// Add new Limiter
			alive := newA
			if alive == nil {
				alive = c.aliveMap
			}
			l := limiter.AddLimiter(c.tag, &c.LimitConfig, c.userList, alive)
			c.limiter = l
		}
		// update alive list
		if newA != nil {
			c.limiter.AliveList = newA
		}
		// Update rule
		err = c.limiter.UpdateRule(&newN.Rules)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Update Rule failed")
			return fmt.Errorf("update rules for node %s: %w", c.tag, err)
		}

		// check cert
		if newN.Security == panel.Tls {
			err = c.requestCert()
			if err != nil {
				log.WithFields(log.Fields{
					"tag": c.tag,
					"err": err,
				}).Error("Request cert failed")
				return fmt.Errorf("request certificate for node %s: %w", c.tag, err)
			}
		}
		// add new node
		err = c.server.AddNode(c.tag, newN, c.Options)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Add node failed")
			return fmt.Errorf("add node %s: %w", c.tag, err)
		}
		_, err = c.server.AddUsers(&vCore.AddUsersParams{
			Tag:      c.tag,
			Users:    c.userList,
			NodeInfo: newN,
		})
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Add users failed")
			return fmt.Errorf("add users to node %s: %w", c.tag, err)
		}
		// Check interval
		if c.nodeInfoMonitorPeriodic.Interval != newN.PullInterval &&
			newN.PullInterval != 0 {
			c.nodeInfoMonitorPeriodic.Interval = newN.PullInterval
			c.nodeInfoMonitorPeriodic.Close()
			_ = c.nodeInfoMonitorPeriodic.Start(false)
		}
		if c.userReportPeriodic.Interval != newN.PushInterval &&
			newN.PushInterval != 0 {
			c.userReportPeriodic.Interval = newN.PushInterval
			c.userReportPeriodic.Close()
			_ = c.userReportPeriodic.Start(false)
		}
		log.WithField("tag", c.tag).Infof("Added %d new users", len(c.userList))
		// exit
		return nil
	}
	// update alive list
	if newA != nil {
		c.limiter.AliveList = newA
	}
	// The status goes on the control stream (NodeStatus, sent by the data
	// plane) while it carries reports.v1, else over the legacy transport.
	if !c.stream.streamReports() {
		if stats, statsErr := monitor.GetSystemInfo(); statsErr != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": statsErr,
			}).Warn("Get system info failed")
		} else if err = c.apiClient.ReportNodeStatus(stats, 0, 0, 0); err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Warn("Report node status failed")
		}
	}
	c.reportRuntimeHealth()
	// node no changed, check users
	if newU == nil {
		return nil
	}
	return c.applyUserDiffLocked(newU)
}

// applyUserDiffLocked adds and removes the users that differ between the
// running node and newU, in place. reconcileMu is held.
func (c *Controller) applyUserDiffLocked(newU []panel.UserInfo) (err error) {
	deleted, added := compareUserList(c.userList, newU)
	if len(deleted) > 0 {
		// have deleted users
		err = c.server.DelUsers(deleted, c.tag, c.info)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Delete users failed")
			return fmt.Errorf("delete users from node %s: %w", c.tag, err)
		}
	}
	if len(added) > 0 {
		// have added users
		_, err = c.server.AddUsers(&vCore.AddUsersParams{
			Tag:      c.tag,
			NodeInfo: c.info,
			Users:    added,
		})
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Add users failed")
			return fmt.Errorf("add users to node %s: %w", c.tag, err)
		}
	}
	if len(added) > 0 || len(deleted) > 0 {
		// update Limiter
		c.limiter.UpdateUser(c.tag, added, deleted)
		// clear traffic record
		if c.LimitConfig.EnableDynamicSpeedLimit {
			for i := range deleted {
				delete(c.traffic, deleted[i].Uuid)
			}
		}
	}
	c.userList = newU
	if len(added)+len(deleted) != 0 {
		log.WithField("tag", c.tag).
			Infof("%d user deleted, %d user added", len(deleted), len(added))
	}
	return nil
}

func (c *Controller) reportRuntimeHealth() {
	if c.stream.streamReports() {
		// NodeStatus carries the runtime health on the stream.
		return
	}
	provider, ok := c.server.(vCore.RuntimeHealthProvider)
	if !ok {
		return
	}
	reporter, ok := c.apiClient.(apiclient.RuntimeHealthReporter)
	if !ok {
		return
	}
	healthy, message := provider.RuntimeHealth(c.tag)
	if err := reporter.ReportNodeRuntimeHealth(healthy, message); err != nil {
		log.WithFields(log.Fields{
			"tag":     c.tag,
			"healthy": healthy,
			"err":     err,
		}).Warn("Report runtime health failed")
	}
}

func (c *Controller) SpeedChecker() error {
	if c.traffic == nil || c.LimitConfig.DynamicSpeedLimitConfig == nil {
		return nil
	}
	for u, t := range c.traffic {
		if t >= c.LimitConfig.DynamicSpeedLimitConfig.Traffic {
			err := c.limiter.UpdateDynamicSpeedLimit(c.tag, u,
				c.LimitConfig.DynamicSpeedLimitConfig.SpeedLimit,
				time.Now().Add(time.Duration(c.LimitConfig.DynamicSpeedLimitConfig.ExpireTime)*time.Minute))
			if err != nil {
				log.WithField("err", err).Error("Update dynamic speed limit failed")
			}
			delete(c.traffic, u)
		}
	}
	c.syncCoreUserRateLimits()
	return nil
}
