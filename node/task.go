package node

import (
	"fmt"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/common/task"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	log "github.com/sirupsen/logrus"
)

func (c *Controller) startTasks(node *panel.NodeInfo) {
	// The traffic report task.
	c.userReportPeriodic = &task.Task{
		Interval: node.PushInterval,
		Execute:  c.reportUserTrafficTask,
	}
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
		log.Printf("[NodeID: %d] Start dynamic speed limit", c.nodeID)
	}
}

// reconcileLocked brings the node to newN (a changed configuration: the
// node restarts), newU (a changed user list: users are added and removed
// in place) and newA (the alive list); nil leaves that part as it is. A
// newN equal to the configuration the node runs is no change: the core is
// not touched (a configuration revision also moves for the forwarding
// member of the document, which proxy nodes do not run). reconcileMu is
// held.
func (c *Controller) reconcileLocked(newN *panel.NodeInfo, newU []panel.UserInfo, newA map[int]int) (err error) {
	if newN != nil && c.nodeAdded && nodeConfigEqual(c.info, newN) {
		log.WithField("tag", c.tag).Debug("Node configuration unchanged, no reload")
		newN = nil
	}
	if newN != nil {
		if newU != nil {
			c.userList = newU
		}
		if newA != nil {
			c.aliveMap = newA
		}
		log.WithField("tag", c.tag).Info("Node changed, reload")
		if err = c.replaceNodeLocked(newN); err != nil {
			return err
		}
		c.traffic = make(map[string]int64)
		// Check interval
		if c.userReportPeriodic != nil && c.userReportPeriodic.Interval != newN.PushInterval &&
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

// reportRuntimeHealth sends the runtime health with the next NodeStatus on
// the stream, at once.
func (c *Controller) reportRuntimeHealth() {
	c.stream.runtimeHealthChanged()
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
