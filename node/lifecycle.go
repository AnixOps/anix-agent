package node

import (
	"fmt"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	log "github.com/sirupsen/logrus"
)

// buildNodeTag is the node's core tag: the configured Name, else one made
// of Control's URL and the node. Logs rewrite the second form.
func (c *Controller) buildNodeTag(info *panel.NodeInfo) string {
	if c.Name != "" {
		return c.Name + c.protocolTagSuffix()
	}
	return fmt.Sprintf("[%s]-%s:%d%s", c.apiHost, info.Type, info.Id, c.protocolTagSuffix())
}

// setUsers stores the node's users and their rate limits, and the alive
// list unless the stream delivered one before.
func (c *Controller) setUsers(users []panel.UserInfo, alive map[int]int) {
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()
	c.userList = users
	if !c.aliveFromStream {
		if alive == nil {
			alive = make(map[int]int)
		}
		c.aliveMap = alive
	}
	c.rates = newRateLimits(c.LimitConfig.SpeedLimit, users)
}

// startWith starts the node info with users and alive in the core and
// starts its periodic jobs.
func (c *Controller) startWith(info *panel.NodeInfo, users []panel.UserInfo, alive map[int]int) error {
	if len(users) == 0 {
		log.WithField("node", c.label()).Warn("The node has no users")
	}
	c.tag = c.buildNodeTag(info)
	c.logHook.Close()
	c.logHook = newRemoteLogHook(c.reportNodeLogs, c.tag)
	log.AddHook(c.logHook)
	c.setUsers(users, alive)
	if info.Security == panel.Tls {
		if err := c.ensureCertificate(); err != nil {
			return fmt.Errorf("certificate of node %s: %w", c.tag, err)
		}
	}
	if err := c.server.AddNode(c.tag, info, c.Options); err != nil {
		return fmt.Errorf("add node %s: %w", c.tag, err)
	}
	c.nodeAdded = true
	added, err := c.server.AddUsers(c.tag, info, c.userList)
	if err != nil {
		return fmt.Errorf("add users of node %s: %w", c.tag, err)
	}
	log.WithField("tag", c.tag).Infof("Added %d new users", added)
	c.info = info
	c.startJobs(info)
	c.started.Store(true)
	return nil
}

// Close stops the jobs and the log hook and removes the node from the
// core. It is safe to call more than once.
func (c *Controller) Close() error {
	c.stopJobs()
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()
	c.logHook.Close()
	c.logHook = nil
	if c.nodeAdded {
		if err := c.server.DelNode(c.tag); err != nil {
			return fmt.Errorf("delete node %s: %w", c.tag, err)
		}
		c.nodeAdded = false
	}
	return nil
}

// reconcileLocked brings the running node to newN, newU and newA (each nil
// when unchanged). A changed node is replaced with the new users and alive
// list; otherwise the alive list is stored and the user diff applied in
// place. reconcileMu is held.
func (c *Controller) reconcileLocked(newN *panel.NodeInfo, newU []panel.UserInfo, newA map[int]int) error {
	if newN != nil && !nodeConfigEqual(c.info, newN) {
		if newU != nil {
			c.userList = newU
			c.rates = newRateLimits(c.LimitConfig.SpeedLimit, newU)
		}
		if newA != nil {
			c.aliveMap = newA
		}
		if err := c.replaceNodeLocked(newN); err != nil {
			return err
		}
		if c.traffic != nil {
			c.traffic = make(map[string]int64)
		}
		c.reportJob.reset(newN.PushInterval)
		return nil
	}
	if newA != nil {
		c.aliveMap = newA
	}
	c.reportRuntimeHealth()
	if newU != nil {
		return c.applyUserDiffLocked(newU)
	}
	return nil
}

// reportRuntimeHealth sends a NodeStatus at once when the runtime health
// of the node's controllers changed.
func (c *Controller) reportRuntimeHealth() {
	c.stream.runtimeHealthChanged()
}
