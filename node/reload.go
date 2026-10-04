package node

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/AnixOps/anix-agent/v4/api/panel"
	vCore "github.com/AnixOps/anix-agent/v4/core"
	"github.com/AnixOps/anix-agent/v4/limiter"
	log "github.com/sirupsen/logrus"
)

// nodeAddRetryDelays are the waits between the attempts to add a node
// whose listener is still held (EADDRINUSE): the inbound just removed can
// keep its port for a moment. reconcileMu is held meanwhile, so the total
// stays short.
var nodeAddRetryDelays = []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second}

// nodeConfigEqual tells whether two node configurations are the same: the
// parsed configuration as a whole, the fields kept out of JSON (Reality)
// included. The same configuration document parses to equal values.
func nodeConfigEqual(a, b *panel.NodeInfo) bool {
	if a == nil || b == nil {
		return false
	}
	return reflect.DeepEqual(a, b)
}

// replaceNodeLocked replaces the running node with newN. When newN cannot
// be added, the previous configuration is put back (its tag, limiter,
// rules and inbound) so that the node keeps serving, and the error is
// returned. c.nodeAdded always tells whether the core runs the node: a
// later reconciliation adds it without deleting a node that is not there.
// reconcileMu is held.
func (c *Controller) replaceNodeLocked(newN *panel.NodeInfo) error {
	oldInfo, oldTag := c.info, c.tag
	if c.nodeAdded {
		if err := c.server.DelNode(oldTag); err != nil && !errors.Is(err, vCore.ErrNodeNotFound) {
			log.WithFields(log.Fields{
				"tag": oldTag,
				"err": err,
			}).Error("Delete node failed")
			return fmt.Errorf("delete node %s: %w", oldTag, err)
		}
		c.nodeAdded = false
	}
	applyErr := c.startNodeLocked(newN)
	if applyErr == nil {
		c.info = newN
		return nil
	}
	if oldInfo == nil {
		return applyErr
	}
	log.WithFields(log.Fields{
		"tag": c.tag,
		"err": applyErr,
	}).Warn("The new node configuration failed; restoring the previous one")
	if restoreErr := c.startNodeLocked(oldInfo); restoreErr != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": restoreErr,
		}).Error("Restore the previous node configuration failed; the node is down until the next configuration")
		return errors.Join(applyErr, fmt.Errorf("restore the previous configuration of node %s: %w", oldTag, restoreErr))
	}
	c.info = oldInfo
	log.WithField("tag", c.tag).Warn("Restored the previous node configuration")
	return fmt.Errorf("%w (the previous configuration of node %s was restored)", applyErr, c.tag)
}

// startNodeLocked brings up info in the core with the controller's users:
// the tag and limiter, the rules, the certificate, the inbound and the
// users. A node whose users fail is removed again. c.nodeAdded is set once
// it all succeeded. reconcileMu is held.
func (c *Controller) startNodeLocked(info *panel.NodeInfo) error {
	alive := c.aliveMap
	if alive == nil {
		alive = make(map[int]int)
	}
	if len(c.Options.Name) == 0 {
		oldTag := c.tag
		c.tag = c.buildNodeTag(info)
		// Remove the limiter under the old tag before replacing the tag.
		limiter.DeleteLimiter(oldTag)
		c.limiter = limiter.AddLimiter(c.tag, &c.LimitConfig, c.userList, alive)
		c.limiterAdded = true
	} else if c.aliveMap != nil {
		c.limiter.AliveList = c.aliveMap
	}
	if err := c.limiter.UpdateRule(&info.Rules); err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Update Rule failed")
		return fmt.Errorf("update rules for node %s: %w", c.tag, err)
	}
	if info.Security == panel.Tls {
		if err := c.requestCert(); err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Request cert failed")
			return fmt.Errorf("request certificate for node %s: %w", c.tag, err)
		}
	}
	if err := c.addCoreNodeLocked(c.tag, info); err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Add node failed")
		return fmt.Errorf("add node %s: %w", c.tag, err)
	}
	if _, err := c.server.AddUsers(&vCore.AddUsersParams{
		Tag:      c.tag,
		Users:    c.userList,
		NodeInfo: info,
	}); err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Add users failed")
		if delErr := c.server.DelNode(c.tag); delErr != nil && !errors.Is(delErr, vCore.ErrNodeNotFound) {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": delErr,
			}).Error("Remove the node whose users failed")
			// The core may still run it: delete it before the next add.
			c.nodeAdded = true
		}
		return fmt.Errorf("add users to node %s: %w", c.tag, err)
	}
	c.nodeAdded = true
	return nil
}

// addCoreNodeLocked adds the node to the core, again after a short wait
// while its address is still in use.
func (c *Controller) addCoreNodeLocked(tag string, info *panel.NodeInfo) error {
	err := c.server.AddNode(tag, info, c.Options)
	for _, delay := range nodeAddRetryDelays {
		if err == nil || !isAddressInUse(err) {
			break
		}
		log.WithFields(log.Fields{
			"tag":   tag,
			"err":   err,
			"retry": delay,
		}).Warn("Node address still in use, retrying")
		time.Sleep(delay)
		err = c.server.AddNode(tag, info, c.Options)
	}
	return err
}

// isAddressInUse tells whether err is a listener's EADDRINUSE; the cores
// often pass it on as text only.
func isAddressInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || strings.Contains(err.Error(), "address already in use")
}
