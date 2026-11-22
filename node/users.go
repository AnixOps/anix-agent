package node

import (
	"fmt"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	log "github.com/sirupsen/logrus"
)

// userKey is what makes two users the same to the core: a user whose key
// changed is removed and added again.
type userKey struct {
	uuid                      string
	speedLimit, deviceLimit   int
	wgPeerIP, wgPublic, wgPSK string
	ss2022Key                 string
}

func keyOf(user panel.UserInfo) userKey {
	return userKey{
		uuid: user.Uuid, speedLimit: user.SpeedLimit, deviceLimit: user.DeviceLimit,
		wgPeerIP: user.WireGuardPeerIP, wgPublic: user.WireGuardPublicKey, wgPSK: user.WireGuardPresharedKey,
		ss2022Key: user.Extra["ss2022_key"],
	}
}

// diffUsers returns the users of running that wanted does not have, and
// those of wanted that running does not have, in wanted's order.
// Duplicates within a list count once.
func diffUsers(running, wanted []panel.UserInfo) (removed, added []panel.UserInfo) {
	want := make(map[userKey]bool, len(wanted))
	for _, user := range wanted {
		want[keyOf(user)] = true
	}
	seen := make(map[userKey]bool, len(running)+len(wanted))
	for _, user := range running {
		key := keyOf(user)
		if seen[key] {
			continue
		}
		seen[key] = true
		if !want[key] {
			removed = append(removed, user)
		}
	}
	for _, user := range wanted {
		key := keyOf(user)
		if seen[key] {
			continue
		}
		seen[key] = true
		added = append(added, user)
	}
	return removed, added
}

// applyUserDiffLocked brings the node's users in the core to newU.
// reconcileMu is held.
func (c *Controller) applyUserDiffLocked(newU []panel.UserInfo) error {
	removed, added := diffUsers(c.userList, newU)
	if len(removed) > 0 {
		if err := c.server.DelUsers(c.tag, c.info, removed); err != nil {
			log.WithFields(log.Fields{"tag": c.tag, "err": err}).Error("Delete users failed")
			return fmt.Errorf("delete users of node %s: %w", c.tag, err)
		}
	}
	if len(added) > 0 {
		if _, err := c.server.AddUsers(c.tag, c.info, added); err != nil {
			log.WithFields(log.Fields{"tag": c.tag, "err": err}).Error("Add users failed")
			return fmt.Errorf("add users of node %s: %w", c.tag, err)
		}
	}
	if len(removed) > 0 || len(added) > 0 {
		if c.rates != nil {
			c.rates.update(added, removed)
		}
		for _, user := range removed {
			delete(c.traffic, user.Uuid)
		}
		log.WithField("tag", c.tag).Infof("%d users deleted, %d users added", len(removed), len(added))
	}
	c.userList = newU
	return nil
}
