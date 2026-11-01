package node

import (
	"github.com/AnixOps/anix-agent/v5/api/panel"
)

// Extra controllers (nodeDataPlane.reconcileExtras) run a node's protocols
// past the first one in inbounds of their own, from the stream's
// snapshots: the installer's configuration has one controller per node,
// and a node may serve several protocols, also two of one type
// (shadowsocks and shadowsocks 2022 on two ports).

// newExtraController is a controller for protocolID of base's node: the
// same core, options and Control as base, on the node's data plane.
func newExtraController(base *Controller, protocolID uint64, plane *nodeDataPlane) *Controller {
	controller := NewController(base.server, base.nodeID, base.apiHost, base.Options)
	controller.protocolID = protocolID
	controller.stream = plane
	return controller
}

// currentUsers is a copy of the users the controller runs.
func (c *Controller) currentUsers() []panel.UserInfo {
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()
	return append([]panel.UserInfo{}, c.userList...)
}
