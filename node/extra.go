package node

import (
	apiclient "github.com/AnixOps/anix-agent/v5/api/client"
	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/common/monitor"
)

// Extra controllers (nodeDataPlane.reconcileExtras) run a node's protocols
// past the first one in inbounds of their own, from the stream's
// snapshots: the installer's configuration has one controller per node,
// and a node may serve several protocols, also two of one type
// (shadowsocks and shadowsocks 2022 on two ports).

// newExtraController is a controller for protocolID of base's node: the
// same core, options and Control as base, on the node's data plane.
func newExtraController(base *Controller, protocolID uint64, plane *nodeDataPlane) *Controller {
	controller := NewController(base.server, extraAPI{NodeAPI: base.apiClient}, base.Options)
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

// extraAPI is an extra controller's view of its node's legacy client, which
// the node's first controller owns: it is not closed with the extra, the
// node type the client asks for stays the first controller's, no WebSocket
// is opened for it, and the node-wide reports a legacy transport would
// replace (online users, status) are left to the first controller. Its
// traffic is reported as the node's.
type extraAPI struct {
	apiclient.NodeAPI
}

func (extraAPI) SetNodeType(string) {}

func (extraAPI) SupportsSync() bool { return false }

func (extraAPI) Close() error { return nil }

func (extraAPI) ReportNodeOnlineUsers(*map[int][]string) error { return nil }

func (extraAPI) ReportNodeStatus(*monitor.SystemInfo, int, int64, int64) error { return nil }
