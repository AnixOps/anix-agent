package node

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	agentapi "github.com/AnixOps/anix-agent/v5/api/agent"
	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	"github.com/AnixOps/anix-agent/v5/diagnostic"
	"github.com/AnixOps/anix-agent/v5/plugin"
	"github.com/AnixOps/anix-agent/v5/upgrade"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
)

type Controller struct {
	server vCore.Core
	// nodeID is the node the controller runs; apiHost is Control's base
	// URL, which names the node's core tag.
	nodeID  int
	apiHost string
	tag     string
	rates   *rateLimits
	traffic map[string]int64
	// unsent is traffic read from the core but not spooled yet, added to
	// the next window (reportUserTrafficTask).
	unsent           []panel.UserTraffic
	userList         []panel.UserInfo
	aliveMap         map[int]int
	info             *panel.NodeInfo
	reportJob        *job
	certJob          *job
	speedJob         *job
	logHook          *RemoteLogHook
	reconcileMu      sync.Mutex
	pluginSupervisor *plugin.Supervisor
	nodeAdded        bool
	// stream is the node's control-stream data plane: it carries the
	// node's configuration, users and reports.
	stream *nodeDataPlane
	// agentClient is the node's Agent control client, nil without one.
	agentClient *agentapi.Client
	// diagnostics runs agent.diagnostic: the generic tasks on the Agent's
	// own unit, plus Control's forward checks when the node forwards; nil before the Agent Control client starts.
	diagnostics *diagnostic.Executor
	// upgrader runs agent.upgrade (upgrade.v1); nil without one.
	upgrader *upgrade.Agent
	// nodeType is the configured NodeType; it picks the controller's entry
	// of a configuration snapshot (runtime.types), empty for the node's
	// default answer.
	nodeType string
	// protocolID is the protocol an extra controller of the node runs
	// (runtime.protocols, nodeDataPlane.reconcileExtras), 0 for a
	// controller of the configuration file.
	protocolID uint64
	// started is set once the node runs in the core.
	started atomic.Bool
	// aliveFromStream is set once the control stream delivered an alive
	// list: a node that starts after it keeps that list instead of the one
	// its caller read before. userList, aliveMap, rates, traffic (the
	// dynamic speed limit's counter) and aliveFromStream are guarded by
	// reconcileMu: the alive list is applied from the data
	// plane's goroutine, also while the node starts.
	aliveFromStream bool
	*conf.Options
}

func (c *Controller) SetPluginSupervisor(supervisor *plugin.Supervisor) {
	c.pluginSupervisor = supervisor
}

// NewController returns the controller of node nodeID.
func NewController(server vCore.Core, nodeID int, apiHost string, config *conf.Options) *Controller {
	return &Controller{server: server, nodeID: nodeID, apiHost: apiHost, Options: config}
}

// startUsers are the users the node starts with: the stream's set
// (users.v1) and alive list (alive.v1; without one, device limits count
// this node's own connections).
func (c *Controller) startUsers() ([]panel.UserInfo, map[int]int, error) {
	users, ok := c.stream.currentUserList()
	if !ok {
		return nil, nil, errors.New("the Agent control stream has delivered no user set yet")
	}
	return users, c.stream.startupAliveList(), nil
}

// applySnapshot runs the controller's entry of a configuration snapshot
// from the control stream: it starts the node, or reloads it.
func (c *Controller) applySnapshot(snapshot *agentv1pb.ConfigSnapshot) error {
	node, err := nodeInfoFromSnapshot(snapshot, c.nodeType, c.protocolID, c.nodeID)
	if err != nil {
		// The document itself is wrong: config_invalid.
		return agentapi.InvalidConfig(err)
	}
	if !c.isStarted() {
		users, alive, err := c.startUsers()
		if err != nil {
			return err
		}
		return c.startWith(node, users, alive)
	}
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()
	return c.reconcileLocked(node, nil, nil)
}

// applyStreamAlive makes the node's device limits count alive, Control's
// alive list (alive.v1). It runs on the data plane's goroutine, also while
// the node is starting: a controller that has not stored its users yet
// keeps the list at startup (setUsers).
func (c *Controller) applyStreamAlive(alive map[int]int) {
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()
	c.aliveMap = alive
	c.aliveFromStream = true
}

// applyStreamUsers brings the running node to users, the node's set from
// the control stream (users.v1): changed users are removed and added in
// place, without restarting the core. A controller that is not started yet
// takes its users at startup.
func (c *Controller) applyStreamUsers(users []panel.UserInfo) error {
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()
	if !c.isStarted() {
		return nil
	}
	return c.applyUserDiffLocked(users)
}

// reportNodeLogs sends the controller's log entries to the node's LogBatch
// on the control stream.
func (c *Controller) reportNodeLogs(entries []panel.NodeLogEntry) error {
	if c.stream == nil {
		return errNoStream
	}
	return c.stream.submitLogs(entries)
}

// errNoStream: the controller is not bound to a control stream.
var errNoStream = errors.New("the node has no Agent control stream")

func (c *Controller) isStarted() bool {
	return c.started.Load()
}

// label names the controller in errors and logs.
func (c *Controller) label() string {
	if c.tag != "" {
		return c.tag
	}
	nodeType := c.nodeType
	if nodeType == "" {
		nodeType = "default"
	}
	if c.protocolID != 0 {
		nodeType = fmt.Sprintf("protocol %d", c.protocolID)
	}
	return fmt.Sprintf("node %d (%s)", c.nodeID, nodeType)
}

// protocolTagSuffix keeps an extra controller's core tag apart from the
// node's other protocols, also those of the same type.
func (c *Controller) protocolTagSuffix() string {
	if c.protocolID == 0 {
		return ""
	}
	return fmt.Sprintf("#%d", c.protocolID)
}
