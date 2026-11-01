package node

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	agentapi "github.com/AnixOps/anix-agent/v5/api/agent"
	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/common/task"
	"github.com/AnixOps/anix-agent/v5/conf"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	"github.com/AnixOps/anix-agent/v5/diagnostic"
	"github.com/AnixOps/anix-agent/v5/limiter"
	"github.com/AnixOps/anix-agent/v5/plugin"
	"github.com/AnixOps/anix-agent/v5/upgrade"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	log "github.com/sirupsen/logrus"
)

type Controller struct {
	server vCore.Core
	// nodeID is the node the controller runs; apiHost is Control's base
	// URL, which names the node's core tag.
	nodeID                    int
	apiHost                   string
	tag                       string
	limiter                   *limiter.Limiter
	traffic                   map[string]int64
	userList                  []panel.UserInfo
	aliveMap                  map[int]int
	info                      *panel.NodeInfo
	userReportPeriodic        *task.Task
	renewCertPeriodic         *task.Task
	dynamicSpeedLimitPeriodic *task.Task
	onlineIpReportPeriodic    *task.Task
	logHook                   *RemoteLogHook
	reconcileMu               sync.Mutex
	pluginSupervisor          *plugin.Supervisor
	limiterAdded              bool
	nodeAdded                 bool
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
	// its caller read before. aliveMap, limiter and aliveFromStream are
	// guarded by reconcileMu: the alive list is applied from the data
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
// the node is starting: a limiter that exists takes the list at once (the
// node may be half started), and a controller that has no limiter yet takes
// it at startup (addLimiter).
func (c *Controller) applyStreamAlive(alive map[int]int) {
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()
	c.aliveMap = alive
	c.aliveFromStream = true
	if c.limiter != nil {
		c.limiter.AliveList = alive
	}
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

// addLimiter sets the node's users and alive list and adds its limiter,
// under reconcileMu: the data plane applies an alive list (applyStreamAlive)
// from its own goroutine while the node starts. A list that came from the
// stream before this point is newer than alive, which the caller read
// earlier, so it stays.
func (c *Controller) addLimiter(users []panel.UserInfo, alive map[int]int) *limiter.Limiter {
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()
	c.userList = users
	if !c.aliveFromStream || c.aliveMap == nil {
		c.aliveMap = alive
	}
	if c.aliveMap == nil {
		c.aliveMap = make(map[int]int)
	}
	l := limiter.AddLimiter(c.tag, &c.LimitConfig, c.userList, c.aliveMap)
	c.limiter = l
	c.limiterAdded = true
	return l
}

// startWith starts the node with its configuration, users and alive list.
func (c *Controller) startWith(node *panel.NodeInfo, users []panel.UserInfo, alive map[int]int) error {
	var err error
	if len(users) == 0 {
		log.Warn("No users found for this node, will continue running and check for users periodically")
	}
	if len(c.Options.Name) == 0 {
		c.tag = c.buildNodeTag(node)
	} else {
		c.tag = c.Options.Name + c.protocolTagSuffix()
	}
	c.logHook = newRemoteLogHook(c.reportNodeLogs, c.tag)
	log.StandardLogger().AddHook(c.logHook)

	// add limiter
	l := c.addLimiter(users, alive)
	// add rule limiter
	if err = l.UpdateRule(&node.Rules); err != nil {
		return fmt.Errorf("update rule error: %s", err)
	}
	if node.Security == panel.Tls {
		err = c.requestCert()
		if err != nil {
			return fmt.Errorf("request cert error: %s", err)
		}
	}
	// Add new tag
	err = c.server.AddNode(c.tag, node, c.Options)
	if err != nil {
		return fmt.Errorf("add new node error: %s", err)
	}
	c.nodeAdded = true
	added, err := c.server.AddUsers(&vCore.AddUsersParams{
		Tag:      c.tag,
		Users:    c.userList,
		NodeInfo: node,
	})
	if err != nil {
		return fmt.Errorf("add users error: %s", err)
	}
	log.WithField("tag", c.tag).Infof("Added %d new users", added)
	c.info = node
	c.startTasks(node)
	c.started.Store(true)

	return nil
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	var closeErr error

	if c.limiterAdded {
		limiter.DeleteLimiter(c.tag)
		c.limiterAdded = false
	}
	if c.userReportPeriodic != nil {
		c.userReportPeriodic.Close()
	}
	if c.renewCertPeriodic != nil {
		c.renewCertPeriodic.Close()
	}
	if c.dynamicSpeedLimitPeriodic != nil {
		c.dynamicSpeedLimitPeriodic.Close()
	}
	if c.onlineIpReportPeriodic != nil {
		c.onlineIpReportPeriodic.Close()
	}
	if c.logHook != nil {
		c.logHook.Close()
		c.logHook = nil
	}
	if c.nodeAdded {
		if err := c.server.DelNode(c.tag); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("del node error: %w", err))
		}
		c.nodeAdded = false
	}
	return closeErr
}

func (c *Controller) buildNodeTag(node *panel.NodeInfo) string {
	return fmt.Sprintf("[%s]-%s:%d", c.apiHost, node.Type, node.Id) + c.protocolTagSuffix()
}

// protocolTagSuffix keeps an extra controller's core tag apart from the
// node's other protocols, also those of the same type.
func (c *Controller) protocolTagSuffix() string {
	if c.protocolID == 0 {
		return ""
	}
	return fmt.Sprintf("#%d", c.protocolID)
}
