package node

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	apiclient "github.com/AnixOps/anix-agent/v4/api/client"
	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/common/task"
	"github.com/AnixOps/anix-agent/v4/conf"
	vCore "github.com/AnixOps/anix-agent/v4/core"
	"github.com/AnixOps/anix-agent/v4/diagnostic"
	"github.com/AnixOps/anix-agent/v4/limiter"
	"github.com/AnixOps/anix-agent/v4/plugin"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	log "github.com/sirupsen/logrus"
)

type Controller struct {
	server                    vCore.Core
	apiClient                 apiclient.NodeAPI
	tag                       string
	limiter                   *limiter.Limiter
	traffic                   map[string]int64
	userList                  []panel.UserInfo
	aliveMap                  map[int]int
	info                      *panel.NodeInfo
	nodeInfoMonitorPeriodic   *task.Task
	userReportPeriodic        *task.Task
	renewCertPeriodic         *task.Task
	dynamicSpeedLimitPeriodic *task.Task
	onlineIpReportPeriodic    *task.Task
	syncManager               *SyncManager
	// syncMu guards syncManager and closed: a retired WebSocket is
	// replaced from another goroutine.
	syncMu           sync.Mutex
	closed           bool
	logHook          *RemoteLogHook
	reconcileMu      sync.Mutex
	pluginSupervisor *plugin.Supervisor
	limiterAdded     bool
	nodeAdded        bool
	// stream is the node's control-stream data plane, nil when it is off:
	// the legacy transports then carry everything.
	stream *nodeDataPlane
	// agentClient is the node's Agent control client, nil without one.
	agentClient *agentapi.Client
	// diagnostics runs agent.diagnostic when the node forwards (the
	// forward checks of Control's route diagnosis); nil otherwise.
	diagnostics *diagnostic.Executor
	// nodeType is the configured NodeType; it picks the controller's entry
	// of a configuration snapshot (legacy_pull.types), empty for the node's
	// default answer.
	nodeType string
	// started is set once the node runs in the core.
	started atomic.Bool
	// lastConfigMode and lastUsersMode are the transports the last
	// reconciliation took the configuration and the users from, guarded by
	// reconcileMu.
	lastConfigMode agentapi.DataPlaneMode
	lastUsersMode  agentapi.DataPlaneMode
	*conf.Options
}

func (c *Controller) SetPluginSupervisor(supervisor *plugin.Supervisor) {
	c.pluginSupervisor = supervisor
}

// NewController return a Node controller with default parameters.
func NewController(server vCore.Core, api apiclient.NodeAPI, config *conf.Options) *Controller {
	controller := &Controller{
		server:    server,
		Options:   config,
		apiClient: api,
	}
	return controller
}

// Start fetches the node's configuration and users over the legacy
// transports (UniProxy, v2board gRPC) and starts the node.
func (c *Controller) Start() error {
	node, err := c.apiClient.GetNodeInfo()
	if err != nil {
		return fmt.Errorf("get node info error: %s", err)
	}
	if node == nil {
		return errors.New("get node info error: the panel answered no configuration")
	}
	if node.Type != "" {
		c.apiClient.SetNodeType(node.Type)
	}
	users, alive, err := c.startUsers()
	if err != nil {
		return err
	}
	return c.startWith(node, users, alive)
}

// startUsers are the users the node starts with: the stream's set during a
// stream start (users.v1), else the legacy pull.
func (c *Controller) startUsers() ([]panel.UserInfo, map[int]int, error) {
	if users, ok := c.stream.startupUserList(); ok {
		// The alive list comes from the stream too (alive.v1); without
		// one, device limits count this node's own connections.
		return users, c.stream.startupAliveList(), nil
	}
	return c.fetchLegacyUsers()
}

// fetchLegacyUsers pulls the user list and the alive list over the legacy
// transports.
func (c *Controller) fetchLegacyUsers() ([]panel.UserInfo, map[int]int, error) {
	users, err := c.apiClient.GetUserList()
	if err != nil {
		return nil, nil, fmt.Errorf("get user list error: %s", err)
	}
	alive, err := c.apiClient.GetUserAlive()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get user alive list: %s", err)
	}
	return users, alive, nil
}

// applySnapshot runs the controller's entry of a configuration snapshot
// from the control stream: it starts the node, or reloads it through the
// same restart path as a legacy configuration change.
func (c *Controller) applySnapshot(snapshot *agentv1pb.ConfigSnapshot) error {
	node, err := nodeInfoFromSnapshot(snapshot, c.nodeType, c.apiClient.GetNodeID())
	if err != nil {
		// The document itself is wrong: config_invalid.
		return agentapi.InvalidConfig(err)
	}
	if node.Type != "" {
		c.apiClient.SetNodeType(node.Type)
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
	c.lastConfigMode = agentapi.DataPlaneStream
	return c.reconcileLocked(node, nil, nil)
}

// applyStreamAlive makes the running node's device limits count alive,
// Control's alive list (alive.v1). A controller that is not started yet
// takes it at startup.
func (c *Controller) applyStreamAlive(alive map[int]int) {
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()
	c.aliveMap = alive
	if c.isStarted() && c.limiter != nil {
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
	c.lastUsersMode = agentapi.DataPlaneStream
	return c.applyUserDiffLocked(users)
}

// streamCarriesNodeData tells whether the control stream carries both the
// configuration and the users now (or within its grace period): the
// WebSocket then has nothing to push.
func (c *Controller) streamCarriesNodeData() bool {
	return c.stream.mode(agentcontrol.CapabilityConfig) != agentapi.DataPlaneLegacy &&
		c.stream.mode(agentcontrol.CapabilityUsers) != agentapi.DataPlaneLegacy
}

// retireLegacySync stops the WebSocket once the control stream carries the
// node's configuration and users. A plugin maintenance outbox keeps a
// maintenance-only WebSocket only while the stream does not carry it
// (maintenance.v1); a maintenance-only WebSocket stops once it does. The
// WebSocket's own goroutines may call here, so the work is done in the
// background.
func (c *Controller) retireLegacySync() {
	c.syncMu.Lock()
	syncManager := c.syncManager
	maintenanceOnStream := c.streamCarriesMaintenance()
	if syncManager == nil || c.closed || (syncManager.config.MaintenanceOnly && !maintenanceOnStream) {
		c.syncMu.Unlock()
		return
	}
	c.syncManager = nil
	c.syncMu.Unlock()
	go func() {
		_ = syncManager.Close()
		if syncManager.config.MaintenanceOnly {
			log.WithField("tag", c.tag).Info("The Agent control stream carries the plugin maintenance outbox (maintenance.v1); stopped the maintenance WebSocket")
			return
		}
		log.WithField("tag", c.tag).Info("The Agent control stream carries the node's configuration and users; stopped the legacy WebSocket")
		if c.pluginSupervisor == nil {
			return
		}
		if err := c.attachMaintenanceTransport(c.pluginSupervisor); err != nil {
			log.WithError(err).WithField("tag", c.tag).Error("Could not restart the plugin maintenance WebSocket")
		}
	}()
}

// streamCarriesMaintenance tells whether the control stream carries the
// plugin maintenance outbox now (or within its grace period).
func (c *Controller) streamCarriesMaintenance() bool {
	return c.stream.mode(agentcontrol.CapabilityMaintenance) != agentapi.DataPlaneLegacy
}

// reportNodeLogs sends the controller's log entries: to the node's LogBatch
// on the control stream while it carries reports.v1 (or is briefly down),
// else over the legacy transport.
func (c *Controller) reportNodeLogs(entries []panel.NodeLogEntry) error {
	if c.stream.streamReports() {
		return c.stream.submitLogs(entries)
	}
	return c.apiClient.ReportNodeLogs(entries)
}

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
	return fmt.Sprintf("node %d (%s)", c.apiClient.GetNodeID(), nodeType)
}

// startWith starts the node with its configuration, users and alive list.
func (c *Controller) startWith(node *panel.NodeInfo, users []panel.UserInfo, alive map[int]int) error {
	var err error
	c.userList = users
	if len(c.userList) == 0 {
		log.Warn("No users found for this node, will continue running and check for users periodically")
	}
	c.aliveMap = alive
	if c.aliveMap == nil {
		c.aliveMap = make(map[int]int)
	}
	if len(c.Options.Name) == 0 {
		c.tag = c.buildNodeTag(node)
	} else {
		c.tag = c.Options.Name
	}
	c.logHook = newRemoteLogHook(c.reportNodeLogs, c.tag)
	log.StandardLogger().AddHook(c.logHook)

	// add limiter
	l := limiter.AddLimiter(c.tag, &c.LimitConfig, c.userList, c.aliveMap)
	c.limiter = l
	c.limiterAdded = true
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

	// The WebSocket pushes configuration and user changes; it is not
	// started while the control stream carries both.
	if c.apiClient.SupportsSync() && !c.streamCarriesNodeData() {
		syncManager := NewSyncManager(c.apiClient, c, c.buildSyncConfig())
		if err := syncManager.Start(); err != nil {
			return fmt.Errorf("start sync manager error: %w", err)
		}
		c.syncMu.Lock()
		c.syncManager = syncManager
		c.syncMu.Unlock()
	}
	c.started.Store(true)

	return nil
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	var closeErr error
	c.syncMu.Lock()
	syncManager := c.syncManager
	c.syncManager, c.closed = nil, true
	c.syncMu.Unlock()
	if syncManager != nil {
		if err := syncManager.Close(); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("close sync manager error: %w", err))
		}
	}

	if c.limiterAdded {
		limiter.DeleteLimiter(c.tag)
		c.limiterAdded = false
	}
	if c.nodeInfoMonitorPeriodic != nil {
		c.nodeInfoMonitorPeriodic.Close()
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
	if err := c.apiClient.Close(); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("close api client error: %w", err))
	}
	return closeErr
}

func (c *Controller) buildNodeTag(node *panel.NodeInfo) string {
	return fmt.Sprintf("[%s]-%s:%d", c.apiClient.GetAPIHost(), node.Type, node.Id)
}

func (c *Controller) buildSyncConfig() *SyncConfig {
	if c.Options == nil || c.Options.SyncConfig == nil {
		return DefaultSyncConfig()
	}

	config := DefaultSyncConfig()
	syncConfig := c.Options.SyncConfig

	config.EnableWebSocket = syncConfig.EnableWebSocket
	if syncConfig.WSEndpoint != "" {
		config.WSEndpoint = syncConfig.WSEndpoint
	}
	if len(syncConfig.WSEndpointFallbacks) > 0 {
		config.WSEndpointFallbacks = syncConfig.WSEndpointFallbacks
	}
	if syncConfig.ReconnectInterval > 0 {
		config.ReconnectInterval = time.Duration(syncConfig.ReconnectInterval) * time.Second
	}
	config.MaxReconnectTries = syncConfig.MaxReconnectTries

	if syncConfig.PingInterval > 0 {
		config.PingInterval = time.Duration(syncConfig.PingInterval) * time.Second
	}
	if syncConfig.PongTimeout > 0 {
		config.PongTimeout = time.Duration(syncConfig.PongTimeout) * time.Second
	}
	if syncConfig.AckTimeout > 0 {
		config.AckTimeout = time.Duration(syncConfig.AckTimeout) * time.Second
	}
	if syncConfig.BufferSize > 0 {
		config.BufferSize = syncConfig.BufferSize
	}
	config.AckRetries = syncConfig.AckRetries

	config.EnableFallback = syncConfig.EnableFallback
	if syncConfig.FallbackInterval > 0 {
		config.FallbackInterval = time.Duration(syncConfig.FallbackInterval) * time.Second
	}

	return config
}

// reloadNode 重载节点配置 (用于同步管理器)
func (c *Controller) reloadNode(newNode *panel.NodeInfo) error {
	log.WithField("tag", c.tag).Info("Reloading node configuration")

	// 保存旧的 tag
	oldTag := c.tag

	// 删除旧节点
	if err := c.server.DelNode(oldTag); err != nil {
		log.WithFields(log.Fields{
			"tag": oldTag,
			"err": err,
		}).Error("Failed to delete old node")
		return err
	}
	c.nodeAdded = false

	// 更新 tag
	if len(c.Options.Name) == 0 {
		c.tag = c.buildNodeTag(newNode)
		// 更新 limiter
		if c.limiterAdded {
			limiter.DeleteLimiter(oldTag)
			c.limiterAdded = false
		}
		l := limiter.AddLimiter(c.tag, &c.LimitConfig, c.userList, c.aliveMap)
		c.limiter = l
		c.limiterAdded = true
	}

	// 更新规则
	if err := c.limiter.UpdateRule(&newNode.Rules); err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Failed to update rules")
		return err
	}

	// 请求证书
	if newNode.Security == panel.Tls {
		if err := c.requestCert(); err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Failed to request cert")
			return err
		}
	}

	// 添加新节点
	if err := c.server.AddNode(c.tag, newNode, c.Options); err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Failed to add new node")
		return err
	}
	c.nodeAdded = true

	// 添加用户
	added, err := c.server.AddUsers(&vCore.AddUsersParams{
		Tag:      c.tag,
		Users:    c.userList,
		NodeInfo: newNode,
	})
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Failed to add users")
		return err
	}

	c.info = newNode
	c.traffic = make(map[string]int64)

	log.WithFields(log.Fields{
		"tag":   c.tag,
		"users": added,
	}).Info("Node reloaded successfully")

	return nil
}
