package node

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	apiclient "github.com/AnixOps/anix-agent/v4/api/client"
	grpcapi "github.com/AnixOps/anix-agent/v4/api/grpc"
	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/common/maintenance"
	"github.com/AnixOps/anix-agent/v4/conf"
	vCore "github.com/AnixOps/anix-agent/v4/core"
	"github.com/AnixOps/anix-agent/v4/forward"
	"github.com/AnixOps/anix-agent/v4/plugin"
	log "github.com/sirupsen/logrus"
)

const pluginSupervisorShutdownTimeout = 15 * time.Second

type Node struct {
	lifecycle             sync.Mutex
	controllers           []*Controller
	agentClients          []*agentapi.Client
	dataPlanes            []*nodeDataPlane
	pluginSupervisors     map[int]*plugin.Supervisor
	supervisorSpecs       map[int]pluginSupervisorSpec
	supervisorFactory     func(plugin.Config) (*plugin.Supervisor, error)
	allowLegacySingleNode bool
	// forward rides the stream of proxy node forwardNodeID (SetForward).
	forward       *forward.Component
	forwardNodeID int
}

func New() *Node {
	return &Node{supervisorFactory: plugin.NewSupervisor}
}

func createAPIClient(apiCfg *conf.ApiConfig) (apiclient.NodeAPI, error) {
	var (
		client apiclient.NodeAPI
		err    error
	)
	switch strings.ToLower(strings.TrimSpace(apiCfg.Transport)) {
	case "", "http", "https", "rest":
		client, err = panel.New(apiCfg)
	case "grpc":
		client, err = grpcapi.NewFromAPIConfig(apiCfg)
	default:
		return nil, fmt.Errorf("unsupported api transport %q", apiCfg.Transport)
	}
	if err != nil {
		return nil, err
	}
	if apiCfg.NodeType != "" {
		client.SetNodeType(apiCfg.NodeType)
	}
	return client, nil
}

func initialNodeType(nodeType, coreType string) string {
	if strings.TrimSpace(nodeType) != "" {
		return nodeType
	}
	if strings.EqualFold(strings.TrimSpace(coreType), "wireguard") {
		return "wireguard"
	}
	return ""
}

func (n *Node) Start(nodes []conf.NodeConfig, core vCore.Core) error {
	n.lifecycle.Lock()
	defer n.lifecycle.Unlock()
	if len(n.controllers) > 0 || len(n.agentClients) > 0 || len(n.pluginSupervisors) > 0 {
		if err := n.closeResources(); err != nil {
			return fmt.Errorf("close previous node resources before restart: %w", err)
		}
	}
	n.controllers = make([]*Controller, len(nodes))
	n.agentClients = nil
	n.pluginSupervisors = make(map[int]*plugin.Supervisor)
	n.supervisorSpecs = make(map[int]pluginSupervisorSpec)
	n.allowLegacySingleNode = countPluginSupervisorNodes(nodes) == 1
	if n.supervisorFactory == nil {
		n.supervisorFactory = plugin.NewSupervisor
	}

	// Phase 1: the API clients (auto-registration may replace a
	// placeholder node ID), the controllers and the node-scoped
	// Supervisors. Nothing is pulled from Control yet.
	//
	// A node may appear more than once in the configuration (for example
	// with different protocol/core settings). Only one control stream is
	// started per final node ID, after all controllers have had a chance
	// to attach their node-scoped Supervisor.
	agentNodes := make(map[int]agentNodeStart)
	agentNodeOrder := make([]int, 0, len(nodes))
	controllerIdentities := make(map[*Controller]string)
	for i := range nodes {
		nodes[i].ApiConfig.NodeType = initialNodeType(nodes[i].ApiConfig.NodeType, nodes[i].Options.Core)
		client, err := createAPIClient(&nodes[i].ApiConfig)
		if err != nil {
			return n.failStart(err)
		}
		n.controllers[i] = NewController(core, client, &nodes[i].Options)
		n.controllers[i].nodeType = nodes[i].ApiConfig.NodeType
		nodeID := client.GetNodeID()
		// Auto-registration may replace the configured zero/placeholder ID.
		// Keep the in-memory configuration aligned with the credential that the
		// controller and its Supervisor now use.
		nodes[i].ApiConfig.NodeID = nodeID
		nodes[i].ApiConfig.Key = client.GetAPIKey()
		identity := nodeControlIdentity(nodes[i].ApiConfig)
		controllerIdentities[n.controllers[i]] = identity
		var supervisor *plugin.Supervisor
		if nodes[i].ApiConfig.PluginSupervisorEnabled {
			supervisor, err = n.supervisorForNode(nodeID, nodes[i].ApiConfig)
			if err != nil {
				return n.failStart(err)
			}
			n.controllers[i].SetPluginSupervisor(supervisor)
		}
		if nodes[i].ApiConfig.AgentControlEnabled {
			candidate := agentNodeStart{
				apiConfig:  nodes[i].ApiConfig,
				controller: n.controllers[i],
				supervisor: supervisor,
				identity:   identity,
			}
			// Prefer the duplicate configuration that has the Supervisor so the
			// single stream advertises plugin capabilities whenever any duplicate
			// opts into the official runtime.
			if previous, ok := agentNodes[nodeID]; ok {
				if previous.identity != candidate.identity {
					return n.failStart(fmt.Errorf("node %d has multiple Agent control endpoints; refusing to share Supervisor state", nodeID))
				}
				if previous.supervisor == nil && supervisor != nil {
					agentNodes[nodeID] = candidate
				}
			} else {
				agentNodes[nodeID] = candidate
				agentNodeOrder = append(agentNodeOrder, nodeID)
			}
		}
	}

	// Phase 2: the control streams whose data plane is on start first and
	// bring their controllers up from the stream (or from the stored
	// snapshot), so a node whose configuration Control serves on the
	// stream never pulls it over a legacy transport.
	type pendingClient struct {
		nodeID int
		client *agentapi.Client
	}
	var operationsOnly []pendingClient
	for _, nodeID := range agentNodeOrder {
		candidate := agentNodes[nodeID]
		if candidate.supervisor == nil {
			// A duplicate entry may opt into AgentControl while another entry for
			// the same physical node opts into the Supervisor.  Bind the stream to
			// the controller that owns the node-scoped runtime instead of silently
			// advertising a plugin-less handler.
			if controller := findNodeSupervisorController(n.controllers, controllerIdentities, nodeID, candidate.identity); controller != nil {
				candidate.controller = controller
				candidate.supervisor = controller.pluginSupervisor
			}
		}
		var dataPlane *nodeDataPlane
		if dataPlaneEnabled(candidate.apiConfig) {
			dataPlane = newNodeDataPlane(nodeID, nodeControllers(n.controllers, controllerIdentities, nodeID, candidate.identity))
			if n.forward != nil && nodeID == n.forwardNodeID {
				dataPlane.forward = n.forward
			}
			dataPlane.streamOnly = strings.TrimSpace(candidate.apiConfig.Key) == ""
		}
		agentClient, agentErr := newAgentControlClientForSupervisor(&candidate.apiConfig, candidate.controller, core, candidate.supervisor, dataPlane)
		if agentErr != nil {
			if dataPlane != nil {
				dataPlane.detach()
			}
			logAgentControlUnavailable(nodeID, agentErr)
			continue
		}
		if dataPlane == nil {
			operationsOnly = append(operationsOnly, pendingClient{nodeID: nodeID, client: agentClient})
			continue
		}
		n.agentClients = append(n.agentClients, agentClient)
		n.dataPlanes = append(n.dataPlanes, dataPlane)
		if err := dataPlane.start(context.Background()); err != nil {
			return n.failStart(err)
		}
	}

	// Phase 3: every other controller on the legacy transports.
	for i, controller := range n.controllers {
		if controller.isStarted() {
			continue
		}
		if controller.stream != nil && controller.stream.waitingForStream() {
			// A stream-only node starts from its stream (nodeDataPlane.awaitStream).
			continue
		}
		if err := controller.Start(); err != nil {
			startErr := fmt.Errorf("start node controller [%s-%d] error: %s",
				nodes[i].ApiConfig.APIHost,
				nodes[i].ApiConfig.NodeID,
				err)
			return n.failStart(startErr)
		}
	}
	for _, controller := range n.controllers {
		if controller.pluginSupervisor == nil {
			continue
		}
		if err := controller.attachMaintenanceTransport(controller.pluginSupervisor); err != nil {
			return n.failStart(err)
		}
	}

	// The operations-only streams start after their controllers, as
	// before the data plane: their operations act on running nodes.
	for _, pending := range operationsOnly {
		if agentErr := pending.client.Start(); agentErr != nil {
			_ = pending.client.Close()
			logAgentControlUnavailable(pending.nodeID, agentErr)
			continue
		}
		n.agentClients = append(n.agentClients, pending.client)
	}
	return nil
}

// nodeControllers lists the controllers of a node that share its control
// endpoint: the stream's data plane serves all of them.
func nodeControllers(controllers []*Controller, identities map[*Controller]string, nodeID int, identity string) []*Controller {
	var result []*Controller
	for _, controller := range controllers {
		if controller != nil && controller.apiClient.GetNodeID() == nodeID && identities[controller] == identity {
			result = append(result, controller)
		}
	}
	return result
}

func findNodeSupervisorController(controllers []*Controller, identities map[*Controller]string, nodeID int, identity string) *Controller {
	for _, controller := range controllers {
		if controller != nil && controller.apiClient.GetNodeID() == nodeID &&
			identities[controller] == identity && controller.pluginSupervisor != nil {
			return controller
		}
	}
	return nil
}

func (n *Node) Close() {
	n.lifecycle.Lock()
	defer n.lifecycle.Unlock()
	if err := n.closeResources(); err != nil {
		log.WithError(err).Error("close node resources")
	}
}

// failStart releases every resource created before a startup error.  In
// particular, a Supervisor must never outlive a controller whose final node
// ID could not be established.
func (n *Node) failStart(startErr error) error {
	return errors.Join(startErr, n.closeResources())
}

func (n *Node) closeResources() error {
	var closeErr error
	// Buffered logs go to the spool before the streams close.
	for _, dataPlane := range n.dataPlanes {
		dataPlane.close()
	}
	n.dataPlanes = nil
	for _, client := range n.agentClients {
		if client != nil {
			closeErr = errors.Join(closeErr, client.Close())
		}
	}
	n.agentClients = nil

	for _, supervisor := range n.pluginSupervisors {
		if supervisor == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), pluginSupervisorShutdownTimeout)
		closeErr = errors.Join(closeErr, supervisor.Close(ctx))
		cancel()
	}
	n.pluginSupervisors = nil
	n.supervisorSpecs = nil
	n.allowLegacySingleNode = false

	for _, controller := range n.controllers {
		if controller != nil {
			closeErr = errors.Join(closeErr, controller.Close())
		}
	}
	n.controllers = nil
	return closeErr
}

type agentNodeStart struct {
	apiConfig  conf.ApiConfig
	controller *Controller
	supervisor *plugin.Supervisor
	identity   string
}

type pluginSupervisorSpec struct {
	rootDir     string
	socketDir   string
	publicKey   ed25519.PublicKey
	identity    string
	environment string
	legacy      bool
}

func countPluginSupervisorNodes(nodes []conf.NodeConfig) int {
	identities := make(map[string]struct{})
	for _, node := range nodes {
		api := node.ApiConfig
		if !api.PluginSupervisorEnabled {
			continue
		}
		identity := fmt.Sprintf("%s|node=%d|credential=%s|name=%s",
			nodeControlIdentity(api), api.NodeID, strings.TrimSpace(api.CredentialFile), strings.TrimSpace(api.NodeName))
		identities[identity] = struct{}{}
	}
	return len(identities)
}

// supervisorForNode creates (or reuses) the Supervisor for the final panel
// node ID.  Base paths from configuration are deliberately namespaced below
// nodes/<id>; this makes state, installed artifacts, and Unix sockets
// impossible to collide across nodes in one Agent process.
func (n *Node) supervisorForNode(nodeID int, api conf.ApiConfig) (*plugin.Supervisor, error) {
	if n.pluginSupervisors == nil {
		n.pluginSupervisors = make(map[int]*plugin.Supervisor)
	}
	if n.supervisorSpecs == nil {
		n.supervisorSpecs = make(map[int]pluginSupervisorSpec)
	}
	spec, err := pluginSupervisorSpecForNodeMode(nodeID, api, n.allowLegacySingleNode)
	if err != nil {
		return nil, err
	}
	if previous, ok := n.supervisorSpecs[nodeID]; ok {
		if !samePluginSupervisorSpec(previous, spec) {
			return nil, fmt.Errorf("conflicting plugin-supervisor configuration for node %d", nodeID)
		}
		return n.pluginSupervisors[nodeID], nil
	}
	factory := n.supervisorFactory
	if factory == nil {
		factory = plugin.NewSupervisor
	}
	environment := spec.environment
	store, err := maintenance.Open(filepath.Join(spec.rootDir, "maintenance.json"), strconv.Itoa(nodeID), environment, panel.Version)
	if err != nil {
		return nil, fmt.Errorf("open maintenance outbox for node %d: %w", nodeID, err)
	}
	supervisor, err := factory(plugin.Config{
		Maintenance: store,
		RootDir:     spec.rootDir,
		SocketDir:   spec.socketDir,
		PublicKey:   spec.publicKey,
		NodeID:      nodeID,
	})
	if err != nil {
		return nil, fmt.Errorf("create plugin supervisor for node %d: %w", nodeID, err)
	}
	if supervisor == nil {
		return nil, fmt.Errorf("create plugin supervisor for node %d returned nil", nodeID)
	}
	n.supervisorSpecs[nodeID] = spec
	n.pluginSupervisors[nodeID] = supervisor
	return supervisor, nil
}

func pluginSupervisorSpecForNode(nodeID int, api conf.ApiConfig) (pluginSupervisorSpec, error) {
	return pluginSupervisorSpecForNodeMode(nodeID, api, false)
}

func pluginSupervisorSpecForNodeMode(nodeID int, api conf.ApiConfig, allowLegacySingleNode bool) (pluginSupervisorSpec, error) {
	if nodeID <= 0 {
		return pluginSupervisorSpec{}, fmt.Errorf("plugin supervisor requires a positive final node ID, got %d", nodeID)
	}
	rootBase := strings.TrimSpace(api.PluginRoot)
	socketBase := strings.TrimSpace(api.PluginSocketDir)
	if rootBase == "" {
		// The O1 layout: data under the state root, sockets in the unit's
		// RuntimeDirectory. A configured PluginRoot without
		// PluginSocketDir keeps its sockets below it, as before.
		rootBase = api.PluginRootDir()
		socketBase = api.PluginSocketBase()
	}
	rootBaseAbs, err := filepath.Abs(rootBase)
	if err != nil {
		return pluginSupervisorSpec{}, fmt.Errorf("resolve plugin root base for node %d: %w", nodeID, err)
	}
	socketDir := filepath.Join(rootBaseAbs, "sockets")
	socketBaseAbs := filepath.Join(rootBaseAbs, "sockets")
	if socketBase != "" {
		socketBaseAbs, err = filepath.Abs(socketBase)
		if err != nil {
			return pluginSupervisorSpec{}, fmt.Errorf("resolve plugin socket base for node %d: %w", nodeID, err)
		}
		socketDir = socketBaseAbs
	}
	rootDir := rootBaseAbs
	legacy := allowLegacySingleNode && (supervisorDataExists(rootBaseAbs) || socketDataExists(socketBaseAbs))
	if !legacy {
		rootDir, err = namespacedPluginPath(rootBase, nodeID)
		if err != nil {
			return pluginSupervisorSpec{}, fmt.Errorf("resolve plugin root for node %d: %w", nodeID, err)
		}
		socketDir = filepath.Join(rootDir, "sockets")
		if socketBase != "" {
			socketDir, err = namespacedPluginPath(socketBase, nodeID)
			if err != nil {
				return pluginSupervisorSpec{}, fmt.Errorf("resolve plugin socket directory for node %d: %w", nodeID, err)
			}
		}
		if err := rejectLegacyPluginSupervisorLayout(rootBaseAbs, rootDir, socketBaseAbs, socketDir, nodeID); err != nil {
			return pluginSupervisorSpec{}, err
		}
	}
	if strings.TrimSpace(api.PluginOfficialPublicKey) == "" {
		return pluginSupervisorSpec{}, fmt.Errorf("PluginOfficialPublicKey is required when PluginSupervisorEnabled is true for node %d", nodeID)
	}
	publicKey, err := plugin.ParseOfficialPublicKey(api.PluginOfficialPublicKey)
	if err != nil {
		return pluginSupervisorSpec{}, err
	}
	environment := strings.TrimSpace(api.MaintenanceEnvironment)
	if environment == "" {
		environment = "development"
	}
	return pluginSupervisorSpec{
		rootDir: rootDir, socketDir: socketDir, publicKey: publicKey,
		identity: nodeControlIdentity(api), legacy: legacy, environment: environment,
	}, nil
}

func nodeControlIdentity(api conf.ApiConfig) string {
	apiHost := strings.ToLower(strings.TrimRight(strings.TrimSpace(api.APIHost), "/"))
	grpcHost := strings.ToLower(strings.TrimSpace(api.GRPCHost))
	keyDigest := sha256.Sum256([]byte(strings.TrimSpace(api.Key)))
	return fmt.Sprintf("%s|%s|%s|%t|%x", apiHost, grpcHost, strings.TrimSpace(api.GRPCServerName), api.GRPCUseTLS, keyDigest[:])
}

// rejectLegacyPluginSupervisorLayout prevents a namespace rollout from
// silently presenting an existing single-node installation as empty.  A
// future migration command can deliberately move this data; normal startup
// must fail closed until then.
func rejectLegacyPluginSupervisorLayout(rootBase, rootDir, socketBase, socketDir string, nodeID int) error {
	if supervisorDataExists(rootDir) {
		return nil
	}
	if supervisorDataExists(rootBase) {
		return fmt.Errorf("legacy plugin supervisor data detected at %s; migrate it to %s before enabling node %d", rootBase, rootDir, nodeID)
	}
	if socketDataExists(socketBase) && !socketDataExists(socketDir) {
		return fmt.Errorf("legacy plugin supervisor sockets detected at %s; migrate them to %s before enabling node %d", socketBase, socketDir, nodeID)
	}
	return nil
}

func supervisorDataExists(root string) bool {
	entries, err := os.ReadDir(root)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "nodes" || name == "sockets" || strings.HasPrefix(name, ".") {
			continue
		}
		if name == "state.json" || entry.IsDir() {
			return true
		}
	}
	return false
}

func socketDataExists(directory string) bool {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sock") {
			return true
		}
	}
	return false
}

func namespacedPluginPath(base string, nodeID int) (string, error) {
	base = strings.TrimSpace(base)
	if base == "" {
		return "", fmt.Errorf("path is empty")
	}
	abs, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	return filepath.Clean(filepath.Join(abs, "nodes", strconv.Itoa(nodeID))), nil
}

func samePluginSupervisorSpec(left, right pluginSupervisorSpec) bool {
	return left.rootDir == right.rootDir && left.socketDir == right.socketDir &&
		len(left.publicKey) == len(right.publicKey) && string(left.publicKey) == string(right.publicKey) &&
		left.identity == right.identity && left.legacy == right.legacy && left.environment == right.environment
}
