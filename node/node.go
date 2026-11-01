package node

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v5/api/agent"
	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/common/maintenance"
	"github.com/AnixOps/anix-agent/v5/conf"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	"github.com/AnixOps/anix-agent/v5/forward"
	"github.com/AnixOps/anix-agent/v5/plugin"
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

	// Phase 1: the controllers and the node-scoped Supervisors.
	//
	// A node may appear more than once in the configuration (for example
	// with different protocol/core settings). Only one control stream is
	// started per node ID, after all controllers have had a chance to
	// attach their node-scoped Supervisor.
	agentNodes := make(map[int]agentNodeStart)
	agentNodeOrder := make([]int, 0, len(nodes))
	controllerIdentities := make(map[*Controller]string)
	for i := range nodes {
		api := &nodes[i].ApiConfig
		api.NodeType = initialNodeType(api.NodeType, nodes[i].Options.Core)
		nodeID := api.NodeID
		if nodeID <= 0 {
			return n.failStart(fmt.Errorf("node %d: NodeID (or AgentNode proxy-<id>) is required", i))
		}
		n.controllers[i] = NewController(core, nodeID, api.APIHost, &nodes[i].Options)
		n.controllers[i].nodeType = api.NodeType
		identity := nodeControlIdentity(*api)
		controllerIdentities[n.controllers[i]] = identity
		var supervisor *plugin.Supervisor
		if api.PluginSupervisorEnabled {
			var err error
			supervisor, err = n.supervisorForNode(nodeID, *api)
			if err != nil {
				return n.failStart(err)
			}
			n.controllers[i].SetPluginSupervisor(supervisor)
		}
		candidate := agentNodeStart{
			apiConfig:  *api,
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

	// Phase 2: one control stream per node, which brings its controllers
	// up from Control's snapshot (or from the stored one).
	networkClaimed := false
	for _, nodeID := range agentNodeOrder {
		candidate := agentNodes[nodeID]
		if candidate.supervisor == nil {
			// A duplicate entry may run without the Supervisor while another
			// entry for the same physical node opts into it. Bind the stream
			// to the controller that owns the node-scoped runtime instead of
			// silently advertising a plugin-less handler.
			if controller := findNodeSupervisorController(n.controllers, controllerIdentities, nodeID, candidate.identity); controller != nil {
				candidate.controller = controller
				candidate.supervisor = controller.pluginSupervisor
			}
		}
		dataPlane := newNodeDataPlane(nodeID, nodeControllers(n.controllers, controllerIdentities, nodeID, candidate.identity))
		if n.forward != nil && nodeID == n.forwardNodeID {
			dataPlane.forward = n.forward
		}
		if !networkClaimed {
			// The core runs one plan: the first node drives it.
			dataPlane.network = newNetworkComponent(nodeID, core)
			networkClaimed = dataPlane.network != nil
		}
		agentClient, err := newAgentControlClientForSupervisor(&candidate.apiConfig, candidate.controller, core, candidate.supervisor, dataPlane)
		if err != nil {
			return n.failStart(fmt.Errorf("node %d: Agent control stream: %w", nodeID, err))
		}
		n.agentClients = append(n.agentClients, agentClient)
		n.dataPlanes = append(n.dataPlanes, dataPlane)
		if err := dataPlane.start(context.Background()); err != nil {
			return n.failStart(err)
		}
	}
	return nil
}

// nodeControllers lists the controllers of a node that share its control
// endpoint: the stream's data plane serves all of them.
func nodeControllers(controllers []*Controller, identities map[*Controller]string, nodeID int, identity string) []*Controller {
	var result []*Controller
	for _, controller := range controllers {
		if controller != nil && controller.nodeID == nodeID && identities[controller] == identity {
			result = append(result, controller)
		}
	}
	return result
}

func findNodeSupervisorController(controllers []*Controller, identities map[*Controller]string, nodeID int, identity string) *Controller {
	for _, controller := range controllers {
		if controller != nil && controller.nodeID == nodeID &&
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

// failStart releases every resource created before a startup error.
func (n *Node) failStart(startErr error) error {
	return errors.Join(startErr, n.closeResources())
}

func (n *Node) closeResources() error {
	var closeErr error
	// Buffered logs go to the spool before the streams close.
	for _, dataPlane := range n.dataPlanes {
		dataPlane.close()
	}
	for _, client := range n.agentClients {
		if client != nil {
			closeErr = errors.Join(closeErr, client.Close())
		}
	}
	n.agentClients = nil
	// The extras once no stream applies a snapshot any more.
	for _, dataPlane := range n.dataPlanes {
		closeErr = errors.Join(closeErr, dataPlane.closeExtras())
	}
	n.dataPlanes = nil

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
		identity := fmt.Sprintf("%s|node=%d", nodeControlIdentity(api), api.NodeID)
		identities[identity] = struct{}{}
	}
	return len(identities)
}

// supervisorForNode creates (or reuses) the Supervisor for the node ID.  Base paths from configuration are deliberately namespaced below
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
	return fmt.Sprintf("%s|%s|%s|%t", apiHost, grpcHost, strings.TrimSpace(api.GRPCServerName), api.GRPCUseTLS)
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
