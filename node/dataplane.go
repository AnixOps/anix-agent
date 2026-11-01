package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v5/api/agent"
	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/common/monitor"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	"github.com/AnixOps/anix-agent/v5/forward"
	"github.com/AnixOps/anix-agent/v5/plugin"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	log "github.com/sirupsen/logrus"
)

// The node side of the control stream's data plane (AG-3): one per Agent
// control stream, serving every controller of that node. Configuration
// snapshots (config.v1) replace UniProxy's config pull, v2board GetConfig,
// the WebSocket config_update and the node.reload re-pull; they go through
// the same restart path as a legacy configuration change.

// Startup waits of a node whose data plane is on (Node.Start).
var (
	// streamStartupWait bounds the wait for the first session when the
	// node has no stored configuration. Without a session by then the
	// node starts on the legacy transports.
	streamStartupWait = 20 * time.Second
	// streamConfigWait bounds the wait for the first snapshot once a
	// session negotiated config.v1. Control sends one right after the
	// HelloAck; without it the start fails (systemd restarts the Agent)
	// rather than falling back to a transport Control has moved away from.
	streamConfigWait = 60 * time.Second
	// streamLegacyGrace is how long after the stream went down the legacy
	// transports stay off (0: agentapi.DefaultLegacyGrace); tests lower it.
	streamLegacyGrace time.Duration
)

// nodeDataPlane applies what the stream delivers to a node's controllers.
type nodeDataPlane struct {
	nodeID      int
	controllers []*Controller
	// extras run the node's protocols past its first one, by protocol id
	// (reconcileExtras), guarded by extrasMu: an Agent of the installer's
	// configuration has one controller, which runs the first protocol, and
	// a node may serve more, also two of one type.
	extrasMu sync.Mutex
	extras   map[uint64]*Controller
	client   *agentapi.Client
	// forward runs the forwarding state of the node's snapshots (F3b),
	// nil when the node does not forward.
	forward *forward.Component
	// network runs the device's network plan (network.v1), nil when the
	// node does not drive the core's network model.
	network *networkComponent
	// streamOnly marks a node without an API key (the O1 installer's
	// credential-only configuration): it has no legacy transport, so it
	// waits for the stream (enrollment, then Control's snapshot) instead
	// of falling back. awaiting is set while it waits in the background.
	streamOnly bool
	awaiting   atomic.Bool
	background sync.WaitGroup

	// startupUsers are the users the controllers start with during a
	// stream start (startupUsersSet), nil otherwise: they then pull them.
	startupMu       sync.Mutex
	startupUsers    []panel.UserInfo
	startupUsersSet bool

	// Reports (AG-5), guarded by reportMu: each controller's latest online
	// IPs, whether the last traffic report had any, the log buffer.
	reportMu   sync.Mutex
	online     map[*Controller]map[int][]string
	onlineSent bool
	logBuffer  []*agentv1pb.LogEntry
	// lastSystem is the last system usage read, for a status when a new
	// sample fails; health is the runtime health last reported.
	lastSystem *monitor.SystemInfo
	health     *runtimeHealth
	stop       chan struct{}
	stopped    chan struct{}
	stopOnce   sync.Once
}

func newNodeDataPlane(nodeID int, controllers []*Controller) *nodeDataPlane {
	plane := &nodeDataPlane{nodeID: nodeID, controllers: controllers}
	for _, controller := range controllers {
		controller.stream = plane
	}
	return plane
}

// supervisor is the node's plugin Supervisor, nil without one.
func (n *nodeDataPlane) supervisor() *plugin.Supervisor {
	for _, controller := range n.controllers {
		if controller.pluginSupervisor != nil {
			return controller.pluginSupervisor
		}
	}
	return nil
}

// detach returns the controllers to the legacy transports, after the
// stream could not be created.
func (n *nodeDataPlane) detach() {
	for _, controller := range n.controllers {
		if controller.stream == n {
			controller.stream = nil
		}
	}
}

func (n *nodeDataPlane) logger() *log.Entry {
	// Never the controllers' tag field: RemoteLogHook forwards entries
	// carrying it, and these are about the transport itself.
	return log.WithFields(log.Fields{"component": "agent-dataplane", "node_id": n.nodeID})
}

// mode says which transport carries capability's data for this node.
func (n *nodeDataPlane) mode(capability string) agentapi.DataPlaneMode {
	if n == nil || n.client == nil || n.client.DataPlane() == nil {
		return agentapi.DataPlaneLegacy
	}
	return n.client.DataPlane().Mode(capability)
}

// ApplyConfig implements agentapi.ConfigApplier: each controller runs its
// entry of the snapshot, started or reloaded through the legacy restart
// path.
func (n *nodeDataPlane) ApplyConfig(ctx context.Context, snapshot *agentv1pb.ConfigSnapshot) error {
	if n.forward != nil {
		// The forwarding member first: a malformed one refuses the
		// document as a whole.
		if err := n.forward.ApplySnapshot(ctx, snapshot); err != nil {
			return err
		}
	}
	var errs []error
	for _, controller := range n.controllers {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := controller.applySnapshot(snapshot); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", controller.label(), err))
		}
	}
	if err := n.reconcileExtras(ctx, snapshot); err != nil {
		errs = append(errs, err)
	}
	if n.network != nil {
		// After the inbounds: the core joins them to the plan's
		// ingresses.
		if err := n.network.apply(snapshot); err != nil {
			errs = append(errs, err)
		}
	}
	if err := n.applyEgress(snapshot); err != nil {
		errs = append(errs, err)
	}
	if err := n.applyQoS(snapshot); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// applyQoS runs the snapshot's traffic priorities and per-user class caps
// (the member "qos") on the node's core; a snapshot without them turns
// them off. A core that cannot run them is skipped: traffic still flows.
func (n *nodeDataPlane) applyQoS(snapshot *agentv1pb.ConfigSnapshot) error {
	if snapshot == nil {
		return nil
	}
	qos, err := panel.ParseQoS(snapshot.GetConfigJson())
	if err != nil {
		return err
	}
	for _, controller := range n.controllers {
		if controller.server == nil {
			continue
		}
		applier, ok := controller.server.(vCore.QoSApplier)
		if !ok {
			return nil
		}
		if err := applier.ApplyQoS(qos); err != nil {
			return fmt.Errorf("traffic priorities: %w", err)
		}
		return nil
	}
	return nil
}

// applyEgress runs the snapshot's egress routes and relays (the member
// "egress") on the node's core; a snapshot without them removes the ones
// the core ran. A core that cannot run them fails only a snapshot that has
// some.
func (n *nodeDataPlane) applyEgress(snapshot *agentv1pb.ConfigSnapshot) error {
	if snapshot == nil {
		return nil
	}
	egress, err := panel.ParseEgress(snapshot.GetConfigJson())
	if err != nil {
		return err
	}
	var server vCore.Core
	for _, controller := range n.controllers {
		if controller.server != nil {
			server = controller.server
			break
		}
	}
	if server == nil {
		if egress.Empty() {
			return nil
		}
		return errors.New("egress routes: the node has no core")
	}
	applier, ok := server.(vCore.EgressApplier)
	if !ok {
		if egress.Empty() {
			return nil
		}
		return vCore.ErrEgressUnsupported
	}
	if err := applier.ApplyEgress(egress); err != nil {
		return fmt.Errorf("egress routes: %w", err)
	}
	if !egress.Empty() {
		n.logger().WithFields(log.Fields{"egress_routes": len(egress.Routes), "egress_relays": len(egress.Relays)}).
			Info("Applied the node's egress routes")
	}
	return nil
}

// allControllers lists the node's controllers: the configuration file's and
// the extras, in protocol order.
func (n *nodeDataPlane) allControllers() []*Controller {
	n.extrasMu.Lock()
	defer n.extrasMu.Unlock()
	if len(n.extras) == 0 {
		return n.controllers
	}
	all := append([]*Controller(nil), n.controllers...)
	ids := make([]uint64, 0, len(n.extras))
	for id := range n.extras {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		all = append(all, n.extras[id])
	}
	return all
}

// expandingController is the controller whose node runs every protocol of
// a snapshot: the only controller of the node, configured with no
// NodeType (the installer's configuration). It runs the first protocol,
// and extras run the others. nil when the configuration file names the
// node's protocols itself (a NodeType, or several entries).
func (n *nodeDataPlane) expandingController() *Controller {
	if len(n.controllers) != 1 || normalizeNodeType(n.controllers[0].nodeType) != "" {
		return nil
	}
	return n.controllers[0]
}

// reconcileExtras brings the node's extra controllers to snapshot's
// protocols past the first (snapshotExtraProtocols): one that is gone is
// closed first (its port may be another protocol's now), a new one starts
// with the first controller's users, and one that stays applies the
// snapshot as any controller does.
func (n *nodeDataPlane) reconcileExtras(ctx context.Context, snapshot *agentv1pb.ConfigSnapshot) error {
	base := n.expandingController()
	var wanted []uint64
	if base != nil {
		ids, err := snapshotExtraProtocols(snapshot)
		if err != nil {
			return agentapi.InvalidConfig(err)
		}
		wanted = ids
	}
	keep := make(map[uint64]bool, len(wanted))
	for _, id := range wanted {
		keep[id] = true
	}
	var errs []error
	n.extrasMu.Lock()
	for id, extra := range n.extras {
		if keep[id] {
			continue
		}
		delete(n.extras, id)
		n.forgetController(extra)
		if err := extra.Close(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", extra.label(), err))
		}
	}
	n.extrasMu.Unlock()
	for _, id := range wanted {
		if err := ctx.Err(); err != nil {
			return err
		}
		n.extrasMu.Lock()
		extra := n.extras[id]
		n.extrasMu.Unlock()
		if extra != nil {
			if err := extra.applySnapshot(snapshot); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", extra.label(), err))
			}
			continue
		}
		extra = newExtraController(base, id, n)
		if err := n.startExtra(base, extra, snapshot); err != nil {
			_ = extra.Close()
			errs = append(errs, fmt.Errorf("%s: %w", extra.label(), err))
			continue
		}
		n.extrasMu.Lock()
		if n.extras == nil {
			n.extras = map[uint64]*Controller{}
		}
		n.extras[id] = extra
		n.extrasMu.Unlock()
		log.WithField("tag", extra.tag).Info("Started the node's protocol in its own inbound")
	}
	return errors.Join(errs...)
}

// startExtra starts extra from snapshot with the users the node runs: the
// stream start's, else the first controller's.
func (n *nodeDataPlane) startExtra(base, extra *Controller, snapshot *agentv1pb.ConfigSnapshot) error {
	info, err := nodeInfoFromSnapshot(snapshot, "", extra.protocolID, base.apiClient.GetNodeID())
	if err != nil {
		return agentapi.InvalidConfig(err)
	}
	users, ok := n.startupUserList()
	if !ok {
		users = base.currentUsers()
	}
	return extra.startWith(info, users, n.startupAliveList())
}

// closeExtras closes the node's extra controllers, when the node stops.
func (n *nodeDataPlane) closeExtras() error {
	n.extrasMu.Lock()
	extras := n.extras
	n.extras = nil
	n.extrasMu.Unlock()
	var errs []error
	for _, extra := range extras {
		n.forgetController(extra)
		errs = append(errs, extra.Close())
	}
	return errors.Join(errs...)
}

// forgetController drops a closed controller's online IPs from the node's
// reports.
func (n *nodeDataPlane) forgetController(controller *Controller) {
	n.reportMu.Lock()
	delete(n.online, controller)
	n.reportMu.Unlock()
}

// shareLegacyPull hands the users and alive list the node's first
// controller pulled over the legacy transports (nil: unchanged) to the
// extras, which pull nothing themselves.
func (n *nodeDataPlane) shareLegacyPull(from *Controller, users []panel.UserInfo, alive map[int]int) {
	if n == nil || (users == nil && alive == nil) || from != n.expandingController() {
		return
	}
	for _, extra := range n.allControllers()[len(n.controllers):] {
		var copied []panel.UserInfo
		if users != nil {
			copied = append([]panel.UserInfo{}, users...)
		}
		extra.reconcileMu.Lock()
		err := extra.reconcileLocked(nil, copied, alive)
		extra.reconcileMu.Unlock()
		if err != nil {
			log.WithField("tag", extra.tag).WithError(err).Error("Could not apply the node's users")
		}
	}
}

// snapshotExtraProtocols lists the protocols of snapshot past the first, in
// the document's order, that legacy_pull.protocols answers. The first is
// the one legacy_pull.default answers. None when Control sends no
// per-protocol answers (an older Control, or a raw configuration, which the
// node runs instead of its protocols).
func snapshotExtraProtocols(snapshot *agentv1pb.ConfigSnapshot) ([]uint64, error) {
	if snapshot == nil {
		return nil, nil
	}
	var document snapshotDocument
	if err := json.Unmarshal(snapshot.GetConfigJson(), &document); err != nil {
		return nil, fmt.Errorf("decode the configuration document: %w", err)
	}
	if document.LegacyPull == nil || len(document.LegacyPull.Protocols) == 0 || len(document.Protocols) == 0 {
		return nil, nil
	}
	if _, ok := document.LegacyPull.Protocols[strconv.FormatUint(document.Protocols[0].ID, 10)]; !ok {
		return nil, nil
	}
	var ids []uint64
	for _, protocol := range document.Protocols[1:] {
		if body := document.LegacyPull.Protocols[strconv.FormatUint(protocol.ID, 10)]; len(body) > 0 && string(body) != "null" {
			ids = append(ids, protocol.ID)
		}
	}
	return ids, nil
}

// ApplyUsers implements agentapi.UsersApplier: each running controller
// adds and removes the users that changed, without restarting the core.
func (n *nodeDataPlane) ApplyUsers(ctx context.Context, set agentapi.UserSet) error {
	users := panelUsers(set.Users)
	var errs []error
	for _, controller := range n.allControllers() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := controller.applyStreamUsers(users); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", controller.label(), err))
		}
	}
	return errors.Join(errs...)
}

// ApplyAlive implements agentapi.AliveApplier: every controller's device
// limits count the alive list from Control (alive.v1), each user missing
// from it at 0.
func (n *nodeDataPlane) ApplyAlive(ctx context.Context, alive map[uint64]uint32) {
	for _, controller := range n.allControllers() {
		if ctx.Err() != nil {
			return
		}
		controller.applyStreamAlive(aliveMap(alive))
	}
}

// startupAliveList is the alive list a controller starts with during a
// stream start: Control's latest (alive.v1), else empty.
func (n *nodeDataPlane) startupAliveList() map[int]int {
	if n != nil && n.client != nil && n.client.DataPlane() != nil {
		if alive, ok := n.client.DataPlane().AliveList(); ok {
			return aliveMap(alive)
		}
	}
	return make(map[int]int)
}

// aliveMap converts an alive list to the limiter's map.
func aliveMap(alive map[uint64]uint32) map[int]int {
	converted := make(map[int]int, len(alive))
	for uid, count := range alive {
		converted[int(uid)] = int(count) // #nosec G115 -- user ids and device counts fit the limiter's int fields.
	}
	return converted
}

// startupUserList returns a copy of the users to start with, ok false when
// the controller pulls them over the legacy transport.
func (n *nodeDataPlane) startupUserList() ([]panel.UserInfo, bool) {
	if n == nil {
		return nil, false
	}
	n.startupMu.Lock()
	defer n.startupMu.Unlock()
	if !n.startupUsersSet {
		return nil, false
	}
	return append([]panel.UserInfo(nil), n.startupUsers...), true
}

func (n *nodeDataPlane) setStartupUsers(users []*agentv1pb.NodeUser) {
	converted := panelUsers(users)
	n.startupMu.Lock()
	n.startupUsers, n.startupUsersSet = converted, true
	n.startupMu.Unlock()
}

func (n *nodeDataPlane) clearStartupUsers() {
	n.startupMu.Lock()
	n.startupUsers, n.startupUsersSet = nil, false
	n.startupMu.Unlock()
}

// start brings the node's controllers up from the stream, or from the
// legacy transports for what the stream does not serve, and then lets
// later snapshots and user deltas through (Activate). The client is
// started here.
func (n *nodeDataPlane) start(ctx context.Context) error {
	plane := n.client.DataPlane()
	n.stop, n.stopped = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(n.stopped)
		n.runLogFlusher()
	}()
	persistedConfig := plane.PersistedConfig()
	persistedUsers := plane.PersistedUsers()
	if persistedConfig != nil && persistedUsers != nil {
		// What the node last ran, without waiting for Control: Hello then
		// reports its revision and cursor, and Control sends only what
		// moved since.
		n.setStartupUsers(persistedUsers.Users)
		if err := n.ApplyConfig(ctx, persistedConfig); err != nil {
			n.logger().WithError(err).WithField("config_revision", persistedConfig.GetConfigRevision()).
				Warn("Could not start from the stored configuration and users; asking Control for the desired ones")
			plane.DiscardPersistedConfig()
			plane.DiscardPersistedUsers()
			persistedConfig, persistedUsers = nil, nil
			n.clearStartupUsers()
		} else {
			plane.RestoreConfig(persistedConfig)
			plane.RestoreUsers(*persistedUsers)
			n.logger().WithFields(log.Fields{"config_revision": persistedConfig.GetConfigRevision(), "users_cursor": persistedUsers.Cursor}).
				Info("Started from the stored configuration and users")
		}
	}
	if err := n.client.Start(); err != nil {
		n.clearStartupUsers()
		return err
	}
	if n.allStarted() {
		n.clearStartupUsers()
		plane.Activate()
		return nil
	}

	waitCtx, cancel := context.WithTimeout(ctx, streamStartupWait)
	_, waitErr := plane.WaitSession(waitCtx)
	cancel()
	if waitErr != nil && n.streamOnly && persistedConfig == nil {
		// No legacy transport to fall back to: the node starts when the
		// stream comes up (after enrollment, which may wait for the
		// one-time credential), in the background.
		n.logger().WithError(waitErr).Warn("The Agent control stream did not connect in time; this node has no ApiKey for the legacy transports, so it starts once the stream delivers its configuration (enrollment may still be pending)")
		n.awaitStream(persistedUsers)
		return nil
	}
	if waitErr != nil {
		n.logger().WithError(waitErr).Warn("The Agent control stream did not connect in time; starting the node on the stored state or the legacy transports")
	}
	return n.finishStart(ctx, waitErr, persistedConfig, persistedUsers)
}

// streamStartFailed ends the Agent when a stream-only node could not start
// from the stream in the background: systemd starts it again, as after a
// failed start in the foreground. Tests replace it.
var streamStartFailed = func(nodeID int, err error) {
	log.WithFields(log.Fields{"component": "agent-dataplane", "node_id": nodeID}).WithError(err).
		Fatal("Could not start the node from the Agent control stream")
}

// awaitStream starts a stream-only node once its stream has a session.
func (n *nodeDataPlane) awaitStream(persistedUsers *agentapi.UserSet) {
	n.awaiting.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	stop := n.stop
	n.background.Add(1)
	go func() {
		defer n.background.Done()
		defer cancel()
		defer n.awaiting.Store(false)
		go func() {
			select {
			case <-stop:
				cancel()
			case <-ctx.Done():
			}
		}()
		if _, err := n.client.DataPlane().WaitSession(ctx); err != nil {
			n.clearStartupUsers()
			return
		}
		n.logger().Info("The Agent control stream is up; starting the node from it")
		if err := n.finishStart(ctx, nil, nil, persistedUsers); err != nil {
			if ctx.Err() != nil {
				return
			}
			streamStartFailed(n.nodeID, err)
		}
	}()
}

// waitingForStream tells whether a stream-only node is still waiting for
// its stream: its controllers must not start on the legacy transports.
func (n *nodeDataPlane) waitingForStream() bool {
	return n != nil && n.awaiting.Load()
}

// finishStart starts the node's controllers once the stream had its
// chance: from the stream, from the stored state, or on the legacy
// transports.
func (n *nodeDataPlane) finishStart(ctx context.Context, waitErr error, persistedConfig *agentv1pb.ConfigSnapshot, persistedUsers *agentapi.UserSet) error {
	plane := n.client.DataPlane()
	defer n.clearStartupUsers()
	configMode := plane.Mode(agentcontrol.CapabilityConfig)
	usersMode := plane.Mode(agentcontrol.CapabilityUsers)

	// Users first: every controller starts with them.
	var taken *agentapi.UserSet
	switch {
	case usersMode == agentapi.DataPlaneStream:
		usersCtx, cancel := context.WithTimeout(ctx, streamConfigWait)
		set, err := plane.TakeUsers(usersCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("node %d: Control negotiated users.v1 but sent no user set within %s: %w", n.nodeID, streamConfigWait, err)
		}
		n.setStartupUsers(set.Users)
		taken = &set
	case usersMode == agentapi.DataPlanePending && persistedUsers != nil:
		plane.RestoreUsers(*persistedUsers)
		n.setStartupUsers(persistedUsers.Users)
	default:
		if n.streamOnly && configMode == agentapi.DataPlaneStream {
			return fmt.Errorf("node %d: Control serves configuration but not users (users.v1) on the Agent control stream, and this node has no ApiKey for the legacy transports", n.nodeID)
		}
		n.clearStartupUsers()
	}

	switch {
	case configMode == agentapi.DataPlaneStream:
		configCtx, cancel := context.WithTimeout(ctx, streamConfigWait)
		snapshot, err := plane.TakeConfig(configCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("node %d: Control negotiated config.v1 but sent no configuration snapshot within %s: %w", n.nodeID, streamConfigWait, err)
		}
		applyErr := n.ApplyConfig(ctx, snapshot)
		plane.ConfigResult(snapshot, applyErr)
		if applyErr != nil {
			return fmt.Errorf("node %d: apply the configuration snapshot from Control: %w", n.nodeID, applyErr)
		}
	case configMode == agentapi.DataPlanePending && persistedConfig != nil:
		if err := n.ApplyConfig(ctx, persistedConfig); err != nil {
			return fmt.Errorf("node %d: start from the stored configuration snapshot: %w", n.nodeID, err)
		}
		plane.RestoreConfig(persistedConfig)
	default:
		if n.streamOnly {
			return fmt.Errorf("node %d: Control does not serve configuration on the Agent control stream (config.v1), and this node has no ApiKey for the legacy transports: upgrade Control, or configure the node's ApiKey", n.nodeID)
		}
		if waitErr == nil {
			n.logger().Info("Control does not serve configuration on the Agent control stream (config.v1); starting the node on the legacy transports")
		}
		for _, controller := range n.controllers {
			if controller.isStarted() {
				continue
			}
			if err := controller.Start(); err != nil {
				return fmt.Errorf("start node controller %s: %w", controller.label(), err)
			}
		}
	}
	if taken != nil {
		plane.UsersResult(*taken, nil)
	}
	plane.Activate()
	return nil
}

func (n *nodeDataPlane) allStarted() bool {
	for _, controller := range n.controllers {
		if !controller.isStarted() {
			return false
		}
	}
	return true
}

// snapshotDocument is the part of an anixops.nodeconfig/v1 document a proxy
// Agent runs: the UniProxy configuration answers (legacy_pull), byte for
// byte what the legacy pull would give the node.
type snapshotDocument struct {
	Kind string `json:"kind"`
	// Protocols are the node's enabled protocols, in order.
	Protocols []struct {
		ID uint64 `json:"id"`
	} `json:"protocols"`
	LegacyPull *struct {
		Default json.RawMessage            `json:"default"`
		Types   map[string]json.RawMessage `json:"types"`
		// Protocols holds each enabled protocol's answer, by protocol id
		// (UniProxy's protocol_id); Control sends it since v5.0.0-rc.2.
		Protocols map[string]json.RawMessage `json:"protocols"`
	} `json:"legacy_pull"`
}

// nodeInfoFromSnapshot returns the node configuration a controller with
// nodeType (its configured NodeType, empty for the node's default) runs
// from snapshot: legacy_pull.types[nodeType], or legacy_pull.default. An
// extra controller (protocolID set) runs legacy_pull.protocols[protocolID].
func nodeInfoFromSnapshot(snapshot *agentv1pb.ConfigSnapshot, nodeType string, protocolID uint64, nodeID int) (*panel.NodeInfo, error) {
	if snapshot == nil {
		return nil, errors.New("no configuration snapshot")
	}
	var document snapshotDocument
	if err := json.Unmarshal(snapshot.GetConfigJson(), &document); err != nil {
		return nil, fmt.Errorf("decode the configuration document: %w", err)
	}
	if document.Kind != "" && document.Kind != agentcontrol.NodeKindProxy {
		return nil, fmt.Errorf("the configuration is of a %s node; this Agent runs proxy nodes", document.Kind)
	}
	if document.LegacyPull == nil {
		return nil, errors.New("the configuration document has no legacy_pull")
	}
	var body json.RawMessage
	if protocolID != 0 {
		body = document.LegacyPull.Protocols[strconv.FormatUint(protocolID, 10)]
		if len(body) == 0 || string(body) == "null" {
			return nil, fmt.Errorf("the node serves no protocol %d (legacy_pull.protocols)", protocolID)
		}
	} else if normalized := normalizeNodeType(nodeType); normalized != "" {
		body = document.LegacyPull.Types[normalized]
		if len(body) == 0 || string(body) == "null" {
			return nil, fmt.Errorf("the node serves no %q configuration (legacy_pull.types)", normalized)
		}
	} else {
		body = document.LegacyPull.Default
		if len(body) == 0 || string(body) == "null" {
			return nil, errors.New("the configuration has no default answer (legacy_pull.default)")
		}
	}
	info, _, err := panel.ParseNodeInfo(body, nodeID)
	return info, err
}

// panelUsers converts the stream's users to the node's user list, as the
// legacy user pulls give it (UniProxy user, v2board GetUsers): extra_json
// carries the WireGuard peer fields.
func panelUsers(users []*agentv1pb.NodeUser) []panel.UserInfo {
	converted := make([]panel.UserInfo, 0, len(users))
	for _, user := range users {
		info := panel.UserInfo{
			Id: int(user.GetUserId()), Uuid: user.GetUuid(), // #nosec G115 -- user ids fit the legacy int field.
			SpeedLimit: int(user.GetSpeedLimitMbps()), DeviceLimit: int(user.GetDeviceLimit()),
		}
		if len(user.GetExtraJson()) > 0 {
			var extra map[string]string
			if err := json.Unmarshal(user.GetExtraJson(), &extra); err == nil && len(extra) > 0 {
				info.Extra = extra
				info.WireGuardPeerIP = extra["wireguard_peer_ip"]
				info.WireGuardPublicKey = extra["wireguard_public_key"]
				if info.WireGuardPublicKey == "" {
					info.WireGuardPublicKey = extra["wireguard_peer_public_key"]
				}
				info.WireGuardPresharedKey = extra["wireguard_preshared_key"]
			}
		}
		converted = append(converted, info)
	}
	return converted
}

// normalizeNodeType is Control's service.NormalizeNodeType: the key of
// legacy_pull.types.
func normalizeNodeType(nodeType string) string {
	normalized := strings.ToLower(strings.TrimSpace(nodeType))
	switch normalized {
	case "v2ray", "vmess-aead", "vmessaead":
		return "vmess"
	default:
		return normalized
	}
}
