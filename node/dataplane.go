package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	"github.com/AnixOps/anix-agent/v4/api/panel"
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
)

// nodeDataPlane applies what the stream delivers to a node's controllers.
type nodeDataPlane struct {
	nodeID      int
	controllers []*Controller
	client      *agentapi.Client

	// startupUsers are the users the controllers start with during a
	// stream start (startupUsersSet), nil otherwise: they then pull them.
	startupMu       sync.Mutex
	startupUsers    []panel.UserInfo
	startupUsersSet bool
}

func newNodeDataPlane(nodeID int, controllers []*Controller) *nodeDataPlane {
	plane := &nodeDataPlane{nodeID: nodeID, controllers: controllers}
	for _, controller := range controllers {
		controller.stream = plane
	}
	return plane
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
	var errs []error
	for _, controller := range n.controllers {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := controller.applySnapshot(snapshot); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", controller.label(), err))
		}
	}
	return errors.Join(errs...)
}

// ApplyUsers implements agentapi.UsersApplier: each running controller
// adds and removes the users that changed, without restarting the core.
func (n *nodeDataPlane) ApplyUsers(ctx context.Context, set agentapi.UserSet) error {
	users := panelUsers(set.Users)
	var errs []error
	for _, controller := range n.controllers {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := controller.applyStreamUsers(users); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", controller.label(), err))
		}
	}
	return errors.Join(errs...)
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
	defer n.clearStartupUsers()
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
		return err
	}
	if n.allStarted() {
		plane.Activate()
		return nil
	}

	waitCtx, cancel := context.WithTimeout(ctx, streamStartupWait)
	_, waitErr := plane.WaitSession(waitCtx)
	cancel()
	if waitErr != nil {
		n.logger().WithError(waitErr).Warn("The Agent control stream did not connect in time; starting the node on the stored state or the legacy transports")
	}
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
	Kind       string `json:"kind"`
	LegacyPull *struct {
		Default json.RawMessage            `json:"default"`
		Types   map[string]json.RawMessage `json:"types"`
	} `json:"legacy_pull"`
}

// nodeInfoFromSnapshot returns the node configuration a controller with
// nodeType (its configured NodeType, empty for the node's default) runs
// from snapshot: legacy_pull.types[nodeType], or legacy_pull.default.
func nodeInfoFromSnapshot(snapshot *agentv1pb.ConfigSnapshot, nodeType string, nodeID int) (*panel.NodeInfo, error) {
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
	if normalized := normalizeNodeType(nodeType); normalized != "" {
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
