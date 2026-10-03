package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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

// start brings the node's controllers up from the stream, or from the
// legacy transports when the stream does not serve configuration, and then
// lets later snapshots through (Activate). The client is started here.
func (n *nodeDataPlane) start(ctx context.Context) error {
	plane := n.client.DataPlane()
	if snapshot := plane.PersistedConfig(); snapshot != nil {
		// What the node last applied, without waiting for Control: Hello
		// then reports its revision, and Control sends a snapshot only
		// when the desired configuration moved.
		if err := n.ApplyConfig(ctx, snapshot); err != nil {
			n.logger().WithError(err).WithField("config_revision", snapshot.GetConfigRevision()).
				Warn("Could not start from the stored configuration snapshot; asking Control for the desired one")
			plane.DiscardPersistedConfig()
		} else {
			plane.RestoreConfig(snapshot)
			n.logger().WithField("config_revision", snapshot.GetConfigRevision()).Info("Started from the stored configuration snapshot")
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
	session, err := plane.WaitSession(waitCtx)
	cancel()
	if err == nil && session.Has(agentcontrol.CapabilityConfig) {
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
	} else {
		if err != nil {
			n.logger().WithError(err).Warn("The Agent control stream did not connect in time; starting the node on the legacy transports")
		} else {
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
