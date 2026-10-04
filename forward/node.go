package forward

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	agentstate "github.com/AnixOps/anix-agent/v4/api/agent/state"
	"github.com/AnixOps/anix-agent/v4/diagnostic"
	"github.com/AnixOps/anix-agent/v4/upgrade"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	log "github.com/sirupsen/logrus"
)

// A forward node's Agent (forward-<id>): no proxy core, only the control
// stream and the forward component. Control authenticates a forward node's
// stream by client certificate only, so the Agent enrolls first (with the
// forward node's token and x-node-kind forward, or a one-time enrollment
// credential); the stream then carries config.v1 (the anixops.nodeconfig/v2
// document, whose v1 part describes the node and has nothing else for the
// Agent to run), package-reports.v1 for the reports, and forward.v1.

// NodeConfig configures a forward node's Agent.
type NodeConfig struct {
	// Client is the stream's configuration: Target, NodeID, APIKey (the
	// forward node's token, used only to enroll), UseTLS, ServerName,
	// RootCAs, Identity (required), AgentVersion, Labels. NodeKind,
	// DataPlane and Handler are set by StartNode.
	Client agentapi.Config
	// StateRoot is the data-plane state root (the stored snapshot and
	// session); empty is the default.
	StateRoot string
	// Component is the forward component, already started.
	Component *Component
	// GostUnit is gost's systemd unit for the diagnostic tasks; empty is
	// anixops-gost.service.
	GostUnit string
	// Upgrader runs Control-pushed upgrades (agent.upgrade, upgrade.v1,
	// listed when its updater is installed); nil turns them off.
	Upgrader *upgrade.Agent
}

// DefaultGostUnit is the unit the gost driver runs gost as.
const DefaultGostUnit = "anixops-gost.service"

// NodeDiagnostics answers the agent.diagnostic executor of a node that
// forwards with component: the forward checks, and the generic tasks on
// gost's unit, which the component manages, so it is not restarted from
// a task.
func NodeDiagnostics(component *Component, gostUnit string) *diagnostic.Executor {
	if gostUnit == "" {
		gostUnit = DefaultGostUnit
	}
	return &diagnostic.Executor{
		Forward:   component,
		Units:     map[string]string{"gost": gostUnit},
		NoRestart: map[string]string{"gost": "managed by the forward component"},
	}
}

// DiagnosticCapabilities answers the operation capability of
// NodeDiagnostics when existing does not list it yet: agent.diagnostic.
// diag.v1, which tells Control the handler runs the forward checks, comes
// from the data plane (DataPlaneConfig.Diagnostics).
func DiagnosticCapabilities(existing []*agentv1pb.Capability) []*agentv1pb.Capability {
	if agentcontrol.HasCapability(existing, diagnostic.Operation) {
		return nil
	}
	return []*agentv1pb.Capability{{Name: diagnostic.Operation, Version: agentcontrol.CapabilityVersionV1}}
}

// Node is a running forward node's Agent.
type Node struct {
	client    *agentapi.Client
	component *Component
}

// StartNode connects a forward node's Agent: it restores the stored
// snapshot (so Hello reports the revision the node runs and Control sends
// only what moved), starts the stream and lets later snapshots through.
func StartNode(ctx context.Context, config NodeConfig) (*Node, error) {
	if config.Component == nil {
		return nil, errors.New("forward node: the forward component is required")
	}
	if config.Client.Identity == nil {
		return nil, errors.New("forward node: the agent identity is required (Control authenticates forward nodes by client certificate)")
	}
	node := agentcontrol.AgentNode{Kind: agentcontrol.NodeKindForward, ID: uint32(config.Client.NodeID)} // #nosec G115 -- NewClient bounds the ID.
	if config.Component.NodeRef() != node.String() {
		return nil, fmt.Errorf("forward node: the component serves %s, not %s", config.Component.NodeRef(), node.String())
	}
	store, err := agentstate.Open(config.StateRoot, node)
	if err != nil {
		return nil, err
	}
	applier := config.Component.Applier(nil)
	clientConfig := config.Client
	clientConfig.NodeKind = agentcontrol.NodeKindForward
	clientConfig.DataPlane = &agentapi.DataPlaneConfig{State: store, Config: applier, Forward: config.Component, Diagnostics: true}
	diagnostics := NodeDiagnostics(config.Component, config.GostUnit)
	upgrader := config.Upgrader
	if upgrader != nil {
		clientConfig.DataPlane.Upgrade = upgrader.Available(ctx)
		clientConfig.Admit = upgrader.Admit
	}
	clientConfig.Handler = agentapi.OperationHandlerFunc(func(ctx context.Context, operation *agentv1pb.DesiredOperation) (json.RawMessage, error) {
		switch operation.GetKind() {
		case "agent.ping":
			return json.Marshal(map[string]any{"node": node.String(), "time": time.Now().UnixMilli()})
		case diagnostic.Operation:
			return diagnostics.Handle(ctx, operation)
		case agentcontrol.OperationKindAgentUpgrade:
			if upgrader == nil {
				return nil, fmt.Errorf("unsupported desired operation %q on a forward node", operation.GetKind())
			}
			return upgrader.Handle(ctx, operation)
		default:
			return nil, fmt.Errorf("unsupported desired operation %q on a forward node", operation.GetKind())
		}
	})
	if !agentcontrol.HasCapability(clientConfig.Capabilities, "agent.ping") {
		clientConfig.Capabilities = append(clientConfig.Capabilities,
			&agentv1pb.Capability{Name: "agent.control", Version: agentcontrol.CapabilityVersionV1},
			&agentv1pb.Capability{Name: "agent.ping", Version: agentcontrol.CapabilityVersionV1})
	}
	clientConfig.Capabilities = append(clientConfig.Capabilities, DiagnosticCapabilities(clientConfig.Capabilities)...)
	client, err := agentapi.NewClient(clientConfig)
	if err != nil {
		return nil, err
	}
	config.Component.SetSender(client.DataPlane().SendForwardReport)
	config.Component.AttachLinkClient(client)
	client.OnIdentityRejected(config.Component.IdentityRejected)
	plane := client.DataPlane()
	if persisted := plane.PersistedConfig(); persisted != nil {
		// The component re-applied its own state at start; the stored
		// snapshot carries the same generation, so this is a no-op that
		// lets Hello report the revision.
		if err := applier.ApplyConfig(ctx, persisted); err != nil {
			log.WithError(err).WithField("node", node.String()).Warn("Could not restore the stored configuration snapshot; asking Control for the desired one")
			plane.DiscardPersistedConfig()
		} else {
			plane.RestoreConfig(persisted)
		}
	}
	if err := client.Start(); err != nil {
		_ = client.Close()
		return nil, err
	}
	plane.Activate()
	return &Node{client: client, component: config.Component}, nil
}

// Client answers the node's control stream client.
func (n *Node) Client() *agentapi.Client { return n.client }

// Close ends the stream. The component and forwarding keep running until
// the component is closed.
func (n *Node) Close() error { return n.client.Close() }
