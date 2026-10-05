package node

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/conf"
	"github.com/AnixOps/anix-agent/v4/forward"
	"github.com/AnixOps/anix-agent/v4/upgrade"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	log "github.com/sirupsen/logrus"
)

// Forwarding (F3b): the forward component rides one control stream per
// host, a forward node's of its own (StartForward) or a proxy node's
// (Node.SetForward).

// forwardProbeTimeout bounds the drivers' host probe at start.
const forwardProbeTimeout = 30 * time.Second

// NewForwardComponent probes the host, builds the drivers and the forward
// component of the node cfg names, and starts it: the persisted state is
// re-applied before any stream connects. nodes are the proxy nodes, for a
// proxy node's forwarding.
func NewForwardComponent(cfg *conf.ForwardConfig, nodes []conf.NodeConfig) (*forward.Component, int, error) {
	node, proxyNodeID, err := forwardNode(cfg, nodes)
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), forwardProbeTimeout)
	defer cancel()
	drivers, err := forward.BuildDrivers(ctx, forward.Settings{
		Nftables: forward.NftablesSettings{
			Disable: cfg.Nftables.Disable, NFT: cfg.Nftables.NFT, TC: cfg.Nftables.TC, MarkMask: cfg.Nftables.MarkMask,
			LimitInterfaces: cfg.Nftables.LimitInterfaces, MSSClampInterfaces: cfg.Nftables.MSSClampInterfaces,
		},
		Gost: forward.GostSettings{
			Disable: cfg.Gost.Disable, Binary: cfg.Gost.Binary, Dir: cfg.Gost.Dir, RuntimeDir: cfg.Gost.RuntimeDir,
			ManualLinkCertificates: cfg.Gost.ManualLinkCertificates,
		},
		AnixOps: forward.AnixOpsSettings{
			Enable: cfg.AnixOps.Enable, Binary: cfg.AnixOps.Binary, Dir: cfg.AnixOps.Dir, RuntimeDir: cfg.AnixOps.RuntimeDir,
			ManualLinkCertificates: cfg.AnixOps.ManualLinkCertificates,
		},
	})
	if err != nil {
		return nil, 0, err
	}
	component, err := forward.New(forward.Options{
		Node: node, Registry: drivers.Registry, Unavailable: drivers.Unavailable, Retired: drivers.Retired, Sources: drivers.Sources,
		StateDir: cfg.Dir(), AgentVersion: panel.Version, Host: forward.ProbeHost(),
		LinkCertificates: drivers.LinkCertificates, Links: drivers.Links,
	})
	if err != nil {
		return nil, 0, err
	}
	if err := component.Start(context.Background()); err != nil {
		return nil, 0, err
	}
	log.WithFields(log.Fields{"component": "forward", "node": node.String(), "engines": drivers.Registry.Engines()}).Info("Forward component started")
	return component, proxyNodeID, nil
}

// forwardNode answers the node the Agent forwards for.
func forwardNode(cfg *conf.ForwardConfig, nodes []conf.NodeConfig) (agentcontrol.AgentNode, int, error) {
	if cfg.ForwardNodeOnly() {
		return agentcontrol.AgentNode{Kind: agentcontrol.NodeKindForward, ID: uint32(cfg.ForwardNode.NodeID)}, 0, nil // #nosec G115 -- validated positive
	}
	id := cfg.ProxyNodeID
	if id == 0 {
		var candidates []int
		seen := map[int]bool{}
		for _, n := range nodes {
			if dataPlaneEnabled(n.ApiConfig) && n.ApiConfig.NodeID > 0 && !seen[n.ApiConfig.NodeID] {
				seen[n.ApiConfig.NodeID] = true
				candidates = append(candidates, n.ApiConfig.NodeID)
			}
		}
		if len(candidates) != 1 {
			return agentcontrol.AgentNode{}, 0, fmt.Errorf("forwarding on a proxy node needs Forward.ProxyNodeID: %d nodes carry the stream data plane", len(candidates))
		}
		id = candidates[0]
	}
	found := false
	for _, n := range nodes {
		if n.ApiConfig.NodeID == id && dataPlaneEnabled(n.ApiConfig) {
			found = true
		}
	}
	if !found {
		return agentcontrol.AgentNode{}, 0, fmt.Errorf("forwarding needs proxy node %d with AgentControlEnabled and the stream data plane", id)
	}
	return agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: uint32(id)}, id, nil // #nosec G115 -- node IDs are uint32 on the wire
}

// SetForward makes the stream of proxy node nodeID carry forwarding with
// component, from the next Start on.
func (n *Node) SetForward(component *forward.Component, nodeID int) {
	n.lifecycle.Lock()
	defer n.lifecycle.Unlock()
	n.forward, n.forwardNodeID = component, nodeID
}

// attachForward binds the component to a proxy node's new client.
func attachForward(component *forward.Component, client *agentapi.Client) {
	component.SetSender(client.DataPlane().SendForwardReport)
	component.AttachLinkClient(client)
	client.OnIdentityRejected(component.IdentityRejected)
}

// StartForward connects a forward node's Agent (forward-<id>): no proxy
// core, only the control stream that carries the forwarding state.
func StartForward(cfg *conf.ForwardConfig, component *forward.Component) (*forward.Node, error) {
	api := *cfg.ForwardNode
	target, useTLS, serverName, err := resolveAgentControlTarget(&api)
	if err != nil {
		return nil, err
	}
	if !useTLS {
		return nil, fmt.Errorf("a forward node's control stream needs TLS: Control authenticates forward nodes by client certificate")
	}
	settings := api.AgentIdentity
	hostname, _ := os.Hostname()
	return forward.StartNode(context.Background(), forward.NodeConfig{
		StateRoot: api.AgentStream.Dir(),
		Component: component,
		Upgrader:  upgrade.Shared(panel.Version),
		Client: agentapi.Config{
			Target: target, NodeID: api.NodeID, APIKey: api.Key, UseTLS: true, ServerName: serverName,
			AgentVersion: panel.Version, InstanceID: fmt.Sprintf("%s-%d-forward-%d", hostname, os.Getpid(), api.NodeID),
			KeepaliveTime: time.Duration(api.GRPCKeepalive) * time.Second, RootCAs: agentControlRootCAs,
			Labels: map[string]string{"node_kind": agentcontrol.NodeKindForward},
			Identity: &agentapi.IdentityConfig{
				Dir: settings.Dir(), Enroll: true, Cluster: strings.TrimSpace(settings.Cluster),
				EnrollCredentialFile: strings.TrimSpace(settings.EnrollCredentialFile),
			},
		},
	})
}
