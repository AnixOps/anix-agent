package conf

import (
	"fmt"
	"path/filepath"
	"strings"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
)

// Forwarding (forward-sdk.md sections 6 to 9, F3b): the Agent runs
// Control's routes with the nftables and gost drivers. One host forwards for
// one node, since the drivers own one nftables table and one gost unit:
//
//   - NodeKind "forward": a forward node (forward-<id>) of its own, with no
//     proxy core: ForwardNode is its connection to Control, and Nodes and
//     Cores may be empty;
//   - NodeKind "proxy" (the default): the stream of a proxy node in Nodes
//     carries forwarding too (ProxyNodeID, or the only node whose control
//     stream carries its data plane).
type ForwardConfig struct {
	Enable   bool   `json:"Enable"`
	NodeKind string `json:"NodeKind"`
	// ProxyNodeID is the proxy node whose stream carries forwarding; 0 is
	// the only node with AgentControlEnabled and the stream data plane.
	ProxyNodeID int `json:"ProxyNodeID"`
	// ForwardNode is a forward node's connection to Control: ApiHost or
	// GRPCHost, GRPCUseTLS, GRPCServerName, NodeID (the forward node's id),
	// ApiKey (its token, used only to enroll), AgentIdentity (required:
	// Control authenticates forward nodes by client certificate),
	// AgentStream.
	ForwardNode *ApiConfig `json:"ForwardNode"`
	// StateDir keeps the applied forwarding state (DefaultForwardStateDir).
	StateDir string                `json:"StateDir"`
	Nftables ForwardNftablesConfig `json:"Nftables"`
	Gost     ForwardGostConfig     `json:"Gost"`
}

// DefaultForwardStateDir is the Agent's own forwarding state, not gost's
// directory (/var/lib/anixops-gost) nor the Agent's PKI directory.
const DefaultForwardStateDir = "/var/lib/anixops-agent/forward"

// Forward node kinds.
const (
	ForwardNodeKindProxy   = "proxy"
	ForwardNodeKindForward = "forward"
)

// ForwardNftablesConfig configures the nftables driver (H13: the Agent
// needs CAP_NET_ADMIN).
type ForwardNftablesConfig struct {
	Disable bool `json:"Disable"`
	// MarkMask is the connection mark bits the driver owns (0x0fff0000 when
	// 0); change it where Docker, WireGuard or policy routing use them.
	MarkMask uint32 `json:"MarkMask"`
	// LimitInterfaces are the egress interfaces that carry rate-limited
	// hops (tc HTB); without one, bandwidth limits are off on this node.
	LimitInterfaces []string `json:"LimitInterfaces"`
	// MSSClampInterfaces are encapsulating egress interfaces (WireGuard,
	// GRE) whose forwarded SYNs get their MSS clamped.
	MSSClampInterfaces []string `json:"MSSClampInterfaces"`
	NFT                string   `json:"NFT"`
	TC                 string   `json:"TC"`
}

// ForwardGostConfig configures the gost driver (H20: the pinned gost the
// Agent's package ships, run as anixops-gost.service).
type ForwardGostConfig struct {
	Disable    bool   `json:"Disable"`
	Binary     string `json:"Binary"`
	Dir        string `json:"Dir"`
	RuntimeDir string `json:"RuntimeDir"`
	// ManualLinkCertificates leaves the link certificate files to the
	// operator; by default the Agent gets them from Control's link CA (H28).
	ManualLinkCertificates bool `json:"ManualLinkCertificates"`
}

// Kind answers the forwarding node kind, proxy by default.
func (f *ForwardConfig) Kind() string {
	if f == nil || strings.TrimSpace(f.NodeKind) == "" {
		return ForwardNodeKindProxy
	}
	return strings.ToLower(strings.TrimSpace(f.NodeKind))
}

// Enabled tells whether the Agent forwards.
func (f *ForwardConfig) Enabled() bool { return f != nil && f.Enable }

// ForwardNodeOnly tells whether the Agent runs a forward node of its own.
func (f *ForwardConfig) ForwardNodeOnly() bool {
	return f.Enabled() && f.Kind() == ForwardNodeKindForward
}

// Dir answers the state directory.
func (f *ForwardConfig) Dir() string {
	if f == nil || strings.TrimSpace(f.StateDir) == "" {
		return DefaultForwardStateDir
	}
	return filepath.Clean(strings.TrimSpace(f.StateDir))
}

// normalizeAgentNodes reads every node's AgentNode ("proxy-<id>",
// "forward-<id>"), and turns a forward node's entry of Nodes, as the O1
// installer writes it, into the forward node of the Forward section: a
// forward node's Agent runs no proxy controller.
func (p *Conf) normalizeAgentNodes() error {
	kept := p.NodeConfig[:0]
	for i := range p.NodeConfig {
		api := &p.NodeConfig[i].ApiConfig
		name := strings.TrimSpace(api.AgentNode)
		if name == "" {
			kept = append(kept, p.NodeConfig[i])
			continue
		}
		node, err := agentcontrol.ParseAgentNode(name)
		if err != nil || (node.Kind != agentcontrol.NodeKindProxy && node.Kind != agentcontrol.NodeKindForward) {
			return fmt.Errorf("node %d: AgentNode %q is not proxy-<id> or forward-<id>", i, api.AgentNode)
		}
		if api.NodeID != 0 && api.NodeID != int(node.ID) {
			return fmt.Errorf("node %d: AgentNode %q and NodeID %d name different nodes", i, api.AgentNode, api.NodeID)
		}
		api.NodeID = int(node.ID)
		if node.Kind == agentcontrol.NodeKindProxy {
			kept = append(kept, p.NodeConfig[i])
			continue
		}
		if p.Forward == nil {
			p.Forward = &ForwardConfig{}
		}
		if p.Forward.ForwardNode != nil {
			return fmt.Errorf("node %d: more than one forward node; one host forwards for one node", i)
		}
		forwardNode := *api
		p.Forward.Enable, p.Forward.NodeKind, p.Forward.ForwardNode = true, ForwardNodeKindForward, &forwardNode
	}
	p.NodeConfig = kept
	return nil
}

// Validate checks the section.
func (f *ForwardConfig) Validate() error {
	if !f.Enabled() {
		return nil
	}
	if !filepath.IsAbs(f.Dir()) {
		return fmt.Errorf("Forward.StateDir %q must be an absolute path", f.StateDir)
	}
	switch f.Kind() {
	case ForwardNodeKindProxy:
		if f.ForwardNode != nil {
			return fmt.Errorf("Forward.ForwardNode is for NodeKind %q", ForwardNodeKindForward)
		}
	case ForwardNodeKindForward:
		node := f.ForwardNode
		if node == nil {
			return fmt.Errorf("Forward.NodeKind %q needs Forward.ForwardNode", ForwardNodeKindForward)
		}
		if node.NodeID <= 0 {
			return fmt.Errorf("Forward.ForwardNode needs NodeID (or AgentNode forward-<id>)")
		}
		if strings.TrimSpace(node.APIHost) == "" && strings.TrimSpace(node.GRPCHost) == "" {
			return fmt.Errorf("Forward.ForwardNode needs ApiHost or GRPCHost")
		}
		if err := node.AgentIdentity.Validate(); err != nil {
			return fmt.Errorf("Forward.ForwardNode: %w", err)
		}
		if node.AgentIdentity.EnrollMode() != AgentIdentityEnrollAuto {
			return fmt.Errorf("Forward.ForwardNode.AgentIdentity must enroll: Control authenticates forward nodes by client certificate")
		}
		if err := node.AgentStream.Validate(); err != nil {
			return fmt.Errorf("Forward.ForwardNode: %w", err)
		}
	default:
		return fmt.Errorf("Forward.NodeKind %q is not %q or %q", f.NodeKind, ForwardNodeKindProxy, ForwardNodeKindForward)
	}
	for _, list := range [][]string{f.Nftables.LimitInterfaces, f.Nftables.MSSClampInterfaces} {
		for _, name := range list {
			if strings.TrimSpace(name) == "" || len(name) > 15 {
				return fmt.Errorf("Forward.Nftables: %q is not an interface name", name)
			}
		}
	}
	return nil
}
