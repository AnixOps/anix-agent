package agenttest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"github.com/AnixOps/anix-control/sdk/forward/wire"
	"google.golang.org/protobuf/proto"
)

// Forwarding (forward.v1), modelled on anix-control's
// internal/grpc/agent_control_forward.go and agent_control_package_reports.go:
//
//   - forward.v1 is offered to a proxy or forward node when Control serves
//     it, the Hello lists it with a node_capabilities attribute that
//     wire.NodeCapabilitiesFromHello accepts for the stream's node, and the
//     session gets config.v1, which carries the state;
//   - a forward node is offered config.v1, and package-reports.v1 only with
//     forward.v1; never users.v1, reports.v1, maintenance.v1, alive.v1 or
//     artifacts.v1;
//   - a forward node's session that negotiated forward.v1 heartbeats every
//     60 s (ForwardHeartbeatSeconds);
//   - a PackageReport of plugin_id forward and kind forward.report is the
//     node's NodeForwardReport: refused (dropped and counted, the stream
//     stays open) without forward.v1, with another version or a payload
//     wire.DecodeReport refuses for the stream's node; accepted otherwise.
//
// The tests build the anixops.nodeconfig/v2 snapshots themselves
// (ForwardSnapshot): Control sends v2 only while the node's last Hello
// negotiated forward.v1.

// ForwardHeartbeatSeconds is the heartbeat a forward node's forward.v1
// session is asked for (forward-sdk.md 8.4).
const ForwardHeartbeatSeconds = 60

// defaultHeartbeatSeconds keeps the other sessions' tests fast.
const defaultHeartbeatSeconds = 1

type forwardState struct {
	capabilities *forwardv1.NodeCapabilities
	reports      []*forwardv1.NodeForwardReport
	refused      map[string]int
	heartbeats   []uint32
}

// node is the stream's node.
func (c *Control) node() agentcontrol.AgentNode {
	kind := c.NodeKind
	if kind == "" {
		kind = agentcontrol.NodeKindProxy
	}
	return agentcontrol.AgentNode{Kind: kind, ID: c.NodeID}
}

// servesForwardLocked tells whether the Hello gets forward.v1 (c.mu held).
func (c *Control) servesForwardLocked(hello *agentv1pb.Hello) bool {
	if !c.serves[agentcontrol.CapabilityForward] || !c.serves[agentcontrol.CapabilityConfig] ||
		!agentcontrol.HasCapabilityVersion(hello.GetCapabilities(), agentcontrol.CapabilityConfig, agentcontrol.CapabilityVersionV1) {
		return false
	}
	_, listed, err := wire.NodeCapabilitiesFromHello(hello.GetCapabilities(), c.node().String())
	return listed && err == nil
}

// offersLocked tells whether the node's kind gets capability name.
func (c *Control) offersLocked(name string, forward bool) bool {
	if name == agentcontrol.CapabilityForward {
		return forward
	}
	if c.node().Kind != agentcontrol.NodeKindForward {
		return true
	}
	switch name {
	case agentcontrol.CapabilityConfig:
		return true
	case agentcontrol.CapabilityPackageReports:
		return forward
	default:
		return false
	}
}

// recordForwardHelloLocked records the Hello's node capabilities (a Hello
// without forward.v1 clears them) and answers the session's heartbeat.
func (c *Control) recordForwardHelloLocked(current *session, hello *agentv1pb.Hello) uint32 {
	c.forward.capabilities = nil
	if current.negotiated[agentcontrol.CapabilityForward] {
		caps, _, _ := wire.NodeCapabilitiesFromHello(hello.GetCapabilities(), c.node().String())
		c.forward.capabilities = caps
	}
	heartbeat := uint32(defaultHeartbeatSeconds)
	if c.node().Kind == agentcontrol.NodeKindForward && current.negotiated[agentcontrol.CapabilityForward] {
		heartbeat = ForwardHeartbeatSeconds
	}
	c.forward.heartbeats = append(c.forward.heartbeats, heartbeat)
	return heartbeat
}

// handleForwardReport records or refuses a forward report.
func (c *Control) handleForwardReport(current *session, report *agentv1pb.PackageReport) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.forward.refused == nil {
		c.forward.refused = map[string]int{}
	}
	switch {
	case !current.negotiated[agentcontrol.CapabilityForward]:
		c.forward.refused["unnegotiated"]++
		return
	case report.GetVersion() != wire.ReportVersion:
		c.forward.refused["invalid"]++
		return
	}
	decoded, err := wire.DecodeReport(report.GetPayloadJson(), c.node().String())
	if err != nil {
		c.forward.refused["bad_payload"]++
		return
	}
	c.forward.reports = append(c.forward.reports, decoded)
}

// ForwardReports returns every forward report accepted, decoded.
func (c *Control) ForwardReports() []*forwardv1.NodeForwardReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*forwardv1.NodeForwardReport, len(c.forward.reports))
	for i, r := range c.forward.reports {
		out[i] = proto.Clone(r).(*forwardv1.NodeForwardReport)
	}
	return out
}

// ForwardRefusals returns the forward reports refused, by reason.
func (c *Control) ForwardRefusals() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]int{}
	for k, v := range c.forward.refused {
		out[k] = v
	}
	return out
}

// NodeCapabilities returns the node capabilities of the last Hello that
// negotiated forward.v1, nil after one that did not.
func (c *Control) NodeCapabilities() *forwardv1.NodeCapabilities {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.forward.capabilities == nil {
		return nil
	}
	return proto.Clone(c.forward.capabilities).(*forwardv1.NodeCapabilities)
}

// Heartbeats returns the heartbeat interval each HelloAck asked for.
func (c *Control) Heartbeats() []uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]uint32(nil), c.forward.heartbeats...)
}

// ForwardSnapshot builds an anixops.nodeconfig/v2 snapshot at revision:
// document (the v1 part) plus the member "forward" holding state, hashed
// as Control hashes it.
func ForwardSnapshot(revision uint64, document map[string]any, state *forwardv1.NodeForwardState) *agentv1pb.ConfigSnapshot {
	member, err := wire.StateMember(state)
	if err != nil {
		panic(err)
	}
	full := map[string]any{}
	for k, v := range document {
		full[k] = v
	}
	full[wire.NodeConfigMember] = member
	encoded, err := json.Marshal(full)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(encoded)
	return &agentv1pb.ConfigSnapshot{ConfigRevision: revision, ConfigHash: hex.EncodeToString(sum[:]), Format: wire.NodeConfigFormat, ConfigJson: encoded}
}
