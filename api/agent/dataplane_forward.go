package agent

import (
	"fmt"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/AnixOps/anix-control/sdk/forward/wire"
)

// Forwarding on the stream (forward.v1; PROTOCOL.md "Forwarding",
// forward-sdk.md section 8). The data plane only carries it:
//
//   - Hello lists forward.v1 with the node's capabilities in its attribute
//     node_capabilities (ForwardHandler.HelloCapability), next to config.v1
//     and package-reports.v1, which forward.v1 needs.
//   - The node's NodeForwardState rides in config.v1 snapshots of format
//     anixops.nodeconfig/v2; with a ForwardHandler the data plane accepts
//     that format next to v1, and the node's ConfigApplier hands the
//     forward member to the forward component (sdk/forward/wire).
//   - The forward component sends its NodeForwardReport itself, on its own
//     cadence, with SendForwardReport.

// ConfigFormatNodeConfigV2 is anixops.nodeconfig/v1 plus the member
// "forward" holding the node's NodeForwardState (wire.NodeConfigFormat). The
// data plane accepts it when DataPlaneConfig.Forward is set.
const ConfigFormatNodeConfigV2 = wire.NodeConfigFormat

// ForwardHandler is the node's forward component, as the data plane sees it.
type ForwardHandler interface {
	// HelloCapability answers forward.v1 with the node's capabilities in
	// its node_capabilities attribute (wire.HelloCapability). The client
	// asks once, when it is created.
	HelloCapability() (*agentv1pb.Capability, error)
	// ForwardSession tells the component that a session started, and
	// whether it negotiated forward.v1 and package-reports.v1: reports can
	// then be sent with SendForwardReport. It must not block.
	ForwardSession(negotiated bool)
}

// acceptsFormat tells whether the data plane applies snapshots of format.
func (d *DataPlane) acceptsFormat(format string) bool {
	return format == ConfigFormatNodeConfigV1 || (format == ConfigFormatNodeConfigV2 && d.config.Forward != nil)
}

// formatsText names the formats the data plane applies, for refusals.
func (d *DataPlane) formatsText() string {
	if d.config.Forward != nil {
		return ConfigFormatNodeConfigV1 + " and " + ConfigFormatNodeConfigV2
	}
	return ConfigFormatNodeConfigV1
}

// forwardNegotiated tells whether session carries forward reports.
func forwardNegotiated(session DataPlaneSession) bool {
	return session.Has(agentcontrol.CapabilityForward) && session.Has(agentcontrol.CapabilityPackageReports)
}

// SendForwardReport sends a forward report (wire.Report) on the current
// session. It answers ErrSessionGone when there is no session or it did not
// negotiate forward.v1 and package-reports.v1: Control would refuse the
// report (unnegotiated). Like every PackageReport it is the latest value
// only: Control does not acknowledge it and the Agent never spools it.
func (d *DataPlane) SendForwardReport(report *agentv1pb.PackageReport) error {
	if d.config.Forward == nil {
		return ErrSessionGone
	}
	if !wire.IsReport(report) || report.GetVersion() != wire.ReportVersion {
		return fmt.Errorf("agent data plane: not a forward report (plugin_id %q, kind %q, version %q)", report.GetPluginId(), report.GetKind(), report.GetVersion())
	}
	d.mu.Lock()
	session := d.session
	d.mu.Unlock()
	if session.ID == "" || !forwardNegotiated(session) {
		return ErrSessionGone
	}
	return d.client.sendData(session.ID, agentcontrol.CapabilityPackageReports, &agentv1pb.AgentToControl{
		RequestId: newID("forward-report"), NodeId: uint32(d.client.config.NodeID), // #nosec G115 -- node IDs are uint32 on the wire.
		SentAtUnixMs: d.now().UnixMilli(),
		Payload:      &agentv1pb.AgentToControl_PackageReport{PackageReport: report},
	})
}
