package agent

import (
	"fmt"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/AnixOps/anix-control/sdk/network"
)

// The device network model on the stream (network.v1; PROTOCOL.md "Network
// model", anix-control docs/design/network-model). The data plane only
// carries it:
//
//   - Hello lists network.v1 with the device's DeviceCapabilities in its
//     attribute device_capabilities (NetworkHandler.HelloCapability), next
//     to config.v1, which carries the plan, and package-reports.v1, which
//     carries the status.
//   - The device's NetworkPlan is the member "network" of the config.v1
//     document (either format); the node's ConfigApplier hands it to the
//     network component (network.PlanFromNodeConfig).
//   - The network component sends its NetworkStatus itself with
//     SendNetworkStatus.

// NetworkHandler is the node's network component, as the data plane sees
// it.
type NetworkHandler interface {
	// HelloCapability answers network.v1 with the device's capabilities in
	// its device_capabilities attribute (network.HelloCapability).
	HelloCapability() (*agentv1pb.Capability, error)
	// NetworkSession tells the component that a session started, and
	// whether it negotiated network.v1 and package-reports.v1: statuses can
	// then be sent with SendNetworkStatus. It must not block.
	NetworkSession(negotiated bool)
}

// networkNegotiated tells whether session carries network statuses.
func networkNegotiated(session DataPlaneSession) bool {
	return session.Has(agentcontrol.CapabilityNetwork) && session.Has(agentcontrol.CapabilityPackageReports)
}

// SendNetworkStatus sends a network status (network.StatusReport) on the
// current session. It answers ErrSessionGone when there is no session or it
// did not negotiate network.v1 and package-reports.v1. Like every
// PackageReport it is the latest value only: Control does not acknowledge it
// and the Agent never spools it.
func (d *DataPlane) SendNetworkStatus(report *agentv1pb.PackageReport) error {
	if d.config.Network == nil {
		return ErrSessionGone
	}
	if !network.IsStatusReport(report) || report.GetVersion() != network.StatusVersion {
		return fmt.Errorf("agent data plane: not a network status (plugin_id %q, kind %q, version %q)", report.GetPluginId(), report.GetKind(), report.GetVersion())
	}
	d.mu.Lock()
	session := d.session
	d.mu.Unlock()
	if session.ID == "" || !networkNegotiated(session) {
		return ErrSessionGone
	}
	return d.client.sendData(session.ID, agentcontrol.CapabilityPackageReports, &agentv1pb.AgentToControl{
		RequestId: newID("network-status"), NodeId: uint32(d.client.config.NodeID), // #nosec G115 -- node IDs are uint32 on the wire.
		SentAtUnixMs: d.now().UnixMilli(),
		Payload:      &agentv1pb.AgentToControl_PackageReport{PackageReport: report},
	})
}
