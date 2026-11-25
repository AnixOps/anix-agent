package agent

import (
	"fmt"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
)

// The intranet mesh on the stream (anix-control
// docs/design/mesh-regions/agent-contract.md): the networks ride in the
// member "mesh" of config.v1, whatever was negotiated; the node's status
// goes as a PackageReport of plugin_id MeshPluginID and kind MeshStatusKind,
// only on a session that negotiated CapabilityMesh and package-reports.v1.

const (
	// CapabilityMesh is the data-plane capability of the mesh status.
	CapabilityMesh = "mesh"
	// MeshPluginID, MeshStatusKind and MeshStatusVersion name the report.
	MeshPluginID      = "mesh"
	MeshStatusKind    = "mesh.status"
	MeshStatusVersion = "v1"
)

// MeshHandler is the node's mesh component, as the data plane sees it.
type MeshHandler interface {
	// MeshSession tells the component that a session started, and whether
	// it negotiated the mesh and package-reports.v1. It must not block.
	MeshSession(negotiated bool)
}

func meshNegotiated(session DataPlaneSession) bool {
	return session.Has(CapabilityMesh) && session.Has(agentcontrol.CapabilityPackageReports)
}

// SendMeshStatus sends a mesh status on the current session. It answers
// ErrSessionGone without a session that negotiated the mesh. Like every
// PackageReport it is the latest value only and never spooled.
func (d *DataPlane) SendMeshStatus(report *agentv1pb.PackageReport) error {
	if d.config.Mesh == nil {
		return ErrSessionGone
	}
	if report.GetPluginId() != MeshPluginID || report.GetKind() != MeshStatusKind || report.GetVersion() != MeshStatusVersion {
		return fmt.Errorf("agent data plane: not a mesh status (plugin_id %q, kind %q, version %q)", report.GetPluginId(), report.GetKind(), report.GetVersion())
	}
	d.mu.Lock()
	session := d.session
	d.mu.Unlock()
	if session.ID == "" || !meshNegotiated(session) {
		return ErrSessionGone
	}
	return d.client.sendData(session.ID, agentcontrol.CapabilityPackageReports, &agentv1pb.AgentToControl{
		RequestId: newID("mesh-status"), NodeId: uint32(d.client.config.NodeID), // #nosec G115 -- node IDs are uint32 on the wire.
		SentAtUnixMs: d.now().UnixMilli(),
		Payload:      &agentv1pb.AgentToControl_PackageReport{PackageReport: report},
	})
}
