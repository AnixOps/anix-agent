package agent

import (
	"errors"
	"testing"

	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
)

func TestMeshReportKinds(t *testing.T) {
	for _, test := range []struct {
		plugin, kind, version string
		ok                    bool
	}{
		{MeshPluginID, MeshStatusKind, MeshStatusVersion, true},
		{MeshPluginID, MeshRegionRequestKind, MeshRegionRequestVersion, true},
		{MeshPluginID, MeshRegionRequestKind, "v2", false},
		{MeshPluginID, "mesh.other", "v1", false},
		{"network", MeshStatusKind, MeshStatusVersion, false},
	} {
		report := &agentv1pb.PackageReport{PluginId: test.plugin, Kind: test.kind, Version: test.version}
		if got := meshReport(report); got != test.ok {
			t.Errorf("%s %s %s: %v", test.plugin, test.kind, test.version, got)
		}
	}
	// Without the mesh the data plane sends neither.
	d := &DataPlane{}
	if err := d.SendMeshReport(&agentv1pb.PackageReport{PluginId: MeshPluginID, Kind: MeshRegionRequestKind, Version: MeshRegionRequestVersion}); !errors.Is(err, ErrSessionGone) {
		t.Fatalf("err = %v", err)
	}
}
