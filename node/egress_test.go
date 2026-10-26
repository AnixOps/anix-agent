package node

import (
	"encoding/json"
	"testing"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/require"
)

// egressRecordingCore is a recordingCore that runs egress routes.
type egressRecordingCore struct {
	*recordingCore
	applied []*panel.EgressConfig
}

func (c *egressRecordingCore) ApplyEgress(config *panel.EgressConfig) error {
	c.applied = append(c.applied, config)
	return nil
}

func egressSnapshot(t *testing.T, egress any) *agentv1pb.ConfigSnapshot {
	t.Helper()
	document := map[string]any{"kind": "proxy"}
	if egress != nil {
		document["egress"] = egress
	}
	encoded, err := json.Marshal(document)
	require.NoError(t, err)
	return &agentv1pb.ConfigSnapshot{ConfigRevision: 1, ConfigJson: encoded}
}

func TestApplyEgressRunsTheSnapshotsEgressOnTheCore(t *testing.T) {
	core := &egressRecordingCore{recordingCore: newRecordingCore()}
	plane := newNodeDataPlane(29, []*Controller{{server: core}})
	route := map[string]any{"routes": []map[string]any{{"id": 1, "domains": []string{"openai.com"},
		"server": map[string]any{"host": "jp.example", "port": 24680, "method": "2022-blake3-aes-128-gcm", "password": "k"}}}}

	require.NoError(t, plane.applyEgress(egressSnapshot(t, route)))
	require.Len(t, core.applied, 1)
	require.Equal(t, []string{"openai.com"}, core.applied[0].Routes[0].Domains)

	// A snapshot without egress removes what the core ran.
	require.NoError(t, plane.applyEgress(egressSnapshot(t, nil)))
	require.Len(t, core.applied, 2)
	require.True(t, core.applied[1].Empty())

	require.ErrorContains(t, plane.applyEgress(egressSnapshot(t, map[string]any{"relays": []map[string]any{{"id": 1}}})), "invalid port")
}

func TestApplyEgressFailsOnACoreWithoutEgressOnlyWhenThereIsSome(t *testing.T) {
	plane := newNodeDataPlane(29, []*Controller{{server: newRecordingCore()}})
	require.NoError(t, plane.applyEgress(egressSnapshot(t, nil)))
	relay := map[string]any{"relays": []map[string]any{{"id": 1, "port": 24680, "method": "m", "password": "k"}}}
	require.ErrorIs(t, plane.applyEgress(egressSnapshot(t, relay)), vCore.ErrEgressUnsupported)
}
