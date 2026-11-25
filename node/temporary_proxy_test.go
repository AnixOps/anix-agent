package node

import (
	"encoding/json"
	"testing"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/require"
)

// proxyRecordingCore is a recordingCore that runs temporary proxies.
type proxyRecordingCore struct {
	*recordingCore
	applied [][]panel.TemporaryProxy
}

func (c *proxyRecordingCore) ApplyTemporaryProxies(proxies []panel.TemporaryProxy) error {
	c.applied = append(c.applied, proxies)
	return nil
}

func proxySnapshot(t *testing.T, proxies any) *agentv1pb.ConfigSnapshot {
	t.Helper()
	document := map[string]any{"kind": "proxy"}
	if proxies != nil {
		document["temporary_proxies"] = proxies
	}
	encoded, err := json.Marshal(document)
	require.NoError(t, err)
	return &agentv1pb.ConfigSnapshot{ConfigRevision: 1, ConfigJson: encoded}
}

var oneProxy = []map[string]any{{"id": 4, "listen": "10.126.126.1", "port": 1080, "username": "tmp-4",
	"password": "0123456789abcdef", "expires_at_unix_ms": 1764045000000}}

func TestApplyTemporaryProxiesRunsTheSnapshotsProxiesOnTheCore(t *testing.T) {
	core := &proxyRecordingCore{recordingCore: newRecordingCore()}
	plane := newNodeDataPlane(29, []*Controller{{server: core}})

	require.NoError(t, plane.applyTemporaryProxies(proxySnapshot(t, oneProxy)))
	require.Len(t, core.applied, 1)
	require.Equal(t, uint64(4), core.applied[0][0].ID)
	require.Equal(t, "10.126.126.1", core.applied[0][0].Listen)

	// A snapshot without proxies stops what the core ran.
	require.NoError(t, plane.applyTemporaryProxies(proxySnapshot(t, nil)))
	require.Len(t, core.applied, 2)
	require.Empty(t, core.applied[1])

	public := []map[string]any{{"id": 5, "listen": "0.0.0.0", "port": 1080, "username": "u",
		"password": "0123456789abcdef", "expires_at_unix_ms": 1764045000000}}
	require.ErrorContains(t, plane.applyTemporaryProxies(proxySnapshot(t, public)), "not an internal address")
	require.Len(t, core.applied, 2)
}

func TestApplyTemporaryProxiesFailsOnACoreWithoutThemOnlyWhenThereAreSome(t *testing.T) {
	plane := newNodeDataPlane(29, []*Controller{{server: newRecordingCore()}})
	require.NoError(t, plane.applyTemporaryProxies(proxySnapshot(t, nil)))
	require.ErrorIs(t, plane.applyTemporaryProxies(proxySnapshot(t, oneProxy)), vCore.ErrTemporaryProxyUnsupported)
}
