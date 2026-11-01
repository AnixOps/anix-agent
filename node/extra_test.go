package node

import (
	"strconv"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/agent/agenttest"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// multiProtocolDocument is a document of a node serving one vless
// protocol per port, in order, with ids 100, 101, ...: legacy_pull.default
// and types answer the first, legacy_pull.protocols each.
func multiProtocolDocument(ports ...int) map[string]any {
	document := proxyDocument(ports[0])
	protocols := make([]any, 0, len(ports))
	answers := map[string]any{}
	for i, port := range ports {
		id := 100 + i
		protocols = append(protocols, map[string]any{"id": id, "type": "vless", "port": port})
		answers[strconv.Itoa(id)] = runtimeAnswer(port)
	}
	document["protocols"] = protocols
	document["runtime"].(map[string]any)["protocols"] = answers
	return document
}

// tagsByPort maps the core's nodes to their ports.
func (c *recordingCore) tagsByPort() map[int]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	ports := map[int]string{}
	for tag, info := range c.nodes {
		if info.VAllss != nil {
			ports[info.VAllss.ServerPort] = tag
		}
	}
	return ports
}

// One controller (the installer's configuration) runs every protocol of
// the node, also two of one type, each in its own inbound with its own
// tag; users reach all of them; a protocol that goes away is removed.
func TestStreamConfigurationRunsEveryProtocolOfTheNode(t *testing.T) {
	fixture := newStreamNodeFixture(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers)
	fixture.control.SetDesiredConfig(agenttest.Snapshot(3, multiProtocolDocument(11111, 11112, 11113)), false)
	fixture.control.UpsertUsers(&agentv1pb.NodeUser{UserId: 1, Uuid: "user-1"})
	node := fixture.start(t)

	byPort := fixture.core.tagsByPort()
	require.Len(t, byPort, 3, "one inbound per protocol")
	assert.Contains(t, byPort[11111], "vless:12")
	assert.NotContains(t, byPort[11111], "#", "the first protocol keeps the node's tag")
	assert.Contains(t, byPort[11112], "vless:12#101")
	assert.Contains(t, byPort[11113], "vless:12#102")
	for port, tag := range byPort {
		assert.ElementsMatch(t, []string{"user-1"}, fixture.core.userUUIDs(tag), "port %d", port)
	}
	require.Eventually(t, func() bool {
		status := lastStatus(fixture.control)
		return status != nil && status.ConfigRevision == 3
	}, 5*time.Second, 10*time.Millisecond)
	assert.True(t, lastStatus(fixture.control).Applied, lastStatus(fixture.control).Error)
	assert.Len(t, node.controllers, 1, "the configuration file's controller only")

	// Users reach every inbound in place.
	fixture.control.UpsertUsers(&agentv1pb.NodeUser{UserId: 2, Uuid: "user-2"})
	require.Eventually(t, func() bool {
		for _, tag := range fixture.core.tagsByPort() {
			if len(fixture.core.userUUIDs(tag)) != 2 {
				return false
			}
		}
		return true
	}, 5*time.Second, 10*time.Millisecond)

	// The middle protocol goes away; the last one changes its port.
	document := multiProtocolDocument(11111, 11112, 11113)
	document["protocols"] = []any{document["protocols"].([]any)[0], map[string]any{"id": 102, "type": "vless", "port": 11114}}
	answers := document["runtime"].(map[string]any)["protocols"].(map[string]any)
	delete(answers, "101")
	answers["102"] = runtimeAnswer(11114)
	fixture.control.SetDesiredConfig(agenttest.Snapshot(4, document), true)
	require.Eventually(t, func() bool {
		status := lastStatus(fixture.control)
		return status != nil && status.ConfigRevision == 4
	}, 5*time.Second, 10*time.Millisecond)
	assert.True(t, lastStatus(fixture.control).Applied, lastStatus(fixture.control).Error)
	byPort = fixture.core.tagsByPort()
	require.Len(t, byPort, 2)
	assert.Contains(t, byPort[11111], "vless:12")
	assert.Contains(t, byPort[11114], "vless:12#102")

	// Without per-protocol answers (an older Control) the node runs its
	// first protocol only, as before.
	fixture.control.SetDesiredConfig(agenttest.Snapshot(5, proxyDocument(11111)), true)
	require.Eventually(t, func() bool {
		status := lastStatus(fixture.control)
		return status != nil && status.ConfigRevision == 5
	}, 5*time.Second, 10*time.Millisecond)
	byPort = fixture.core.tagsByPort()
	require.Len(t, byPort, 1)
	assert.Contains(t, byPort, 11111)
}

func TestSnapshotExtraProtocols(t *testing.T) {
	ids, err := snapshotExtraProtocols(agenttest.Snapshot(1, multiProtocolDocument(1, 2, 3)))
	require.NoError(t, err)
	assert.Equal(t, []uint64{101, 102}, ids)

	// A raw configuration: Control answers no protocol.
	raw := multiProtocolDocument(1, 2)
	delete(raw["runtime"].(map[string]any), "protocols")
	ids, err = snapshotExtraProtocols(agenttest.Snapshot(1, raw))
	require.NoError(t, err)
	assert.Empty(t, ids)

	info, err := nodeInfoFromSnapshot(agenttest.Snapshot(1, multiProtocolDocument(1, 2)), "", 101, 12)
	require.NoError(t, err)
	assert.Equal(t, 2, info.VAllss.ServerPort)
	_, err = nodeInfoFromSnapshot(agenttest.Snapshot(1, multiProtocolDocument(1, 2)), "", 105, 12)
	assert.ErrorContains(t, err, "runtime.protocols")
}
