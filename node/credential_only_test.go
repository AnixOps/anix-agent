package node

import (
	"os"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/agent/agenttest"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCredentialOnlyProxyNodeStartsFromTheStream: a proxy node as the O1
// installer configures it enrolls with its one-time credential and runs
// Control's configuration and users from the stream, never with an API key.
func TestCredentialOnlyProxyNodeStartsFromTheStream(t *testing.T) {
	fixture := newStreamNodeFixture(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers)
	fixture.control.SetDesiredConfig(agenttest.Snapshot(3, proxyDocument(443)), false)
	fixture.control.UpsertUsers(&agentv1pb.NodeUser{UserId: 1, Uuid: "user-1"})

	node := fixture.start(t, fixture.nodeConfig(t))
	require.True(t, node.controllers[0].isStarted())
	_, info := fixture.core.node()
	require.NotNil(t, info, "the node runs the snapshot")
	assert.Equal(t, "vless", info.Type)
	_, err := os.Stat(fixture.credential)
	assert.True(t, os.IsNotExist(err), "the one-time credential is removed after use")
	for _, stream := range fixture.control.Streams() {
		assert.False(t, stream.APIKey, "never an API key")
	}
}

// TestCredentialOnlyProxyNodeWaitsForItsCredential: before its credential
// is written the node cannot enroll; it starts in the background, and runs
// once the credential arrives.
func TestCredentialOnlyProxyNodeWaitsForItsCredential(t *testing.T) {
	previousWait := streamStartupWait
	streamStartupWait = 200 * time.Millisecond
	t.Cleanup(func() { streamStartupWait = previousWait })
	fixture := newStreamNodeFixture(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers)
	fixture.control.SetDesiredConfig(agenttest.Snapshot(3, proxyDocument(443)), false)
	fixture.control.UpsertUsers(&agentv1pb.NodeUser{UserId: 1, Uuid: "user-1"})
	credential, err := os.ReadFile(fixture.credential)
	require.NoError(t, err)
	require.NoError(t, os.Remove(fixture.credential))

	node := fixture.start(t, fixture.nodeConfig(t))
	controller := node.controllers[0]
	assert.False(t, controller.isStarted())
	assert.True(t, controller.stream.waitingForStream())

	require.NoError(t, os.WriteFile(fixture.credential, credential, 0o600))
	require.Eventually(t, controller.isStarted, 20*time.Second, 50*time.Millisecond)
	// A controller reports started inside the background start
	// (nodeDataPlane.finishStart), which then still reports the snapshot
	// and activates the data plane; the node stops "waiting for the stream"
	// only when that start returns. So the node is started before it is no
	// longer waiting, and the second is awaited, not read at the instant of
	// the first.
	require.Eventually(t, func() bool { return !controller.stream.waitingForStream() }, 20*time.Second, 10*time.Millisecond)
	_, info := fixture.core.node()
	require.NotNil(t, info)
}

// TestCredentialOnlyProxyNodeNeedsTLS: without TLS there is no client
// certificate, and so no credential at all.
func TestCredentialOnlyProxyNodeNeedsTLS(t *testing.T) {
	fixture := newStreamNodeFixture(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig)
	config := fixture.nodeConfig(t)
	config.ApiConfig.GRPCUseTLS = false
	config.ApiConfig.AgentControlAllowInsecure = true
	config.ApiConfig.APIHost = "http://control.test"
	config.ApiConfig.GRPCHost = "127.0.0.1:1"
	controller := NewController(fixture.core, config.ApiConfig.NodeID, config.ApiConfig.APIHost, &config.Options)
	_, err := newAgentControlClientForSupervisor(&config.ApiConfig, controller, fixture.core, nil, newNodeDataPlane(config.ApiConfig.NodeID, []*Controller{controller}))
	require.ErrorContains(t, err, "needs TLS")
}
