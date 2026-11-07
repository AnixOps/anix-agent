package node

import (
	"context"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/agent/agenttest"
	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exitPolicyCore is a core that runs an exit policy and counts what it
// refused.
type exitPolicyCore struct {
	*recordingCore
	policies []panel.ExitPolicy
	blocked  uint64
}

func (c *exitPolicyCore) ApplyExitPolicy(policy panel.ExitPolicy) error {
	c.mu.Lock()
	c.policies = append(c.policies, policy)
	c.mu.Unlock()
	return nil
}

func (c *exitPolicyCore) MainlandBlocked(context.Context) (uint64, error) {
	return c.blocked, nil
}

func (c *exitPolicyCore) lastPolicy() (panel.ExitPolicy, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.policies) == 0 {
		return panel.ExitPolicy{}, 0
	}
	return c.policies[len(c.policies)-1], len(c.policies)
}

func TestStreamConfigurationAppliesTheExitPolicy(t *testing.T) {
	fixture := newStreamNodeFixture(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers)
	core := &exitPolicyCore{recordingCore: fixture.core}
	document := proxyDocument(443)
	document["exit_policy"] = map[string]any{"block_mainland": true}
	fixture.control.SetDesiredConfig(agenttest.Snapshot(3, document), false)
	node := New()
	require.NoError(t, node.Start([]conf.NodeConfig{fixture.nodeConfig(t)}, core))
	t.Cleanup(node.Close)
	policy, _ := core.lastPolicy()
	assert.True(t, policy.BlockMainland)

	// A snapshot without the member turns it off.
	fixture.control.SetDesiredConfig(agenttest.Snapshot(4, proxyDocument(443)), true)
	require.Eventually(t, func() bool {
		policy, applied := core.lastPolicy()
		return applied >= 2 && !policy.BlockMainland
	}, 5*time.Second, 10*time.Millisecond)
}

func TestAgentMetricsCarryTheMainlandCounter(t *testing.T) {
	core := &exitPolicyCore{recordingCore: newRecordingCore()}
	metrics, err := agentMetrics(t.Context(), core, nil)
	require.NoError(t, err)
	assert.Nil(t, metrics, "nothing refused, nothing reported")

	core.blocked = 4
	metrics, err = agentMetrics(t.Context(), core, nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]float64{mainlandBlockedMetric: 4}, metrics)

	metrics, err = agentMetrics(t.Context(), newRecordingCore(), nil)
	require.NoError(t, err)
	assert.Nil(t, metrics)
}
