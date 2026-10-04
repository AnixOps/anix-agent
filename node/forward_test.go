package node

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v4/api/agent/agenttest"
	"github.com/AnixOps/anix-agent/v4/conf"
	"github.com/AnixOps/anix-agent/v4/forward"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"github.com/AnixOps/anix-control/sdk/forward/driver"
	"github.com/AnixOps/anix-control/sdk/forward/driver/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyNodeStreamCarriesForwarding(t *testing.T) {
	fixture := newStreamNodeFixture(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityPackageReports, agentcontrol.CapabilityForward)
	proxy := agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: fixture.control.NodeID}
	host := fake.NewHost(nil)
	registry := driver.NewRegistry()
	require.NoError(t, registry.Register(fake.New(host, fake.Options{})))
	component, err := forward.New(forward.Options{Node: proxy, Registry: registry, StateDir: filepath.Join(t.TempDir(), "forward"), ReportMinGap: 10 * time.Millisecond})
	require.NoError(t, err)
	require.NoError(t, component.Start(context.Background()))
	t.Cleanup(component.Close)

	state := &forwardv1.NodeForwardState{NodeRef: proxy.String(), Generation: 1, StateHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Hops: []*forwardv1.NodeHop{{
			RouteId: "R1", Role: forwardv1.HopRole_HOP_ROLE_ENTRY, Engine: forwardv1.Engine_ENGINE_NFTABLES, Mark: 1,
			Listen:    &forwardv1.Listen{Port: 30001, Protocol: forwardv1.L4Protocol_L4_PROTOCOL_TCP},
			Upstreams: []*forwardv1.Upstream{{Address: "192.0.2.10", Port: 443, Weight: 1}},
			Balance:   forwardv1.BalanceStrategy_BALANCE_STRATEGY_ROUND_ROBIN,
			Health:    &forwardv1.HealthCheck{Disabled: true},
		}}}
	fixture.control.SetDesiredConfig(agenttest.ForwardSnapshot(3, proxyDocument(443), state), false)
	node := New()
	node.SetForward(component, int(fixture.control.NodeID))
	require.NoError(t, node.Start([]conf.NodeConfig{fixture.nodeConfig(t)}, fixture.core))
	t.Cleanup(node.Close)

	// The proxy part runs, and the forwarding part too.
	_, info := fixture.core.node()
	require.NotNil(t, info)
	assert.Equal(t, 443, info.VAllss.ServerPort)
	assert.Equal(t, uint64(1), component.Status().Generation)
	assert.True(t, component.Status().Applied)
	require.Eventually(t, func() bool {
		for _, r := range fixture.control.ForwardReports() {
			if r.GetNodeRef() == proxy.String() && r.GetGeneration() == 1 && r.GetApplied() {
				return true
			}
		}
		return false
	}, 5*time.Second, 10*time.Millisecond)
	require.NotNil(t, fixture.control.NodeCapabilities())
	require.Eventually(t, func() bool { return lastStatus(fixture.control) != nil }, 5*time.Second, 10*time.Millisecond)
	assert.True(t, lastStatus(fixture.control).GetApplied())
}

func TestForwardNodeSelection(t *testing.T) {
	stream := func(id int) conf.NodeConfig {
		return conf.NodeConfig{ApiConfig: conf.ApiConfig{NodeID: id, AgentControlEnabled: true}}
	}
	node, proxyID, err := forwardNode(&conf.ForwardConfig{Enable: true}, []conf.NodeConfig{stream(7)})
	require.NoError(t, err)
	assert.Equal(t, "proxy-7", node.String())
	assert.Equal(t, 7, proxyID)
	_, _, err = forwardNode(&conf.ForwardConfig{Enable: true}, []conf.NodeConfig{stream(7), stream(8)})
	assert.Error(t, err, "two candidates need ProxyNodeID")
	node, _, err = forwardNode(&conf.ForwardConfig{Enable: true, ProxyNodeID: 8}, []conf.NodeConfig{stream(7), stream(8)})
	require.NoError(t, err)
	assert.Equal(t, "proxy-8", node.String())
	_, _, err = forwardNode(&conf.ForwardConfig{Enable: true, ProxyNodeID: 9}, []conf.NodeConfig{stream(7)})
	assert.Error(t, err)
	node, _, err = forwardNode(&conf.ForwardConfig{Enable: true, NodeKind: "forward", ForwardNode: &conf.ApiConfig{NodeID: 41}}, nil)
	require.NoError(t, err)
	assert.Equal(t, "forward-41", node.String())
}
