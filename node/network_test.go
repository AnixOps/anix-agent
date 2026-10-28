package node

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	agentapi "github.com/AnixOps/anix-agent/v5/api/agent"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
	"github.com/AnixOps/anix-control/sdk/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeNetworkCore is a core that runs the network model.
type fakeNetworkCore struct {
	vCore.Core
	kinds   []*networkv1.KindSupport
	applied []*networkv1.NetworkPlan
	err     error
}

func (f *fakeNetworkCore) NetworkKinds() []*networkv1.KindSupport { return f.kinds }

func (f *fakeNetworkCore) ApplyNetwork(plan *networkv1.NetworkPlan) (*networkv1.NetworkStatus, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.applied = append(f.applied, plan)
	return &networkv1.NetworkStatus{}, nil
}

func (f *fakeNetworkCore) NetworkStatus() (*networkv1.NetworkStatus, error) {
	return &networkv1.NetworkStatus{}, nil
}

func networkKinds() []*networkv1.KindSupport {
	return []*networkv1.KindSupport{
		{Component: networkv1.Component_COMPONENT_INGRESS, Kind: network.IngressDirect, Versions: []uint32{1}},
		{Component: networkv1.Component_COMPONENT_EGRESS, Kind: network.EgressNATDirect, Versions: []uint32{1}},
	}
}

func networkSnapshot(t *testing.T, plan *networkv1.NetworkPlan) *agentv1pb.ConfigSnapshot {
	t.Helper()
	document := map[string]any{}
	if plan != nil {
		member, err := network.PlanMember(plan)
		require.NoError(t, err)
		document[network.NodeConfigMember] = member
	}
	raw, err := json.Marshal(document)
	require.NoError(t, err)
	return &agentv1pb.ConfigSnapshot{ConfigJson: raw}
}

func devicePlan(generation uint64, egressKind string) *networkv1.NetworkPlan {
	plan := &networkv1.NetworkPlan{
		DeviceRef: "proxy-1",
		Lines:     []*networkv1.Line{{Id: "ln-1", Interface: "eth0", Families: []networkv1.Family{networkv1.Family_FAMILY_V4}}},
		Ingresses: []*networkv1.Ingress{{Id: "in-1", LineId: "ln-1", Kind: network.IngressDirect, KindVersion: 1,
			Audience: networkv1.Audience_AUDIENCE_USER, Family: networkv1.Family_FAMILY_V4,
			Listen: &networkv1.Endpoint{Address: "0.0.0.0", Port: 443}, Protocols: []string{"vless"},
			Pairing: &networkv1.Pairing{Mode: networkv1.PairingMode_PAIRING_MODE_SAME_LINE}}},
		Egresses: []*networkv1.Egress{{Id: "eg-1", LineId: "ln-1", Kind: egressKind, KindVersion: 1,
			Audience: networkv1.Audience_AUDIENCE_INTERNET, Family: networkv1.Family_FAMILY_V4, Source: network.SourceAuto}},
		Paths: []*networkv1.Path{{Id: "pa-1", IngressId: "in-1", Next: &networkv1.Path_EgressId{EgressId: "eg-1"}}},
	}
	network.Stamp(plan, network.Generation{Generation: generation - 1})
	return plan
}

func TestNetworkComponentNeedsACoreThatRunsTheModel(t *testing.T) {
	assert.Nil(t, newNetworkComponent(1, &fakeNetworkCore{}))
	assert.Nil(t, newNetworkComponent(1, struct{ vCore.Core }{}))
	component := newNetworkComponent(1, &fakeNetworkCore{kinds: networkKinds()})
	require.NotNil(t, component)
	capability, err := component.HelloCapability()
	require.NoError(t, err)
	caps, listed, err := network.DeviceCapabilitiesFromHello([]*agentv1pb.Capability{capability}, "proxy-1")
	require.NoError(t, err)
	require.True(t, listed)
	assert.Len(t, caps.GetKinds(), 2)
}

// A plan with a new hash reaches the core once; generation 0 and a
// document without the member leave the core as it is; a plan for another
// device or a kind the core does not run is refused before the core.
func TestNetworkComponentAppliesNewPlansOnly(t *testing.T) {
	core := &fakeNetworkCore{kinds: networkKinds()}
	component := newNetworkComponent(1, core)

	require.NoError(t, component.apply(networkSnapshot(t, nil)))
	require.NoError(t, component.apply(networkSnapshot(t, &networkv1.NetworkPlan{DeviceRef: "proxy-1"})))
	assert.Empty(t, core.applied)

	plan := devicePlan(1, network.EgressNATDirect)
	require.NoError(t, component.apply(networkSnapshot(t, plan)))
	require.NoError(t, component.apply(networkSnapshot(t, plan)))
	require.Len(t, core.applied, 1)
	assert.Equal(t, plan.GetHash(), core.applied[0].GetHash())

	other := devicePlan(2, network.EgressNATDirect)
	other.DeviceRef = "proxy-2"
	err := component.apply(networkSnapshot(t, other))
	require.ErrorIs(t, err, agentapi.ErrConfigInvalid)

	dedicated := devicePlan(2, network.EgressDedicatedIP)
	err = component.apply(networkSnapshot(t, dedicated))
	require.Error(t, err)
	assert.NotErrorIs(t, err, agentapi.ErrConfigInvalid)
	assert.Contains(t, err.Error(), network.EgressDedicatedIP)

	core.err = errors.New("anixcore: this anixcore has no network model; update it")
	err = component.apply(networkSnapshot(t, devicePlan(3, network.EgressNATDirect)))
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "update it"))
	assert.Len(t, core.applied, 1)

	// An emptied plan (the device's paths are gone) reaches the core.
	core.err = nil
	empty := &networkv1.NetworkPlan{DeviceRef: "proxy-1"}
	network.Stamp(empty, network.Generation{Generation: 3, Hash: plan.GetHash()})
	require.NoError(t, component.apply(networkSnapshot(t, empty)))
	require.Len(t, core.applied, 2)
	assert.Empty(t, core.applied[1].GetPaths())
}
