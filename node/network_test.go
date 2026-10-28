package node

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/anxserver"
	agentapi "github.com/AnixOps/anix-agent/v5/api/agent"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	"github.com/AnixOps/anix-agent/v5/networkroute"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
	"github.com/AnixOps/anix-control/sdk/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
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

// withoutRouting makes the components of the test have no policy routing
// (and no anx-server).
func withoutRouting(t *testing.T) {
	previous := networkRouting
	networkRouting = func() *networkroute.Manager { return nil }
	t.Cleanup(func() { networkRouting = previous })
	withoutServers(t)
}

// withoutServers makes the components of the test have no anx-server.
func withoutServers(t *testing.T) {
	previous := networkServers
	networkServers = func() *anxserver.Manager { return nil }
	t.Cleanup(func() { networkServers = previous })
}

func TestNetworkComponentNeedsACoreThatRunsTheModel(t *testing.T) {
	withoutRouting(t)
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
	withoutRouting(t)
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

// With policy routing the Agent runs dedicated_ip egresses: the routes go
// in before the core gets the plan, and a plan without them removes them.
func TestNetworkComponentRoutesAddressSources(t *testing.T) {
	var calls []string
	previous := networkRouting
	networkRouting = func() *networkroute.Manager {
		return &networkroute.Manager{IP: "ip", Run: func(name string, args ...string) ([]byte, error) {
			if args[0] == "-j" {
				return []byte("[]"), nil
			}
			calls = append(calls, strings.Join(args, " "))
			return nil, nil
		}}
	}
	t.Cleanup(func() { networkRouting = previous })
	withoutServers(t)

	core := &fakeNetworkCore{kinds: networkKinds()}
	component := newNetworkComponent(1, core)
	require.NotNil(t, component)
	assert.Len(t, component.caps.GetKinds(), 3, "dedicated_ip is the Agent's")

	plan := devicePlan(1, network.EgressDedicatedIP)
	plan.Lines[0].GatewayV4 = "198.51.100.1"
	plan.Egresses[0].Source = "198.51.100.10"
	network.Stamp(plan, network.Generation{})
	require.NoError(t, component.apply(networkSnapshot(t, plan)))
	require.Len(t, core.applied, 1)
	assert.Equal(t, []string{
		"-4 route replace default via 198.51.100.1 dev eth0 src 198.51.100.10 table 20000",
		"-4 rule add from 198.51.100.10/32 table 20000 priority 20000",
	}, calls)

	calls = nil
	empty := &networkv1.NetworkPlan{DeviceRef: "proxy-1"}
	network.Stamp(empty, network.Generation{Generation: 1, Hash: plan.GetHash()})
	require.NoError(t, component.apply(networkSnapshot(t, empty)))
	assert.Empty(t, calls, "no rule of the range was there to remove")
	require.Len(t, core.applied, 2)
}

// With anx-server the Agent accepts anx_line transports: their server
// runs beside the core's plan, and a dialing end is refused without
// anx-node as the core.
func TestNetworkComponentAcceptsAnxLine(t *testing.T) {
	withoutRouting(t)
	launched := make(chan []string, 1)
	previous := networkServers
	networkServers = func() *anxserver.Manager {
		return &anxserver.Manager{
			Binary: "anx-server", Dir: t.TempDir(),
			Run: func(_ string, args ...string) ([]byte, error) {
				require.NoError(t, os.WriteFile(args[1], []byte("secret"), 0o600))
				return []byte("public: SERVER-PUBLIC\n"), nil
			},
			Launch: func(_ string, args []string) (anxserver.Process, error) {
				select {
				case launched <- args:
				default:
				}
				return nil, errors.New("not here")
			},
		}
	}
	t.Cleanup(func() { networkServers = previous })

	core := &fakeNetworkCore{kinds: append(networkKinds(), &networkv1.KindSupport{
		Component: networkv1.Component_COMPONENT_EGRESS, Kind: network.EgressHop, Versions: []uint32{1}})}
	component := newNetworkComponent(1, core)
	require.NotNil(t, component)
	t.Cleanup(component.close)
	assert.Contains(t, component.caps.GetKinds(), &networkv1.KindSupport{
		Component: networkv1.Component_COMPONENT_TRANSPORT, Kind: network.TransportAnxLine, Versions: []uint32{1}, Executor: "agent",
	})

	plan := &networkv1.NetworkPlan{
		DeviceRef: "proxy-1",
		Lines:     []*networkv1.Line{{Id: "ln-1", Interface: "eth0", Families: []networkv1.Family{networkv1.Family_FAMILY_V4}}},
		Ingresses: []*networkv1.Ingress{{Id: "in-hop", LineId: "ln-1", Kind: network.IngressDirect, KindVersion: 1,
			Audience: networkv1.Audience_AUDIENCE_HOP, Family: networkv1.Family_FAMILY_V4,
			Listen: &networkv1.Endpoint{Address: "198.51.100.10", Port: 443}}},
		Egresses: []*networkv1.Egress{{Id: "eg-1", LineId: "ln-1", Kind: network.EgressNATDirect, KindVersion: 1,
			Audience: networkv1.Audience_AUDIENCE_INTERNET, Family: networkv1.Family_FAMILY_V4, Source: network.SourceAuto}},
		Transports: []*networkv1.Transport{{Id: "tr-1", Kind: network.TransportAnxLine, KindVersion: 1,
			Role: networkv1.TransportRole_TRANSPORT_ROLE_ACCEPT, ToIngressId: "in-hop", PeerDeviceRef: "proxy-2",
			Settings: &networkv1.Transport_AnxLine{AnxLine: &networkv1.AnxLineSettings{
				LinkId: "tr-1", LinkKey: strings.Repeat("5f", 32), TcpAddr: "198.51.100.10:443"}}}},
		Forwarding: []*networkv1.Forwarding{{FromTransportId: "tr-1", Next: &networkv1.Forwarding_EgressId{EgressId: "eg-1"}}},
	}
	network.Stamp(plan, network.Generation{})
	require.NoError(t, component.apply(networkSnapshot(t, plan)))
	require.Len(t, core.applied, 1)
	select {
	case args := <-launched:
		assert.Contains(t, strings.Join(args, " "), "--bare-listen 198.51.100.10:443")
	case <-time.After(2 * time.Second):
		t.Fatal("anx-server was not started")
	}
	require.Eventually(t, func() bool {
		status := component.servers.Status()
		return len(status) == 1 && status[0].GetId() == "tr-1" && strings.Contains(status[0].GetDetail(), "not here")
	}, 2*time.Second, 10*time.Millisecond)
	public, err := component.servers.PublicKey()
	require.NoError(t, err)
	assert.Equal(t, "SERVER-PUBLIC", public)

	dial := proto.Clone(plan).(*networkv1.NetworkPlan)
	dial.Transports[0].Role = networkv1.TransportRole_TRANSPORT_ROLE_DIAL
	dial.Egresses = append(dial.Egresses, &networkv1.Egress{Id: "eg-hop", LineId: "ln-1", Kind: network.EgressHop, KindVersion: 1,
		Audience: networkv1.Audience_AUDIENCE_HOP, Family: networkv1.Family_FAMILY_V4, Source: network.SourceAuto})
	dial.Transports[0].ToIngressId, dial.Transports[0].FromEgressId, dial.Forwarding = "", "eg-hop", nil
	dial.Transports[0].GetAnxLine().ServerPublic = "SERVER-PUBLIC"
	network.Stamp(dial, network.Generation{Generation: 1, Hash: plan.GetHash()})
	err = component.apply(networkSnapshot(t, dial))
	require.ErrorIs(t, err, agentapi.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "needs anx-node")
}

// A core that dials anx_line (anx-node) and an Agent that accepts it list
// the kind once, with both executors.
func TestNetworkComponentListsAnxLineOnce(t *testing.T) {
	withoutRouting(t)
	previous := networkServers
	networkServers = func() *anxserver.Manager { return &anxserver.Manager{Binary: "anx-server", Dir: t.TempDir()} }
	t.Cleanup(func() { networkServers = previous })
	core := &fakeNetworkCore{kinds: append(networkKinds(), &networkv1.KindSupport{
		Component: networkv1.Component_COMPONENT_TRANSPORT, Kind: network.TransportAnxLine, Versions: []uint32{1}, Executor: "anixcore"})}
	component := newNetworkComponent(1, core)
	require.NotNil(t, component)
	t.Cleanup(component.close)
	capability, err := component.HelloCapability()
	require.NoError(t, err)
	caps, _, err := network.DeviceCapabilitiesFromHello([]*agentv1pb.Capability{capability}, "proxy-1")
	require.NoError(t, err)
	require.Len(t, caps.GetKinds(), 3)
	assert.Equal(t, "anixcore,agent", caps.GetKinds()[2].GetExecutor())
	assert.Equal(t, "anixcore", core.kinds[2].GetExecutor(), "the core's own list is not changed")
}
