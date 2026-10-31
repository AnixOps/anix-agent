package anixcore

import (
	"context"
	"strings"
	"sync"
	"testing"

	anxmgmtpb "github.com/AnixOps/anix-agent/v5/api/anxmgmt/v1"
	"github.com/AnixOps/anix-agent/v5/conf"
	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
	"github.com/AnixOps/anix-control/sdk/network"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

// fakeLine is anx-node's ANX-Line management API.
type fakeLine struct {
	anxmgmtpb.ManagementClient

	mu    sync.Mutex
	addr  string
	links map[string]*anxmgmtpb.Link
	calls []string
}

func (f *fakeLine) AddLinks(_ context.Context, in *anxmgmtpb.AddLinksRequest, _ ...grpc.CallOption) (*anxmgmtpb.AddLinksResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, link := range in.GetLinks() {
		f.calls = append(f.calls, "add "+link.GetLinkId())
		f.links[link.GetLinkId()] = link
	}
	return &anxmgmtpb.AddLinksResponse{Added: uint32(len(in.GetLinks()))}, nil
}

func (f *fakeLine) RemoveLinks(_ context.Context, in *anxmgmtpb.RemoveLinksRequest, _ ...grpc.CallOption) (*anxmgmtpb.RemoveLinksResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range in.GetLinkIds() {
		f.calls = append(f.calls, "remove "+id)
		delete(f.links, id)
	}
	return &anxmgmtpb.RemoveLinksResponse{Removed: uint32(len(in.GetLinkIds()))}, nil
}

func (f *fakeLine) LinkStats(context.Context, *anxmgmtpb.LinkStatsRequest, ...grpc.CallOption) (*anxmgmtpb.LinkStatsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	answer := &anxmgmtpb.LinkStatsResponse{}
	for id := range f.links {
		answer.Links = append(answer.Links, &anxmgmtpb.LinkStat{LinkId: id, Connected: true, Carrier: "c2", RttMs: 31})
	}
	return answer, nil
}

func (f *fakeLine) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	calls := f.calls
	f.calls = nil
	return calls
}

func lineCore(t *testing.T, line *fakeLine) (*fakeAPI, *Core) {
	t.Helper()
	previous := connectLine
	connectLine = func(addr string, _ credentials.TransportCredentials) (anxmgmtpb.ManagementClient, func() error, error) {
		line.addr = addr
		return line, func() error { return nil }, nil
	}
	t.Cleanup(func() { connectLine = previous })
	api, server := newFakeAPI(t)
	core, err := New(&conf.CoreConfig{Type: coreType, AnixcoreConfig: &conf.AnixcoreConfig{
		ApiAddress: strings.TrimPrefix(server.URL, "http://"), ApiToken: "secret", StartTimeoutSeconds: 5,
		AnxLine: true, AnxLineApiAddress: "127.0.0.1:7001",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.Close() })
	return api, core.(*Core)
}

func dialPlan(serverPublic string) *networkv1.NetworkPlan {
	plan := networkPlan(443)
	plan.Egresses = append(plan.Egresses, &networkv1.Egress{Id: "eg-hop", LineId: "ln-1", Kind: network.EgressHop, KindVersion: 1,
		Audience: networkv1.Audience_AUDIENCE_HOP, Family: networkv1.Family_FAMILY_V4, Source: "auto"})
	plan.Transports = []*networkv1.Transport{{Id: "tr-jp", Kind: network.TransportAnxLine, KindVersion: 1,
		Role: networkv1.TransportRole_TRANSPORT_ROLE_DIAL, FromEgressId: "eg-hop", PeerDeviceRef: "proxy-2",
		Settings: &networkv1.Transport_AnxLine{AnxLine: &networkv1.AnxLineSettings{
			LinkId: "tr-jp", LinkKey: strings.Repeat("5f", 32), ServerPublic: serverPublic,
			QuicAddr: "203.0.113.20:8443", TcpAddr: "203.0.113.20:443", CarrierOrder: []string{"c2", "c1"}}}}}
	plan.Paths[0].Next = &networkv1.Path_TransportId{TransportId: "tr-jp"}
	plan.Paths[0].FinalEgressId = "eg-jp"
	return plan
}

// anx-node gets the plan's dialing transports as links before the plan,
// a changed link is replaced and a gone one removed, the links are
// reported as transports, and a restarted anx-node gets them again first.
func TestDialingAnxLineEndsAreAnxNodeLinks(t *testing.T) {
	line := &fakeLine{links: map[string]*anxmgmtpb.Link{}}
	api, core := lineCore(t, line)
	if line.addr != "127.0.0.1:7001" {
		t.Fatalf("connected to %q", line.addr)
	}
	caps := &networkv1.DeviceCapabilities{Kinds: core.NetworkKinds()}
	if missing := network.Unsupported(dialPlan("PUB-1"), caps); len(missing) > 0 {
		t.Fatalf("anixcore with anx-node does not run %v", missing)
	}

	status, err := core.ApplyNetwork(dialPlan("PUB-1"))
	if err != nil {
		t.Fatal(err)
	}
	if calls := line.take(); len(calls) != 1 || calls[0] != "add tr-jp" {
		t.Fatalf("calls = %v", calls)
	}
	link := line.links["tr-jp"]
	if link.GetServerPublic() != "PUB-1" || len(link.GetLinkKey()) != 32 || link.GetQuicAddr() != "203.0.113.20:8443" ||
		strings.Join(link.GetPolicy().GetOrder(), ",") != "c2,c1" || link.GetUdpLanes() != 1 {
		t.Fatalf("link = %v", link)
	}
	if api.calls[len(api.calls)-1] != "PUT /v1/network" {
		t.Fatalf("api calls = %v", api.calls)
	}
	var transport *networkv1.ComponentStatus
	for _, component := range status.GetComponents() {
		if component.GetComponent() == networkv1.Component_COMPONENT_TRANSPORT {
			transport = component
		}
	}
	if transport.GetId() != "tr-jp" || transport.GetState() != networkv1.ComponentState_COMPONENT_STATE_APPLIED ||
		transport.GetCarrier() != "c2" || transport.GetRttMs() != 31 {
		t.Fatalf("transport status = %v", transport)
	}

	// The same plan again changes nothing; a new server key replaces the link.
	if _, err := core.ApplyNetwork(dialPlan("PUB-1")); err != nil {
		t.Fatal(err)
	}
	if calls := line.take(); len(calls) != 0 {
		t.Fatalf("calls = %v", calls)
	}
	if _, err := core.ApplyNetwork(dialPlan("PUB-2")); err != nil {
		t.Fatal(err)
	}
	if calls := line.take(); strings.Join(calls, ";") != "remove tr-jp;add tr-jp" {
		t.Fatalf("calls = %v", calls)
	}

	// A restarted anx-node holds no links: they go in before the plan.
	line.links = map[string]*anxmgmtpb.Link{}
	if err := core.replay(); err != nil {
		t.Fatal(err)
	}
	if calls := line.take(); strings.Join(calls, ";") != "add tr-jp" || line.links["tr-jp"].GetServerPublic() != "PUB-2" {
		t.Fatalf("replay calls = %v", calls)
	}

	if _, err := core.ApplyNetwork(networkPlan(443)); err != nil {
		t.Fatal(err)
	}
	if calls := line.take(); strings.Join(calls, ";") != "remove tr-jp" {
		t.Fatalf("calls = %v", calls)
	}
}

func TestDialingAnxLineNeedsAnxNode(t *testing.T) {
	_, server := newFakeAPI(t)
	core := externalCore(t, server)
	defer core.Close()
	for _, kind := range core.NetworkKinds() {
		if kind.GetKind() == network.TransportAnxLine {
			t.Fatal("anixcore lists anx_line")
		}
	}
	if _, err := core.ApplyNetwork(dialPlan("PUB")); err == nil || !strings.Contains(err.Error(), "needs anx-node") {
		t.Fatalf("ApplyNetwork = %v", err)
	}

	broken, err := New(&conf.CoreConfig{Type: coreType, AnixcoreConfig: &conf.AnixcoreConfig{
		ApiAddress: "127.0.0.1:1", ApiToken: "secret", AnxLine: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := broken.Start(); err == nil || !strings.Contains(err.Error(), "AnxLineApiAddress") {
		t.Fatalf("Start = %v", err)
	}
}

// A reverse link has no carrier address and needs anx-node's rendezvous
// listener; two listeners cannot be had. An anx-node the core did not
// start keeps its own listener.
func TestReverseDialLinks(t *testing.T) {
	plan := dialPlan("PUB-1")
	settings := plan.Transports[0].GetAnxLine()
	settings.QuicAddr, settings.TcpAddr, settings.CarrierOrder = "", "", []string{"c1"}
	settings.Reverse, settings.ReverseListen = true, "0.0.0.0:24444"
	links, listen, err := dialLinks(plan)
	if err != nil {
		t.Fatal(err)
	}
	if listen != (reverseListener{Listen: "0.0.0.0:24444"}) || !links["tr-jp"].GetReverse() || links["tr-jp"].GetTcpAddr() != "" {
		t.Fatalf("listen = %+v, links = %v", listen, links)
	}

	// C2 / C3 dial-backs follow the carrier order (anx ANX-LINE-REVERSE §6.3).
	c2 := proto.Clone(plan).(*networkv1.NetworkPlan)
	c2.Transports[0].GetAnxLine().CarrierOrder = []string{"c2", "c3", "c1"}
	if _, listen, err = dialLinks(c2); err != nil || listen != (reverseListener{Listen: "0.0.0.0:24444", QUIC: true, FakeTCP: true}) {
		t.Fatalf("listen = %+v, err = %v", listen, err)
	}

	two := dialPlan("PUB-1")
	other := proto.Clone(plan.Transports[0]).(*networkv1.Transport)
	other.Id = "tr-kr"
	other.GetAnxLine().ReverseListen = "0.0.0.0:24445"
	two.Transports = append(plan.Transports, other)
	if _, _, err := dialLinks(two); err == nil || !strings.Contains(err.Error(), "one reverse listener") {
		t.Fatalf("err = %v", err)
	}

	line := &fakeLine{links: map[string]*anxmgmtpb.Link{}}
	_, core := lineCore(t, line)
	if _, err := core.ApplyNetwork(plan); err != nil {
		t.Fatal(err)
	}
	if !line.links["tr-jp"].GetReverse() || core.reverse.Listen != "" {
		t.Fatalf("links = %v, reverse listen = %q", line.links, core.reverse.Listen)
	}
}

// A link whose from egress moves to another uplink is dialed again; the
// same plan again leaves it be.
func TestMovedLinkIsDialedAgain(t *testing.T) {
	line := &fakeLine{links: map[string]*anxmgmtpb.Link{}}
	_, core := lineCore(t, line)
	moved := func(egress string) *networkv1.NetworkPlan {
		plan := dialPlan("PUB-1")
		plan.Egresses = append(plan.Egresses, &networkv1.Egress{Id: "eg-hop2", LineId: "ln-1", Kind: network.EgressHop, KindVersion: 1,
			Audience: networkv1.Audience_AUDIENCE_HOP, Family: networkv1.Family_FAMILY_V4, Source: "auto"})
		plan.Transports[0].FromEgressId = egress
		return plan
	}
	if _, err := core.ApplyNetwork(moved("eg-hop")); err != nil {
		t.Fatal(err)
	}
	line.take()
	if _, err := core.ApplyNetwork(moved("eg-hop")); err != nil {
		t.Fatal(err)
	}
	if calls := line.take(); len(calls) != 0 {
		t.Fatalf("calls = %v", calls)
	}
	if _, err := core.ApplyNetwork(moved("eg-hop2")); err != nil {
		t.Fatal(err)
	}
	if calls := line.take(); strings.Join(calls, ";") != "remove tr-jp;add tr-jp" {
		t.Fatalf("calls = %v", calls)
	}
}
