package anxserver

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/anxline"
	anxmgmtpb "github.com/AnixOps/anix-agent/v5/api/anxmgmt/v1"
	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
	"github.com/AnixOps/anix-control/sdk/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func init() {
	readyPoll = 5 * time.Millisecond
	restartDelays = []time.Duration{10 * time.Millisecond}
}

const linkKey = "5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f"

func acceptPlan() *networkv1.NetworkPlan {
	return &networkv1.NetworkPlan{
		DeviceRef: "proxy-2",
		Egresses: []*networkv1.Egress{
			{Id: "eg-jp", Kind: network.EgressDedicatedIP, Source: "203.0.113.20"},
			{Id: "eg-auto", Kind: network.EgressNATDirect, Source: network.SourceAuto},
		},
		Transports: []*networkv1.Transport{
			{Id: "tr-b", Kind: network.TransportAnxLine, Role: networkv1.TransportRole_TRANSPORT_ROLE_ACCEPT,
				Settings: &networkv1.Transport_AnxLine{AnxLine: &networkv1.AnxLineSettings{
					LinkId: "tr-b", LinkKey: linkKey, TcpAddr: "203.0.113.20:443"}}},
			{Id: "tr-a", Kind: network.TransportAnxLine, Role: networkv1.TransportRole_TRANSPORT_ROLE_ACCEPT,
				Settings: &networkv1.Transport_AnxLine{AnxLine: &networkv1.AnxLineSettings{
					LinkKey: strings.Repeat("ab", 32), TcpAddr: "203.0.113.20:443",
					QuicAddr: "203.0.113.20:8443", FaketcpAddr: "203.0.113.20:8444"}}},
			{Id: "tr-w", Kind: "wireguard", Role: networkv1.TransportRole_TRANSPORT_ROLE_DIAL},
		},
		Forwarding: []*networkv1.Forwarding{
			{FromTransportId: "tr-a", Next: &networkv1.Forwarding_EgressId{EgressId: "eg-jp"}},
			{FromTransportId: "tr-b", Next: &networkv1.Forwarding_EgressId{EgressId: "eg-auto"}},
		},
	}
}

func TestAccepts(t *testing.T) {
	accepts, err := Accepts(acceptPlan())
	require.NoError(t, err)
	require.Len(t, accepts, 2)
	assert.Equal(t, "tr-a", accepts[0].Transport)
	assert.Equal(t, "tr-a", accepts[0].LinkID, "the transport id when the link id is empty")
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("203.0.113.20")}, accepts[0].Sources)
	assert.Equal(t, "203.0.113.20:8444", accepts[0].FakeTCP)
	assert.Empty(t, accepts[1].Sources, "an auto source binds nothing")

	assert.Equal(t, []string{"--sni", "anx-line", "--bare-listen", "203.0.113.20:443",
		"--quic-listen", "203.0.113.20:8443", "--quic-sockbuf", "8388608", "--quic-dgram-buf", "1048576",
		"--faketcp-listen", "203.0.113.20:8444",
		"--egress-source", "203.0.113.20"}, accepts[0].listener().args())

	l2 := Accept{TCP: "203.0.113.20:443", L2: true, ServerName: "www.example.com"}
	assert.Equal(t, []string{"--sni", "www.example.com", "--listen", "203.0.113.20:443", "--dest", "www.example.com:443"}, l2.listener().args())

	dial := acceptPlan()
	dial.Transports[0].Role = networkv1.TransportRole_TRANSPORT_ROLE_DIAL
	dialed, err := Accepts(dial)
	require.NoError(t, err)
	assert.Len(t, dialed, 1, "the dialing end is not anx-server's")

	onward := acceptPlan()
	onward.Forwarding[0].Next = &networkv1.Forwarding_TransportId{TransportId: "tr-w"}
	_, err = Accepts(onward)
	assert.ErrorContains(t, err, `forwarded into transport "tr-w"`)

	bad := acceptPlan()
	bad.Transports[0].GetAnxLine().LinkKey = "00"
	_, err = Accepts(bad)
	assert.ErrorContains(t, err, "32 bytes")
}

// relayPlan forwards tr-a into the dialing transport tr-n: this device is
// a relay hop.
func relayPlan() *networkv1.NetworkPlan {
	plan := acceptPlan()
	plan.Transports = append(plan.Transports, &networkv1.Transport{Id: "tr-n", Kind: network.TransportAnxLine,
		Role: networkv1.TransportRole_TRANSPORT_ROLE_DIAL, Settings: &networkv1.Transport_AnxLine{AnxLine: &networkv1.AnxLineSettings{
			LinkId: "tr-n", LinkKey: strings.Repeat("6a", 32), ServerPublic: "PUB-N", TcpAddr: "198.51.100.30:443",
			Egress: "l2", ServerName: "www.example.org"}}})
	plan.Forwarding[0].Next = &networkv1.Forwarding_TransportId{TransportId: "tr-n"}
	return plan
}

func TestAcceptsRelay(t *testing.T) {
	plan := relayPlan()
	accepts, err := Accepts(plan)
	require.NoError(t, err)
	require.NotNil(t, accepts[0].Next)
	assert.Equal(t, "tr-n", accepts[0].Next.GetLinkId())
	assert.Equal(t, "l2", accepts[0].Next.GetEgress())
	assert.Equal(t, uint32(1), accepts[0].Next.GetUdpLanes())
	assert.Empty(t, accepts[0].Sources, "relayed traffic leaves by the link")
	assert.Nil(t, accepts[1].Next)
	assert.Equal(t, map[string]bool{"tr-n": true}, Relayed(plan))

	plan.Paths = []*networkv1.Path{{Id: "pa", Next: &networkv1.Path_TransportId{TransportId: "tr-n"}}}
	assert.Empty(t, Relayed(plan), "a path into it is the core's too")
}

func TestGroup(t *testing.T) {
	accepts, err := Accepts(acceptPlan())
	require.NoError(t, err)
	_, err = group(accepts)
	assert.ErrorContains(t, err, "tcp 203.0.113.20:443", "two configurations on one TCP address")

	accepts[1].Sources = accepts[0].Sources
	accepts[1].QUIC, accepts[1].FakeTCP = accepts[0].QUIC, accepts[0].FakeTCP
	groups, err := group(accepts)
	require.NoError(t, err)
	assert.Len(t, groups, 1, "one process for both links")

	accepts[1].LinkID = accepts[0].LinkID
	_, err = group(accepts)
	assert.ErrorContains(t, err, "same link id")

	_, err = group([]Accept{{Transport: "t", L2: true, TCP: "1.2.3.4:443"}})
	assert.ErrorContains(t, err, "server name")
	_, err = group([]Accept{{Transport: "t"}})
	assert.ErrorContains(t, err, "no listen address")
}

// fakeProcess is a started anx-server.
type fakeProcess struct {
	args []string
	done chan struct{}
	once sync.Once
}

func (p *fakeProcess) Done() <-chan struct{} { return p.done }
func (p *fakeProcess) Err() error            { return errors.New("exit status 1") }
func (p *fakeProcess) Stop()                 { p.once.Do(func() { close(p.done) }) }

// fakeHost records the processes and the management calls.
type fakeHost struct {
	anxmgmtpb.ManagementClient

	mu        sync.Mutex
	processes []*fakeProcess
	users     map[string]string // user id -> link id
	relays    map[string]bool   // relay links held
	routes    map[string]string // admitted link -> relay link
	dials     []string          // reverse dials as id=addr
	next      int
	// unready fails the next AddUsers calls, as a process still starting.
	unready int
}

func (h *fakeHost) launch(binary string, args []string) (Process, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	process := &fakeProcess{args: append([]string{binary}, args...), done: make(chan struct{})}
	h.processes = append(h.processes, process)
	h.users, h.relays, h.routes, h.dials = map[string]string{}, map[string]bool{}, map[string]string{}, nil
	return process, nil
}

func (h *fakeHost) connect(string) (anxmgmtpb.ManagementClient, func() error, error) {
	return h, func() error { return nil }, nil
}

func (h *fakeHost) AddUsers(_ context.Context, in *anxmgmtpb.AddUsersRequest, _ ...grpc.CallOption) (*anxmgmtpb.AddUsersResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.unready > 0 {
		h.unready--
		return nil, errors.New("connection refused")
	}
	answer := &anxmgmtpb.AddUsersResponse{}
	for _, user := range in.GetUsers() {
		h.next++
		id := []byte{byte(h.next)}
		h.users[string(id)] = user.GetExternalId()
		answer.UserIds = append(answer.UserIds, id)
	}
	return answer, nil
}

// LinkStats answers the relay links as connected over QUIC, measuring 23 ms
// and one packet in a hundred lost.
func (h *fakeHost) LinkStats(context.Context, *anxmgmtpb.LinkStatsRequest, ...grpc.CallOption) (*anxmgmtpb.LinkStatsResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var links []*anxmgmtpb.LinkStat
	for id := range h.relays {
		links = append(links, &anxmgmtpb.LinkStat{LinkId: id, Connected: true, Carrier: "c2", RttMs: 23, SentPackets: 100, LostPackets: 1})
	}
	return &anxmgmtpb.LinkStatsResponse{Links: links}, nil
}

func (h *fakeHost) RemoveUsers(_ context.Context, in *anxmgmtpb.RemoveUsersRequest, _ ...grpc.CallOption) (*anxmgmtpb.RemoveUsersResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, id := range in.GetUserIds() {
		delete(h.users, string(id))
	}
	return &anxmgmtpb.RemoveUsersResponse{Removed: uint32(len(in.GetUserIds()))}, nil
}

func (h *fakeHost) AddLinks(_ context.Context, in *anxmgmtpb.AddLinksRequest, _ ...grpc.CallOption) (*anxmgmtpb.AddLinksResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, link := range in.GetLinks() {
		h.relays[link.GetLinkId()] = true
	}
	return &anxmgmtpb.AddLinksResponse{Added: uint32(len(in.GetLinks()))}, nil
}

func (h *fakeHost) RemoveLinks(_ context.Context, in *anxmgmtpb.RemoveLinksRequest, _ ...grpc.CallOption) (*anxmgmtpb.RemoveLinksResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, id := range in.GetLinkIds() {
		for _, link := range h.routes {
			if link == id {
				return nil, errors.New("the link has routes")
			}
		}
		delete(h.relays, id)
	}
	return &anxmgmtpb.RemoveLinksResponse{Removed: uint32(len(in.GetLinkIds()))}, nil
}

func (h *fakeHost) SetLinkRoutes(_ context.Context, in *anxmgmtpb.SetLinkRoutesRequest, _ ...grpc.CallOption) (*anxmgmtpb.SetLinkRoutesResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	routes := map[string]string{}
	for _, route := range in.GetRoutes() {
		if !h.relays[route.GetLinkId()] {
			return nil, errors.New("no such link")
		}
		routes[h.users[string(route.GetUserId())]] = route.GetLinkId()
	}
	h.routes = routes
	return &anxmgmtpb.SetLinkRoutesResponse{}, nil
}

func (h *fakeHost) SetReverseDials(_ context.Context, in *anxmgmtpb.SetReverseDialsRequest, _ ...grpc.CallOption) (*anxmgmtpb.SetReverseDialsResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dials = nil
	for _, dial := range in.GetDials() {
		entry := dial.GetDialId() + "=" + dial.GetAddr()
		if dial.GetQuic() {
			entry += "+quic"
		}
		if dial.GetFaketcp() {
			entry += "+faketcp"
		}
		h.dials = append(h.dials, entry)
	}
	return &anxmgmtpb.SetReverseDialsResponse{Dials: uint32(len(in.GetDials()))}, nil
}

func (h *fakeHost) reverseDials() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.dials...)
}

// relayed answers the routes as admitted link -> relay link, and the relay
// links held.
func (h *fakeHost) relayed() (map[string]string, []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var links []string
	for id := range h.relays {
		links = append(links, id)
	}
	sort.Strings(links)
	return maps.Clone(h.routes), links
}

func (h *fakeHost) links() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var links []string
	for _, link := range h.users {
		links = append(links, link)
	}
	return links
}

func (h *fakeHost) started() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.processes)
}

func (h *fakeHost) last() *fakeProcess {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.processes[len(h.processes)-1]
}

func newManager(t *testing.T, host *fakeHost) (*Manager, *[]string) {
	keygens := 0
	var rst []string
	m := &Manager{
		Binary: "/usr/bin/anx-server", Dir: filepath.Join(t.TempDir(), "anx-server"),
		Launch: host.launch, Connect: host.connect,
		Run: func(name string, args ...string) ([]byte, error) {
			keygens++
			require.Equal(t, []string{"keygen"}, args[:1])
			require.NoError(t, os.WriteFile(args[1], []byte("secret"), 0o600))
			return []byte("private key written\npublic: PUBLIC-" + string(rune('0'+keygens)) + "\n"), nil
		},
		RST: func(links []anxline.Link) error {
			for _, link := range links {
				rst = append(rst, link.ID+" "+link.FakeTCP.Local)
			}
			if len(links) == 0 {
				rst = append(rst, "none")
			}
			return nil
		},
	}
	t.Cleanup(m.Close)
	return m, &rst
}

func TestManagerPublicKeyIsKept(t *testing.T) {
	m, _ := newManager(t, &fakeHost{})
	public, err := m.PublicKey()
	require.NoError(t, err)
	assert.Equal(t, "PUBLIC-1", public)

	again := &Manager{Binary: m.Binary, Dir: m.Dir, Run: func(string, ...string) ([]byte, error) {
		return nil, errors.New("keygen must not run again")
	}}
	public, err = again.PublicKey()
	require.NoError(t, err)
	assert.Equal(t, "PUBLIC-1", public, "read back from the directory")
}

func applied(t *testing.T, m *Manager, ids ...string) {
	t.Helper()
	require.Eventually(t, func() bool {
		var got []string
		for _, component := range m.Status() {
			if component.GetState() == networkv1.ComponentState_COMPONENT_STATE_APPLIED {
				got = append(got, component.GetId())
			}
		}
		return assert.ObjectsAreEqual(ids, got)
	}, 2*time.Second, 5*time.Millisecond)
}

// One process serves the links that share their listener; a changed link
// set is admitted on the running process, a dead process is started again
// with its links, and an empty plan stops it.
func TestManagerRunsTheAcceptingEnds(t *testing.T) {
	host := &fakeHost{unready: 2}
	m, rst := newManager(t, host)
	raised := 0
	m.Buffers = func() error { raised++; return nil }
	accepts, err := Accepts(acceptPlan())
	require.NoError(t, err)
	accepts[1].Sources = accepts[0].Sources
	accepts[1].QUIC, accepts[1].FakeTCP = accepts[0].QUIC, accepts[0].FakeTCP

	require.NoError(t, m.Apply(accepts))
	applied(t, m, "tr-a", "tr-b")
	require.Equal(t, 1, host.started())
	args := strings.Join(host.last().args, " ")
	assert.Contains(t, args, "/usr/bin/anx-server run --key "+filepath.Join(m.Dir, "server.key")+" --mgmt 127.0.0.1:")
	assert.Contains(t, args, " --listen 127.0.0.1:", "the unused jacket listener stays on loopback")
	assert.Contains(t, args, "--bare-listen 203.0.113.20:443 --quic-listen 203.0.113.20:8443 --quic-sockbuf 8388608 --quic-dgram-buf 1048576 --faketcp-listen 203.0.113.20:8444 --egress-source 203.0.113.20")
	assert.ElementsMatch(t, []string{"tr-a", "tr-b"}, host.links())
	assert.Equal(t, []string{"tr-a 203.0.113.20", "tr-b 203.0.113.20"}, *rst)
	assert.Equal(t, 1, raised, "a QUIC listener gets the larger socket buffers")

	// tr-b leaves: removed on the running process.
	require.NoError(t, m.Apply(accepts[:1]))
	applied(t, m, "tr-a")
	require.Eventually(t, func() bool { return assert.ObjectsAreEqual([]string{"tr-a"}, host.links()) }, time.Second, 5*time.Millisecond)
	assert.Equal(t, 1, host.started())

	// The process dies: a new one gets the link again.
	host.last().Stop()
	require.Eventually(t, func() bool { return host.started() == 2 && len(host.links()) == 1 }, 2*time.Second, 5*time.Millisecond)
	applied(t, m, "tr-a")

	*rst = nil
	require.NoError(t, m.Apply(nil))
	assert.Empty(t, m.Status())
	assert.Equal(t, []string{"none"}, *rst, "the RST rules are removed")
	select {
	case <-host.last().Done():
	default:
		t.Fatal("the process was not stopped")
	}
}

// A relay hop's process holds the link it relays into and routes the
// accepted link there; a restarted process gets both again, and a plan
// without the relay clears the route and removes the link.
func TestManagerRelays(t *testing.T) {
	host := &fakeHost{}
	m, _ := newManager(t, host)
	accepts, err := Accepts(relayPlan())
	require.NoError(t, err)
	accepts = accepts[:1]

	require.NoError(t, m.Apply(accepts))
	applied(t, m, "tr-a", "tr-n")
	want := func(routes map[string]string, links []string) {
		t.Helper()
		require.Eventually(t, func() bool {
			gotRoutes, gotLinks := host.relayed()
			return assert.ObjectsAreEqual(routes, gotRoutes) && assert.ObjectsAreEqual(links, gotLinks)
		}, 2*time.Second, 5*time.Millisecond)
	}
	want(map[string]string{"tr-a": "tr-n"}, []string{"tr-n"})
	require.Eventually(t, func() bool {
		for _, component := range m.Status() {
			if component.GetId() == "tr-n" {
				return component.GetRttMs() == 23 && component.GetCarrier() == "c2" && component.GetLossPpm() == 10000
			}
		}
		return false
	}, 2*time.Second, 5*time.Millisecond, "the relay link reports what the process measured")

	host.last().Stop()
	require.Eventually(t, func() bool { return host.started() == 2 }, 2*time.Second, 5*time.Millisecond)
	want(map[string]string{"tr-a": "tr-n"}, []string{"tr-n"})

	plain, err := Accepts(acceptPlan())
	require.NoError(t, err)
	require.NoError(t, m.Apply(plain[:1]))
	applied(t, m, "tr-a")
	want(map[string]string{}, nil)
}

func TestManagerReportsADownServer(t *testing.T) {
	host := &fakeHost{unready: 1 << 30}
	m, _ := newManager(t, host)
	previous := readyTimeout
	readyTimeout = 20 * time.Millisecond
	t.Cleanup(func() { readyTimeout = previous })

	require.NoError(t, m.Apply([]Accept{{Transport: "tr-1", LinkID: "tr-1", LinkKey: make([]byte, 32), QUIC: "192.0.2.1:8443"}}))
	require.Eventually(t, func() bool {
		status := m.Status()
		return len(status) == 1 && strings.Contains(status[0].GetDetail(), "connection refused")
	}, 2*time.Second, 5*time.Millisecond)
	assert.Equal(t, networkv1.ComponentState_COMPONENT_STATE_DOWN, m.Status()[0].GetState())
	assert.Equal(t, networkv1.Component_COMPONENT_TRANSPORT, m.Status()[0].GetComponent())
}

func TestRaiseSocketBuffers(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "net/core"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "net/core/rmem_max"), []byte("212992\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "net/core/wmem_max"), []byte("16777216\n"), 0o644))
	require.NoError(t, RaiseSocketBuffers(root))
	rmem, _ := os.ReadFile(filepath.Join(root, "net/core/rmem_max"))
	wmem, _ := os.ReadFile(filepath.Join(root, "net/core/wmem_max"))
	assert.Equal(t, "8388608\n", string(rmem))
	assert.Equal(t, "16777216\n", string(wmem), "a higher limit is kept")
	assert.Error(t, RaiseSocketBuffers(t.TempDir()))
}

// reversePlan has the egress tr-r dial back to the rendezvous instead of
// listening (anx ANX-Line §4.6).
func reversePlan() *networkv1.NetworkPlan {
	plan := acceptPlan()
	plan.Transports[0].GetAnxLine().TcpAddr = ""
	plan.Transports[0].GetAnxLine().Reverse = true
	plan.Transports[0].GetAnxLine().ReverseDial = "198.51.100.30:24444"
	return plan
}

func TestAcceptsReverse(t *testing.T) {
	accepts, err := Accepts(reversePlan())
	require.NoError(t, err)
	reverse := accepts[1]
	assert.Equal(t, "tr-b", reverse.Transport)
	assert.Equal(t, "198.51.100.30:24444", reverse.ReverseDial)
	assert.Equal(t, []string{"--sni", "anx-line"}, reverse.listener().args(), "the egress listens on nothing")
	_, err = group(accepts)
	require.NoError(t, err)

	_, err = group([]Accept{{Transport: "t", ReverseDial: "198.51.100.30:24444", TCP: "1.2.3.4:443"}})
	assert.ErrorContains(t, err, "no listen address and is l1")
	_, err = group([]Accept{{Transport: "t", ReverseDial: "nowhere"}})
	assert.ErrorContains(t, err, "not host:port")

	// A relay hop into a reverse link is the rendezvous.
	relay := relayPlan()
	next := relay.Transports[3].GetAnxLine()
	next.TcpAddr, next.Egress, next.ServerName = "", "", ""
	next.Reverse, next.ReverseListen = true, "0.0.0.0:24444"
	accepts, err = Accepts(relay)
	require.NoError(t, err)
	assert.True(t, accepts[0].Next.GetReverse())
	assert.Empty(t, accepts[0].Next.GetTcpAddr())
	assert.Equal(t, "0.0.0.0:24444", accepts[0].ReverseListen)
	assert.Contains(t, strings.Join(accepts[0].listener().args(), " "), "--reverse-listen 0.0.0.0:24444")
	assert.NotContains(t, strings.Join(accepts[0].listener().args(), " "), "--reverse-quic", "an empty order is C1 only")

	// C2 / C3 dial-backs follow the carrier order (anx ANX-LINE-REVERSE §6.3).
	next.CarrierOrder = []string{"c2", "c3", "c1"}
	accepts, err = Accepts(relay)
	require.NoError(t, err)
	args := strings.Join(accepts[0].listener().args(), " ")
	assert.Contains(t, args, "--reverse-listen 0.0.0.0:24444 --reverse-quic --reverse-faketcp")
	assert.Contains(t, args, "--quic-sockbuf", "the C2 dial-back gets the large UDP buffer")
	egress := reversePlan()
	egress.Transports[0].GetAnxLine().CarrierOrder = []string{"quic", "tcp"}
	accepts, err = Accepts(egress)
	require.NoError(t, err)
	assert.True(t, accepts[1].ReverseQUIC)
	assert.False(t, accepts[1].ReverseFakeTCP)
	assert.Equal(t, []string{"--sni", "anx-line", "--quic-sockbuf", strconv.Itoa(QUICSocketBuffer),
		"--quic-dgram-buf", strconv.Itoa(QUICDatagramBuffer)}, accepts[1].listener().args(), "still listens on nothing")
}

// The egress process keeps the reverse dials of its accepts, again after a
// restart, and drops them with the transport.
func TestManagerDialsBack(t *testing.T) {
	host := &fakeHost{}
	m, _ := newManager(t, host)
	accepts, err := Accepts(reversePlan())
	require.NoError(t, err)
	reverse := accepts[1:]

	require.NoError(t, m.Apply(reverse))
	applied(t, m, "tr-b")
	assert.Equal(t, []string{"tr-b=198.51.100.30:24444"}, host.reverseDials())
	assert.NotContains(t, strings.Join(host.last().args, " "), "--bare-listen")

	host.last().Stop()
	require.Eventually(t, func() bool {
		return host.started() == 2 && assert.ObjectsAreEqual([]string{"tr-b=198.51.100.30:24444"}, host.reverseDials())
	}, 2*time.Second, 5*time.Millisecond)

	reverse[0].ReverseDial = "198.51.100.31:24444"
	require.NoError(t, m.Apply(reverse))
	require.Eventually(t, func() bool {
		return assert.ObjectsAreEqual([]string{"tr-b=198.51.100.31:24444"}, host.reverseDials())
	}, 2*time.Second, 5*time.Millisecond)
	assert.Equal(t, 2, host.started(), "changed on the running process")

	// Adding C2 needs the large UDP buffer, so a new process.
	reverse[0].ReverseQUIC = true
	require.NoError(t, m.Apply(reverse))
	require.Eventually(t, func() bool {
		return assert.ObjectsAreEqual([]string{"tr-b=198.51.100.31:24444+quic"}, host.reverseDials())
	}, 2*time.Second, 5*time.Millisecond)
}

// A carrier that measures no round trip (anything but QUIC) reports the
// handshake of its last probe in its place.
func TestWithStatFallsBackToTheProbeHandshake(t *testing.T) {
	stat := &anxmgmtpb.LinkStat{Connected: true, Carrier: "c1", Probes: []*anxmgmtpb.CarrierProbe{
		{Carrier: "c2", Ok: true, HandshakeMs: 9},
		{Carrier: "c1", Ok: true, HandshakeMs: 31},
	}}
	assert.Equal(t, uint32(31), withStat(&networkv1.ComponentStatus{}, stat).GetRttMs())
	stat.RttMs = 12
	assert.Equal(t, uint32(12), withStat(&networkv1.ComponentStatus{}, stat).GetRttMs())
}
