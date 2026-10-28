package anxserver

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
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
	assert.Equal(t, []string{"--sni", "www.example.com", "--listen", "203.0.113.20:443"}, l2.listener().args())

	dial := acceptPlan()
	dial.Transports[0].Role = networkv1.TransportRole_TRANSPORT_ROLE_DIAL
	dialed, err := Accepts(dial)
	require.NoError(t, err)
	assert.Len(t, dialed, 1, "the dialing end is not anx-server's")

	onward := acceptPlan()
	onward.Forwarding[0].Next = &networkv1.Forwarding_TransportId{TransportId: "tr-w"}
	_, err = Accepts(onward)
	assert.ErrorContains(t, err, "forwarding into transport tr-w")

	bad := acceptPlan()
	bad.Transports[0].GetAnxLine().LinkKey = "00"
	_, err = Accepts(bad)
	assert.ErrorContains(t, err, "32 bytes")
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
	next      int
	// unready fails the next AddUsers calls, as a process still starting.
	unready int
}

func (h *fakeHost) launch(binary string, args []string) (Process, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	process := &fakeProcess{args: append([]string{binary}, args...), done: make(chan struct{})}
	h.processes = append(h.processes, process)
	h.users = map[string]string{}
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

func (h *fakeHost) RemoveUsers(_ context.Context, in *anxmgmtpb.RemoveUsersRequest, _ ...grpc.CallOption) (*anxmgmtpb.RemoveUsersResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, id := range in.GetUserIds() {
		delete(h.users, string(id))
	}
	return &anxmgmtpb.RemoveUsersResponse{Removed: uint32(len(in.GetUserIds()))}, nil
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
