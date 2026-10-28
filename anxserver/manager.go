package anxserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AnixOps/anix-agent/v5/anxline"
	anxmgmtpb "github.com/AnixOps/anix-agent/v5/api/anxmgmt/v1"
	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Files in the Manager's directory.
const (
	keyFile    = "server.key"
	publicFile = "server.pub"
)

// RSTTable is the nftables table of the accepting ends' fake-TCP RST rules
// (anxline; the AnxLine section has a table of its own).
const RSTTable = "anixops_anx_line_net"

// Supervision timings.
var (
	// readyTimeout bounds how long a started process may take to answer on
	// its management endpoint.
	readyTimeout = 10 * time.Second
	readyPoll    = 200 * time.Millisecond
	rpcTimeout   = 5 * time.Second
	// restartDelay grows from its first to its last value while a process
	// keeps failing.
	restartDelays = []time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 15 * time.Second, 30 * time.Second}
)

// Process is a started anx-server.
type Process interface {
	// Done is closed when the process has exited; Err then tells why.
	Done() <-chan struct{}
	Err() error
	// Stop ends the process and waits for it.
	Stop()
}

// Launcher starts binary with args.
type Launcher func(binary string, args []string) (Process, error)

// Connector opens the management client of the process at addr.
type Connector func(addr string) (anxmgmtpb.ManagementClient, func() error, error)

// Runner runs a command and answers its standard output (keygen).
type Runner func(name string, args ...string) ([]byte, error)

// Manager runs the accepting anx_line ends.
type Manager struct {
	// Binary is the anx-server executable, Dir its directory (server key).
	Binary string
	Dir    string
	// Launch, Connect and Run reach the host; nil uses the real one.
	Launch  Launcher
	Connect Connector
	Run     Runner
	// RST installs the fake-TCP RST rules; nil leaves the firewall alone.
	RST func(links []anxline.Link) error
	// Buffers lets the host's sockets have QUICSocketBuffer bytes before a
	// QUIC listener starts; nil leaves the host alone.
	Buffers func() error

	mu      sync.Mutex
	public  string
	servers map[listener]*server
	// rst is whether RST rules were installed.
	rst bool
}

// PublicKey answers the server's public key, generating the key pair the
// first time.
func (m *Manager) PublicKey() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.publicKey()
}

func (m *Manager) publicKey() (string, error) {
	if m.public != "" {
		return m.public, nil
	}
	key, pub := filepath.Join(m.Dir, keyFile), filepath.Join(m.Dir, publicFile)
	if data, err := os.ReadFile(pub); err == nil {
		if _, keyErr := os.Stat(key); keyErr == nil {
			if public := strings.TrimSpace(string(data)); public != "" {
				m.public = public
				return public, nil
			}
		}
	}
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return "", fmt.Errorf("anx-server directory: %w", err)
	}
	// A key without its public half is made again: the dialing ends get
	// the new public key with the next plan.
	_ = os.Remove(key)
	out, err := m.run()(m.Binary, "keygen", key)
	if err != nil {
		return "", fmt.Errorf("anx-server keygen: %w", err)
	}
	public := ""
	for _, line := range strings.Split(string(out), "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "public:"); ok {
			public = strings.TrimSpace(value)
		}
	}
	if public == "" {
		return "", errors.New("anx-server keygen printed no public key")
	}
	if err := os.WriteFile(pub, []byte(public+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("anx-server public key: %w", err)
	}
	m.public = public
	return public, nil
}

// Apply runs exactly accepts: processes whose listener is gone stop, new
// ones start, and each running process admits exactly its links. Processes
// start and admit links in the background; Status tells how they are.
func (m *Manager) Apply(accepts []Accept) error {
	groups, err := group(accepts)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(groups) > 0 {
		if _, err := m.publicKey(); err != nil {
			return err
		}
	}
	var failed error
	if err := m.applyRST(accepts); err != nil {
		failed = fmt.Errorf("fake-TCP RST rules: %w", err)
	}
	if m.Buffers != nil {
		for l := range groups {
			if l.QUIC != "" {
				if err := m.Buffers(); err != nil {
					// anx-server still runs, with the buffer the kernel allows.
					log.WithError(err).Warn("Could not raise the host's socket buffer limits for anx-server's QUIC listener")
				}
				break
			}
		}
	}
	if m.servers == nil {
		m.servers = map[listener]*server{}
	}
	for l, s := range m.servers {
		if _, keep := groups[l]; !keep {
			s.close()
			delete(m.servers, l)
		}
	}
	for l, group := range groups {
		s := m.servers[l]
		if s == nil {
			s = m.newServer(l)
			m.servers[l] = s
			s.want(group)
			go s.run()
			continue
		}
		s.want(group)
	}
	return failed
}

func (m *Manager) applyRST(accepts []Accept) error {
	if m.RST == nil {
		return nil
	}
	var links []anxline.Link
	for _, accept := range accepts {
		if accept.FakeTCP == "" {
			continue
		}
		address, err := netip.ParseAddrPort(accept.FakeTCP)
		if err != nil || !address.Addr().Unmap().Is4() {
			return fmt.Errorf("transport %s: fake-TCP address %q is not IPv4 host:port", accept.Transport, accept.FakeTCP)
		}
		fake := &anxline.FakeTCP{Role: anxline.RoleServer, Port: int(address.Port())}
		if local := address.Addr().Unmap(); !local.IsUnspecified() {
			fake.Local = local.String()
		}
		links = append(links, anxline.Link{ID: accept.Transport, FakeTCP: fake})
	}
	if len(links) == 0 && !m.rst {
		return nil
	}
	if err := m.RST(links); err != nil {
		return err
	}
	m.rst = len(links) > 0
	return nil
}

// Close stops every process.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for l, s := range m.servers {
		s.close()
		delete(m.servers, l)
	}
}

// Status answers one component per accepted transport, in id order.
func (m *Manager) Status() []*networkv1.ComponentStatus {
	m.mu.Lock()
	servers := make([]*server, 0, len(m.servers))
	for _, s := range m.servers {
		servers = append(servers, s)
	}
	m.mu.Unlock()
	var components []*networkv1.ComponentStatus
	for _, s := range servers {
		components = append(components, s.status()...)
	}
	sort.Slice(components, func(i, j int) bool { return components[i].GetId() < components[j].GetId() })
	return components
}

func (m *Manager) run() Runner {
	if m.Run != nil {
		return m.Run
	}
	return run
}

func (m *Manager) newServer(l listener) *server {
	launch, connect := m.Launch, m.Connect
	if launch == nil {
		launch = launchProcess
	}
	if connect == nil {
		connect = connectGRPC
	}
	return &server{
		listener: l, binary: m.Binary, key: filepath.Join(m.Dir, keyFile), launch: launch, connect: connect,
		wake: make(chan struct{}, 1), stop: make(chan struct{}), stopped: make(chan struct{}),
	}
}

// server supervises the process of one listener.
type server struct {
	listener listener
	binary   string
	key      string
	launch   Launcher
	connect  Connector

	mu sync.Mutex
	// wanted are the accepts the process serves.
	wanted []Accept
	// state is the process's: ready once its links are admitted, detail
	// says what is wrong otherwise.
	ready  bool
	detail string
	since  time.Time

	wake    chan struct{}
	stop    chan struct{}
	stopped chan struct{}
	once    sync.Once
}

func (s *server) logger() *log.Entry {
	return log.WithFields(log.Fields{"component": "anx-server", "tcp": s.listener.TCP, "quic": s.listener.QUIC, "faketcp": s.listener.FakeTCP})
}

func (s *server) want(accepts []Accept) {
	s.mu.Lock()
	s.wanted = accepts
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *server) close() {
	s.once.Do(func() {
		close(s.stop)
		<-s.stopped
	})
}

func (s *server) setState(ready bool, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ready != ready || s.detail != detail || s.since.IsZero() {
		s.since = time.Now()
	}
	s.ready, s.detail = ready, detail
}

func (s *server) status() []*networkv1.ComponentStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := networkv1.ComponentState_COMPONENT_STATE_DOWN
	if s.ready {
		state = networkv1.ComponentState_COMPONENT_STATE_APPLIED
	}
	var components []*networkv1.ComponentStatus
	for _, accept := range s.wanted {
		components = append(components, &networkv1.ComponentStatus{
			Component: networkv1.Component_COMPONENT_TRANSPORT, Id: accept.Transport, State: state,
			Detail: s.detail, ChangedAtUnixMs: s.since.UnixMilli(),
		})
	}
	return components
}

// run starts the process and keeps it running until close, admitting the
// wanted links after each start and after each want.
func (s *server) run() {
	defer close(s.stopped)
	failures := 0
	for {
		err := s.serve()
		if err == nil {
			return
		}
		s.setState(false, err.Error())
		s.logger().WithError(err).Warn("anx-server is down")
		delay := restartDelays[min(failures, len(restartDelays)-1)]
		failures++
		select {
		case <-s.stop:
			return
		case <-time.After(delay):
		}
	}
}

// serve runs one process: nil when closed, the reason it ended otherwise.
func (s *server) serve() error {
	mgmt, err := freePort()
	if err != nil {
		return err
	}
	args := []string{"run", "--key", s.key, "--mgmt", mgmt}
	if !s.listener.L2 {
		// anx-server always runs its jacketed listener: a bare server keeps
		// it on loopback, out of the hop ingress's way.
		jacket, err := freePort()
		if err != nil {
			return err
		}
		args = append(args, "--listen", jacket)
	}
	args = append(args, s.listener.args()...)
	process, err := s.launch(s.binary, args)
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	defer process.Stop()
	client, closeClient, err := s.connect(mgmt)
	if err != nil {
		return fmt.Errorf("management endpoint: %w", err)
	}
	defer func() { _ = closeClient() }()
	admitted := map[string]admitted{}
	first := true
	for {
		if err := s.admit(client, admitted, process, first); err != nil {
			select {
			case <-process.Done():
				return exited(process)
			default:
			}
			return err
		}
		first = false
		s.setState(true, "")
		select {
		case <-s.stop:
			return nil
		case <-process.Done():
			return exited(process)
		case <-s.wake:
		}
	}
}

func exited(process Process) error {
	if err := process.Err(); err != nil {
		return fmt.Errorf("exited: %w", err)
	}
	return errors.New("exited")
}

// admitted is a link the process admits.
type admitted struct {
	key    []byte
	userID []byte
}

// admit makes the process admit exactly the wanted links. The first call
// after a start retries until the process answers.
func (s *server) admit(client anxmgmtpb.ManagementClient, current map[string]admitted, process Process, first bool) error {
	s.mu.Lock()
	wanted := s.wanted
	s.mu.Unlock()
	keep := map[string]bool{}
	var add []*anxmgmtpb.User
	var adding []Accept
	for _, accept := range wanted {
		if have, ok := current[accept.LinkID]; ok && bytes.Equal(have.key, accept.LinkKey) {
			keep[accept.LinkID] = true
			continue
		}
		add = append(add, &anxmgmtpb.User{UserKey: accept.LinkKey, ExternalId: accept.LinkID})
		adding = append(adding, accept)
	}
	var remove [][]byte
	var removing []string
	for link, have := range current {
		if !keep[link] {
			remove = append(remove, have.userID)
			removing = append(removing, link)
		}
	}
	if len(remove) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
		_, err := client.RemoveUsers(ctx, &anxmgmtpb.RemoveUsersRequest{UserIds: remove})
		cancel()
		if err != nil {
			return fmt.Errorf("remove links: %w", err)
		}
		for _, link := range removing {
			delete(current, link)
		}
	}
	if len(add) == 0 && !first {
		return nil
	}
	deadline := time.Now().Add(readyTimeout)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
		answer, err := client.AddUsers(ctx, &anxmgmtpb.AddUsersRequest{Users: add})
		cancel()
		if err == nil {
			ids := answer.GetUserIds()
			if len(ids) != len(adding) {
				return fmt.Errorf("add links: %d user ids for %d links", len(ids), len(adding))
			}
			for i, accept := range adding {
				current[accept.LinkID] = admitted{key: accept.LinkKey, userID: ids[i]}
			}
			return nil
		}
		if !first || time.Now().After(deadline) {
			return fmt.Errorf("add links: %w", err)
		}
		select {
		case <-process.Done():
			return exited(process)
		case <-s.stop:
			return errors.New("closed")
		case <-time.After(readyPoll):
		}
	}
}

// freePort answers a free loopback TCP address.
func freePort() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	address := listener.Addr().(*net.TCPAddr)
	_ = listener.Close()
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(address.Port)), nil
}

func connectGRPC(addr string) (anxmgmtpb.ManagementClient, func() error, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, err
	}
	return anxmgmtpb.NewManagementClient(conn), conn.Close, nil
}
