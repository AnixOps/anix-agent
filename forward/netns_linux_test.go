//go:build linux

package forward

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	"github.com/AnixOps/anix-agent/v4/api/agent/agenttest"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"github.com/AnixOps/anix-control/sdk/forward/driver"
	"github.com/AnixOps/anix-control/sdk/forward/driver/nftables"
	"github.com/AnixOps/anix-control/sdk/forward/leastconn"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// The real-kernel test (ANIXOPS_FORWARD_E2E=1, as root, nft and ip
// installed): the forward component with the real nftables driver in a
// throwaway network namespace, behind the in-process Control. Nothing
// touches the host's own ruleset, routes or sysctls:
//
//	client ns (10.250.1.2) --veth-- forwarder ns (10.250.1.1 | 10.250.2.1) --veth-- upstream ns (10.250.2.2)
//
// Control pushes a route whose entry hop listens on 10.250.1.1:30001 and
// balances over 10.250.2.2:8080 (an echo server) and 10.250.2.3:8080
// (nobody). The component applies it, the health loop takes the dead
// upstream out of rotation, the client's connections all reach the echo
// server, and the reports carry the counters.

func requireForwardNetns(t *testing.T) {
	t.Helper()
	if os.Getenv("ANIXOPS_FORWARD_E2E") != "1" {
		t.Skip("set ANIXOPS_FORWARD_E2E=1 (as root, with nft and ip) for the real-kernel test")
	}
	if os.Geteuid() != 0 {
		t.Skip("the real-kernel test needs root")
	}
	for _, tool := range []string{"nft", "ip"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
}

type testNetns struct {
	name   string
	handle netns.NsHandle
}

func addNetns(t *testing.T, name string) *testNetns {
	t.Helper()
	if out, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil { // #nosec G204 -- generated name
		t.Fatalf("ip netns add %s: %v: %s", name, err, out)
	}
	handle, err := netns.GetFromName(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = handle.Close()
		_ = exec.Command("ip", "netns", "del", name).Run() // #nosec G204 -- generated name
	})
	n := &testNetns{name: name, handle: handle}
	n.must(t, "ip", "link", "set", "lo", "up")
	return n
}

func (n *testNetns) Run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	argv := append([]string{"netns", "exec", n.name, name}, args...)
	cmd := exec.CommandContext(ctx, "ip", argv...) // #nosec G204 -- test commands
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), &nftables.CommandError{Name: name, Args: args, Stderr: stderr.String(), Err: err}
	}
	return stdout.Bytes(), nil
}

func (n *testNetns) must(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := n.Run(context.Background(), name, args, nil); err != nil {
		t.Fatalf("%s %s in %s: %v: %s", name, strings.Join(args, " "), n.name, err, out)
	}
}

// in runs f on an OS thread inside the namespace: sockets it opens stay
// there.
func (n *testNetns) in(f func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// The thread is left in the namespace and dies with the goroutine.
		if err := netns.Set(n.handle); err != nil {
			errc <- err
			return
		}
		errc <- f()
	}()
	return <-errc
}

func (n *testNetns) dial(ctx context.Context, network, address string) (net.Conn, error) {
	var conn net.Conn
	err := n.in(func() error {
		var d net.Dialer
		c, err := d.DialContext(ctx, network, address)
		conn = c
		return err
	})
	return conn, err
}

func TestNetnsForwardComponent(t *testing.T) {
	requireForwardNetns(t)
	suffix := make([]byte, 3)
	_, _ = rand.Read(suffix)
	base := "anixops-f3b-" + hex.EncodeToString(suffix)
	fwd, client, upstream := addNetns(t, base+"-f"), addNetns(t, base+"-c"), addNetns(t, base+"-u")
	fwd.must(t, "ip", "link", "add", "vc0", "type", "veth", "peer", "name", "vc1", "netns", client.name)
	fwd.must(t, "ip", "link", "add", "vu0", "type", "veth", "peer", "name", "vu1", "netns", upstream.name)
	fwd.must(t, "ip", "addr", "add", "10.250.1.1/24", "dev", "vc0")
	fwd.must(t, "ip", "addr", "add", "10.250.2.1/24", "dev", "vu0")
	fwd.must(t, "ip", "link", "set", "vc0", "up")
	fwd.must(t, "ip", "link", "set", "vu0", "up")
	client.must(t, "ip", "addr", "add", "10.250.1.2/24", "dev", "vc1")
	client.must(t, "ip", "link", "set", "vc1", "up")
	upstream.must(t, "ip", "addr", "add", "10.250.2.2/24", "dev", "vu1")
	upstream.must(t, "ip", "link", "set", "vu1", "up")
	fwd.must(t, "sysctl", "-qw", "net.ipv4.ip_forward=1")

	// The echo server in the upstream namespace.
	var listener net.Listener
	if err := upstream.in(func() error {
		l, err := net.Listen("tcp", "10.250.2.2:8080")
		listener = l
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()

	// The real nftables driver, probed in the forwarder namespace.
	ctx := context.Background()
	cfg, report, err := nftables.Probe(ctx, fwd, nftables.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version == "" {
		t.Fatalf("nftables unavailable in the namespace: %s (%v)", cfg.Unavailable, report)
	}
	retired := NewRetired()
	d, err := nftables.New(cfg, nftables.WithRunner(fwd), nftables.WithRetiredCounters(retired.Add))
	if err != nil {
		t.Fatal(err)
	}
	registry := driver.NewRegistry()
	if err := registry.Register(d); err != nil {
		t.Fatal(err)
	}
	handle, err := netlink.NewHandleAt(fwd.handle)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(handle.Close)
	conntrack := &ConntrackSource{MarkMask: cfg.MarkMask, Handle: handle}

	control := agenttest.New(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityPackageReports, agentcontrol.CapabilityForward)
	control.NodeKind = agentcontrol.NodeKindForward
	control.NodeID = testNode.ID
	root := t.TempDir()
	component, err := New(Options{
		Node: testNode, Registry: registry, Retired: retired, StateDir: filepath.Join(root, "forward"), AgentVersion: "netns",
		Host: ProbeHost(), Dial: fwd.dial, Sources: map[forwardv1.Engine]leastconn.Source{forwardv1.Engine_ENGINE_NFTABLES: conntrack},
		ReportInterval: time.Second, ReportMinGap: 200 * time.Millisecond, ReconcileInterval: 200 * time.Millisecond,
		HealthTick: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := component.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(component.Close)
	t.Cleanup(func() { _ = d.Remove(context.Background()) })
	credential := filepath.Join(root, "enroll.token")
	control.AddCredential("anixagt_netns")
	if err := os.WriteFile(credential, []byte("anixagt_netns\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	node, err := StartNode(ctx, NodeConfig{
		StateRoot: filepath.Join(root, "state"), Component: component,
		Client: agentapi.Config{
			Target: control.Address, NodeID: int(testNode.ID), APIKey: "forward-node-token", UseTLS: true, ServerName: control.ServerName,
			RootCAs: control.ServerCAs, AgentVersion: "netns", Heartbeat: time.Second, ReconnectMin: 10 * time.Millisecond, ReconnectMax: 100 * time.Millisecond,
			Identity: &agentapi.IdentityConfig{Dir: filepath.Join(root, "pki"), Enroll: true, EnrollCredentialFile: credential, Cluster: control.Cluster},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	eventually(t, "forward.v1", func() bool { return node.Client().Negotiated(agentcontrol.CapabilityForward) })

	entry := &forwardv1.NodeHop{
		RouteId: "R1", HopIndex: 0, Role: forwardv1.HopRole_HOP_ROLE_ENTRY, Engine: forwardv1.Engine_ENGINE_NFTABLES,
		Listen: &forwardv1.Listen{Address: "10.250.1.1", Port: 30001, Protocol: forwardv1.L4Protocol_L4_PROTOCOL_TCP},
		Upstreams: []*forwardv1.Upstream{
			{Address: "10.250.2.2", Port: 8080, Weight: 1},
			{Address: "10.250.2.3", Port: 8080, Weight: 1},
		},
		Balance: forwardv1.BalanceStrategy_BALANCE_STRATEGY_ROUND_ROBIN, Mark: 1,
		Health:         &forwardv1.HealthCheck{IntervalMs: 200, TimeoutMs: 200},
		CircuitBreaker: &forwardv1.CircuitBreaker{FailureThreshold: 2, OpenMs: 60000},
		TargetPolicy:   forwardv1.TargetPolicy_TARGET_POLICY_ALLOW_PRIVATE,
	}
	desired := &forwardv1.NodeForwardState{NodeRef: testNode.String(), Generation: 1, StateHash: hashOf(1), Hops: []*forwardv1.NodeHop{entry}}
	control.SetDesiredConfig(agenttest.ForwardSnapshot(5, map[string]any{"kind": "forward"}, desired), true)
	eventually(t, "the state applied in the kernel", func() bool { return component.Status().Generation == 1 && component.Status().Applied })
	if st := component.Status(); st.HopErrors != 0 {
		t.Fatalf("hop errors: %+v, report %v", st, component.Report(ctx).GetErrors())
	}

	// The dead upstream leaves rotation: every connection reaches the echo
	// server.
	eventually(t, "the dead upstream out of rotation", func() bool {
		obs, err := d.Observe(ctx)
		if err != nil || len(obs.Rotation) != 1 {
			return false
		}
		return len(obs.Rotation[0].Active) == 1 && obs.Rotation[0].Active[0].Address == "10.250.2.2"
	})
	for i := range 10 {
		dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		conn, err := client.dial(dctx, "tcp", "10.250.1.1:30001")
		cancel()
		if err != nil {
			t.Fatalf("connection %d through the route: %v", i, err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		message := []byte(fmt.Sprintf("hello %d through anixops_fwd\n", i))
		if _, err := conn.Write(message); err != nil {
			t.Fatal(err)
		}
		echo := make([]byte, len(message))
		if _, err := io.ReadFull(conn, echo); err != nil || !bytes.Equal(echo, message) {
			t.Fatalf("connection %d: echo %q, %v", i, echo, err)
		}
		if i == 9 {
			// A live connection: the conntrack source sees it under its
			// upstream.
			conns, err := conntrack.ActiveConns(ctx)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for ap, n := range conns {
				if ap.String() == "10.250.2.2:8080" && n > 0 {
					found = true
				}
			}
			if !found {
				t.Fatalf("conntrack source: %v", conns)
			}
		}
		_ = conn.Close()
	}

	// The reports carry the applied generation, the open breaker and the
	// counters of the traffic.
	eventually(t, "a report with the route's counters", func() bool {
		reports := control.ForwardReports()
		if len(reports) == 0 {
			return false
		}
		r := reports[len(reports)-1]
		if r.GetGeneration() != 1 || !r.GetApplied() {
			return false
		}
		var counted, open bool
		for _, c := range r.GetCounters() {
			if c.GetRouteId() == "R1" && c.GetUpBytes() > 0 && c.GetDownBytes() > 0 && c.GetUpPackets() > 0 {
				counted = true
			}
		}
		for _, h := range r.GetHealth() {
			if h.GetAddress() == "10.250.2.3" && h.GetState() == forwardv1.HealthState_HEALTH_STATE_CIRCUIT_OPEN {
				open = true
			}
		}
		return counted && open
	})
	if refused := control.ForwardRefusals(); len(refused) != 0 {
		t.Fatalf("Control refused reports: %v", refused)
	}

	// An empty state removes the table.
	control.SetDesiredConfig(agenttest.ForwardSnapshot(6, map[string]any{"kind": "forward"},
		&forwardv1.NodeForwardState{NodeRef: testNode.String(), Generation: 2, StateHash: hashOf(2)}), true)
	eventually(t, "the empty state applied", func() bool { return component.Status().Generation == 2 })
	out, err := fwd.Run(ctx, "nft", []string{"list", "tables"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), nftables.Table) {
		t.Fatalf("the empty state left the table: %s", out)
	}
	// The removed hop's last counters ride in the next reports.
	eventually(t, "the retired counters reported", func() bool {
		reports := control.ForwardReports()
		r := reports[len(reports)-1]
		if r.GetGeneration() != 2 {
			return false
		}
		for _, c := range r.GetCounters() {
			if c.GetRouteId() == "R1" && c.GetUpBytes() > 0 {
				return true
			}
		}
		return false
	})
}
