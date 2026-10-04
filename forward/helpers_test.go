package forward

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"github.com/AnixOps/anix-control/sdk/forward/driver"
	"github.com/AnixOps/anix-control/sdk/forward/driver/fake"
	"github.com/AnixOps/anix-control/sdk/forward/wire"
	"google.golang.org/protobuf/proto"
)

// testDriver is the fake driver plus what the real drivers add around the
// contract: a soft quota (driver.QuotaEnforcer, counting its calls) and the
// WithRetiredCounters hook (the last counters of the hops an Apply removed).
type testDriver struct {
	*fake.Driver
	retired      func([]*forwardv1.Counters)
	enforceCalls atomic.Int64
}

func (d *testDriver) EnforceQuotas(ctx context.Context) ([]driver.HopKey, error) {
	d.enforceCalls.Add(1)
	return nil, ctx.Err()
}

func (d *testDriver) Apply(ctx context.Context, a driver.Artifact) (driver.ApplyResult, error) {
	before, _ := d.Driver.Observe(ctx)
	result, err := d.Driver.Apply(ctx, a)
	if err != nil || d.retired == nil {
		return result, err
	}
	kept := map[driver.HopKey]bool{}
	for _, k := range a.Hops {
		kept[k] = true
	}
	var gone []*forwardv1.Counters
	for _, c := range before.Counters {
		if !kept[driver.HopKey{RouteID: c.GetRouteId(), HopIndex: c.GetHopIndex()}] {
			gone = append(gone, c)
		}
	}
	if len(gone) > 0 {
		d.retired(gone)
	}
	return result, nil
}

// dialer answers health probes from a table of failing addresses.
type dialer struct {
	mu   sync.Mutex
	down map[string]bool
	n    atomic.Int64
}

func newDialer() *dialer { return &dialer{down: map[string]bool{}} }

func (d *dialer) set(address string, down bool) {
	d.mu.Lock()
	d.down[address] = down
	d.mu.Unlock()
}

func (d *dialer) dial(ctx context.Context, _, address string) (net.Conn, error) {
	d.n.Add(1)
	d.mu.Lock()
	down := d.down[address]
	d.mu.Unlock()
	if down {
		return nil, errors.New("connection refused")
	}
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

// sender records the reports a component sends.
type sender struct {
	mu      sync.Mutex
	reports []*forwardv1.NodeForwardReport
	at      []time.Time
	err     error
}

func (s *sender) send(message *agentv1pb.PackageReport) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	report, err := wire.DecodeReport(message.GetPayloadJson(), testNode.String())
	if err != nil {
		return err
	}
	s.reports = append(s.reports, report)
	s.at = append(s.at, time.Now())
	return nil
}

func (s *sender) all() []*forwardv1.NodeForwardReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*forwardv1.NodeForwardReport(nil), s.reports...)
}

func (s *sender) last() *forwardv1.NodeForwardReport {
	all := s.all()
	if len(all) == 0 {
		return nil
	}
	return all[len(all)-1]
}

var testNode = agentcontrol.AgentNode{Kind: agentcontrol.NodeKindForward, ID: 41}

type harness struct {
	t      *testing.T
	host   *fake.Host
	driver *testDriver
	dial   *dialer
	sent   *sender
	c      *Component
	dir    string
}

func newHarness(t *testing.T, mutate ...func(*Options)) *harness {
	t.Helper()
	h := &harness{t: t, host: fake.NewHost(nil), dial: newDialer(), sent: &sender{}, dir: t.TempDir() + "/forward"}
	h.start(mutate...)
	return h
}

// start makes a component on the harness's host and state directory: a
// second call is an Agent restart.
func (h *harness) start(mutate ...func(*Options)) {
	h.t.Helper()
	retired := NewRetired()
	h.driver = &testDriver{Driver: fake.New(h.host, fake.Options{}), retired: retired.Add}
	registry := driver.NewRegistry()
	if err := registry.Register(h.driver); err != nil {
		h.t.Fatal(err)
	}
	opts := Options{
		Node: testNode, Registry: registry, Retired: retired, StateDir: h.dir, AgentVersion: "test",
		Host: HostInfo{KernelVersion: "6.12.0", Cgroup: "v2", IPv6: true},
		Dial: h.dial.dial, ReportInterval: time.Hour, ReportMinGap: 50 * time.Millisecond,
		ReconcileInterval: 50 * time.Millisecond, ReweightInterval: time.Hour, RetryInterval: 100 * time.Millisecond,
		HealthTick: 10 * time.Millisecond,
	}
	for _, m := range mutate {
		m(&opts)
	}
	c, err := New(opts)
	if err != nil {
		h.t.Fatal(err)
	}
	c.SetSender(h.sent.send)
	if err := c.Start(context.Background()); err != nil {
		h.t.Fatal(err)
	}
	h.c = c
	h.t.Cleanup(c.Close)
}

// hop is a nftables entry hop listening on port with the given upstreams
// ("addr:port" literals, IPv4).
func hop(route string, index, port uint32, balance forwardv1.BalanceStrategy, upstreams ...*forwardv1.Upstream) *forwardv1.NodeHop {
	return &forwardv1.NodeHop{
		RouteId: route, HopIndex: index, Role: forwardv1.HopRole_HOP_ROLE_ENTRY, Engine: forwardv1.Engine_ENGINE_NFTABLES,
		Listen:    &forwardv1.Listen{Port: port, Protocol: forwardv1.L4Protocol_L4_PROTOCOL_TCP},
		Upstreams: upstreams, Balance: balance, Mark: index + 1,
		Health:         &forwardv1.HealthCheck{IntervalMs: 20, TimeoutMs: 20},
		CircuitBreaker: &forwardv1.CircuitBreaker{FailureThreshold: 2, OpenMs: 300},
	}
}

func up(address string, port, priority uint32) *forwardv1.Upstream {
	return &forwardv1.Upstream{Address: address, Port: port, Weight: 1, Priority: priority}
}

func state(generation uint64, hash string, hops ...*forwardv1.NodeHop) *forwardv1.NodeForwardState {
	return &forwardv1.NodeForwardState{NodeRef: testNode.String(), Generation: generation, StateHash: hash, Hops: hops}
}

// hashOf is a state_hash-shaped value.
func hashOf(b byte) string {
	out := make([]byte, 64)
	for i := range out {
		out[i] = "0123456789abcdef"[(int(b)+i)%16]
	}
	return string(out)
}

// snapshot is a ConfigSnapshot of format anixops.nodeconfig/v2 carrying s.
func snapshot(t testing.TB, revision uint64, s *forwardv1.NodeForwardState) *agentv1pb.ConfigSnapshot {
	t.Helper()
	member, err := wire.StateMember(s)
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(map[string]any{"kind": "forward", wire.NodeConfigMember: member})
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1pb.ConfigSnapshot{ConfigRevision: revision, Format: wire.NodeConfigFormat, ConfigJson: document}
}

func (h *harness) apply(revision uint64, s *forwardv1.NodeForwardState) error {
	h.t.Helper()
	return h.c.ApplySnapshot(context.Background(), snapshot(h.t, revision, s))
}

// eventually polls cond for up to 5 s.
func eventually(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// rotation answers the fake host's rotation of a hop.
func (h *harness) rotation(route string, index uint32) []driver.Upstream {
	obs, err := h.driver.Observe(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	for _, r := range obs.Rotation {
		if r.RouteID == route && r.HopIndex == index {
			return r.Active
		}
	}
	return nil
}

func clone[T proto.Message](m T) T { return proto.Clone(m).(T) }
