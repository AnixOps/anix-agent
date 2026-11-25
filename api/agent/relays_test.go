package agent

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// relayMode is how a fake relay answers.
type relayMode int

const (
	// relayWorks accepts and carries Control's answer (one byte).
	relayWorks relayMode = iota
	// relayDown refuses the TCP connection.
	relayDown
	// relayBroken accepts the TCP connection, then closes it without an
	// answer, as a relay whose way to Control is down.
	relayBroken
)

// fakeRelays is a Relays over a fake network: each address takes cost to
// connect (also slept, so that a race finishes in cost order) and answers
// as its mode says.
type fakeRelays struct {
	*Relays
	mu    sync.Mutex
	clock time.Time
	cost  map[string]time.Duration
	mode  map[string]relayMode
	dials []string
}

func newFakeRelays(t *testing.T, addresses ...string) *fakeRelays {
	t.Helper()
	relays, err := NewRelays(addresses)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeRelays{Relays: relays, clock: time.Unix(1_700_000_000, 0), cost: map[string]time.Duration{}, mode: map[string]relayMode{}}
	relays.now = func() time.Time {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return fake.clock
	}
	relays.background = func(f func()) { f() }
	relays.connect = func(_ context.Context, address string) (net.Conn, time.Duration, error) {
		fake.mu.Lock()
		fake.dials = append(fake.dials, address)
		cost, mode := fake.cost[address], fake.mode[address]
		fake.mu.Unlock()
		time.Sleep(cost)
		if mode == relayDown {
			return nil, 0, errors.New("connection refused")
		}
		client, server := net.Pipe()
		go func() {
			if mode == relayWorks {
				_, _ = server.Write([]byte{1})
			}
			_ = server.Close()
		}()
		return client, cost, nil
	}
	return fake
}

func (f *fakeRelays) set(address string, cost time.Duration, mode relayMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cost[address], f.mode[address] = cost, mode
}

func (f *fakeRelays) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clock = f.clock.Add(d)
}

func (f *fakeRelays) resetDials() {
	f.mu.Lock()
	f.dials = nil
	f.mu.Unlock()
}

func (f *fakeRelays) dialList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dials...)
}

func (f *fakeRelays) relayState(index int) relayState {
	f.Relays.mu.Lock()
	defer f.Relays.mu.Unlock()
	return f.state[index]
}

// dialed dials once, reads what comes through as the TLS handshake would,
// closes, and answers the relay the connection went to.
func (f *fakeRelays) dialed(t *testing.T) string {
	t.Helper()
	conn, err := f.Dial(context.Background(), "panel.example.com:50051")
	if err != nil {
		t.Fatal(err)
	}
	relay := f.addresses[conn.(*relayConn).index]
	_, _ = io.ReadFull(conn, make([]byte, 1))
	_ = conn.Close()
	return relay
}

func shortenRelayTimers(t *testing.T, probe, backoff time.Duration) {
	t.Helper()
	savedProbe, savedMin := relayProbeInterval, relayBackoffMin
	relayProbeInterval, relayBackoffMin = probe, backoff
	t.Cleanup(func() { relayProbeInterval, relayBackoffMin = savedProbe, savedMin })
}

func TestNewRelays(t *testing.T) {
	relays, err := NewRelays([]string{" ", ""})
	if err != nil || relays != nil {
		t.Fatalf("an empty list = %v, %v; want no relays", relays, err)
	}
	relays, err = NewRelays([]string{"relay-1.example:50051", "relay-1.example:50051", " [2001:db8::1]:50051 "})
	if err != nil {
		t.Fatal(err)
	}
	if got := relays.Addresses(); len(got) != 2 || got[1] != "[2001:db8::1]:50051" {
		t.Fatalf("addresses = %v", got)
	}
	for _, bad := range []string{"relay.example", ":50051", "relay.example:0", "relay.example:x"} {
		if _, err := NewRelays([]string{bad}); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestRelaysFirstDialTakesTheFastest(t *testing.T) {
	f := newFakeRelays(t, "a:1", "b:1")
	f.set("a:1", 150*time.Millisecond, relayWorks)
	f.set("b:1", time.Millisecond, relayWorks)
	started := time.Now()
	if got := f.dialed(t); got != "b:1" {
		t.Fatalf("first connection went to %s, want the faster b", got)
	}
	if waited := time.Since(started); waited >= 150*time.Millisecond {
		t.Fatalf("the first dial waited %s for the slower relay", waited)
	}
}

func TestRelaysStayUnlessClearlyFaster(t *testing.T) {
	shortenRelayTimers(t, time.Minute, 5*time.Second)
	f := newFakeRelays(t, "a:1", "b:1")
	f.set("a:1", 80*time.Millisecond, relayWorks)
	f.set("b:1", 20*time.Millisecond, relayWorks)
	if got := f.dialed(t); got != "b:1" {
		t.Fatalf("first connection went to %s, want b", got)
	}
	// a becomes a little faster, not 30% faster: stay on b.
	f.set("a:1", 15*time.Millisecond, relayWorks)
	f.advance(time.Minute)
	if got := f.dialed(t); got != "b:1" {
		t.Fatalf("moved to %s for a small gain", got)
	}
	// a becomes clearly faster: the next connection moves.
	f.set("a:1", 5*time.Millisecond, relayWorks)
	f.advance(time.Minute)
	if got := f.dialed(t); got != "a:1" {
		t.Fatalf("stayed on %s, want the clearly faster a", got)
	}
}

// A relay that accepts but cannot reach Control is the common failure: the
// TCP connection succeeds and the stream does not. It must be passed over,
// and a measurement that only connects must not bring it back.
func TestRelaysPassOverARelayThatAcceptsButDoesNotReachControl(t *testing.T) {
	shortenRelayTimers(t, time.Second, time.Minute)
	f := newFakeRelays(t, "a:1", "b:1")
	f.set("a:1", time.Millisecond, relayBroken)
	f.set("b:1", 60*time.Millisecond, relayWorks)
	if got := f.dialed(t); got != "a:1" {
		t.Fatalf("first connection went to %s, want the faster a", got)
	}
	if state := f.relayState(0); state.failures != 1 || state.retryAt.IsZero() {
		t.Fatalf("a closed before Control answered but its state is %+v", state)
	}
	for i := 0; i < 3; i++ {
		f.advance(time.Second) // a measurement runs: a still connects fastest
		if got := f.dialed(t); got != "b:1" {
			t.Fatalf("connection %d went to %s, want the working b", i, got)
		}
	}
	if state := f.relayState(0); state.failures != 1 {
		t.Fatalf("a measurement cleared a's failures: %+v", state)
	}
	if state := f.relayState(1); state.failures != 0 {
		t.Fatalf("b carried Control's answer but has failures: %+v", state)
	}
}

func TestRelaysFailOverAndBackOff(t *testing.T) {
	f := newFakeRelays(t, "a:1", "b:1")
	f.set("a:1", time.Millisecond, relayWorks)
	f.set("b:1", 30*time.Millisecond, relayWorks)
	if got := f.dialed(t); got != "a:1" {
		t.Fatalf("went to %s", got)
	}
	f.set("a:1", time.Millisecond, relayDown)
	if got := f.dialed(t); got != "b:1" {
		t.Fatalf("failed over to %s, want b", got)
	}
	// a is back but in backoff: b keeps the connections without a being
	// tried first.
	f.set("a:1", time.Millisecond, relayWorks)
	f.resetDials()
	if got := f.dialed(t); got != "b:1" {
		t.Fatalf("went to %s", got)
	}
	if dials := f.dialList(); len(dials) != 1 || dials[0] != "b:1" {
		t.Fatalf("dials = %v, want b only while a backs off", dials)
	}
}

func TestRelaysTryEveryRelayWhenAllBackOff(t *testing.T) {
	f := newFakeRelays(t, "a:1", "b:1")
	f.set("a:1", time.Millisecond, relayDown)
	f.set("b:1", time.Millisecond, relayDown)
	if _, err := f.Dial(context.Background(), "panel.example.com:50051"); err == nil {
		t.Fatal("dialed with every relay down")
	}
	f.set("b:1", time.Millisecond, relayWorks)
	if got := f.dialed(t); got != "b:1" {
		t.Fatalf("went to %s", got)
	}
}

func TestRelaysCallerCancellationIsNotARelayFailure(t *testing.T) {
	f := newFakeRelays(t, "a:1", "b:1")
	f.set("a:1", time.Millisecond, relayWorks)
	f.set("b:1", 30*time.Millisecond, relayWorks)
	f.dialed(t)
	f.set("a:1", time.Millisecond, relayDown)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.Dial(ctx, "panel.example.com:50051"); err == nil {
		t.Fatal("dialed with a cancelled context")
	}
	if state := f.relayState(0); state.failures != 0 {
		t.Fatalf("the caller's cancellation counted against a: %+v", state)
	}
}

func TestRelaysBackoffIsBounded(t *testing.T) {
	f := newFakeRelays(t, "a:1")
	for i := 0; i < 40; i++ {
		f.failed(0)
	}
	f.mu.Lock()
	now := f.clock
	f.mu.Unlock()
	if wait := f.relayState(0).retryAt.Sub(now); wait <= 0 || wait > relayBackoffMax {
		t.Fatalf("backoff = %s, want at most %s", wait, relayBackoffMax)
	}
}
