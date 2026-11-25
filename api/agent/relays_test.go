package agent

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeRelays is a Relays over a fake network: each address takes cost of
// fake time to answer, or fails when down.
type fakeRelays struct {
	*Relays
	mu    sync.Mutex
	clock time.Time
	cost  map[string]time.Duration
	down  map[string]bool
	dials []string
}

func newFakeRelays(t *testing.T, addresses ...string) *fakeRelays {
	t.Helper()
	relays, err := NewRelays(addresses)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeRelays{Relays: relays, clock: time.Unix(1_700_000_000, 0), cost: map[string]time.Duration{}, down: map[string]bool{}}
	relays.now = func() time.Time {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return fake.clock
	}
	relays.connect = func(_ context.Context, address string) (net.Conn, time.Duration, error) {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		fake.dials = append(fake.dials, address)
		if fake.down[address] {
			return nil, 0, errors.New("connection refused")
		}
		client, server := net.Pipe()
		_ = server.Close()
		return client, fake.cost[address], nil
	}
	return fake
}

func (f *fakeRelays) set(address string, cost time.Duration, down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cost[address], f.down[address] = cost, down
}

func (f *fakeRelays) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clock = f.clock.Add(d)
}

// dialed dials once and answers the relay the connection went to.
func (f *fakeRelays) dialed(t *testing.T) string {
	t.Helper()
	f.mu.Lock()
	f.dials = nil
	f.mu.Unlock()
	conn, err := f.Dial(context.Background(), "panel.example.com:50051")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dials[len(f.dials)-1]
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

func TestRelaysPickTheFastestAndStayOnIt(t *testing.T) {
	f := newFakeRelays(t, "a:1", "b:1")
	f.set("a:1", 80*time.Millisecond, false)
	f.set("b:1", 20*time.Millisecond, false)
	if got := f.dialed(t); got != "b:1" {
		t.Fatalf("first connection went to %s, want the faster b", got)
	}
	// a becomes a little faster, not 30% faster: stay on b.
	f.set("a:1", 15*time.Millisecond, false)
	f.advance(relayProbeInterval)
	if got := f.dialed(t); got != "b:1" {
		t.Fatalf("moved to %s for a small gain", got)
	}
	// a becomes clearly faster: the next connection moves.
	f.set("a:1", 5*time.Millisecond, false)
	f.advance(relayProbeInterval)
	if got := f.dialed(t); got != "a:1" {
		t.Fatalf("stayed on %s, want the clearly faster a", got)
	}
}

func TestRelaysFailOverAndBackOff(t *testing.T) {
	f := newFakeRelays(t, "a:1", "b:1")
	f.set("a:1", 10*time.Millisecond, false)
	f.set("b:1", 30*time.Millisecond, false)
	if got := f.dialed(t); got != "a:1" {
		t.Fatalf("went to %s", got)
	}
	f.set("a:1", 10*time.Millisecond, true)
	if got := f.dialed(t); got != "b:1" {
		t.Fatalf("failed over to %s, want b", got)
	}
	// a is back but in backoff: b keeps the connections without a being
	// tried first.
	f.set("a:1", 10*time.Millisecond, false)
	f.mu.Lock()
	f.dials = nil
	f.mu.Unlock()
	conn, err := f.Dial(context.Background(), "panel.example.com:50051")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	f.mu.Lock()
	dials := append([]string(nil), f.dials...)
	f.mu.Unlock()
	if len(dials) != 1 || dials[0] != "b:1" {
		t.Fatalf("dials = %v, want b only while a backs off", dials)
	}
}

func TestRelaysTryEveryRelayWhenAllBackOff(t *testing.T) {
	f := newFakeRelays(t, "a:1", "b:1")
	f.set("a:1", time.Millisecond, true)
	f.set("b:1", time.Millisecond, true)
	if _, err := f.Dial(context.Background(), "panel.example.com:50051"); err == nil {
		t.Fatal("dialed with every relay down")
	}
	f.set("b:1", time.Millisecond, false)
	if got := f.dialed(t); got != "b:1" {
		t.Fatalf("went to %s", got)
	}
}

func TestRelaysNeverDialTheTarget(t *testing.T) {
	f := newFakeRelays(t, "relay:50051")
	f.dialed(t)
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, address := range f.dials {
		if address == "panel.example.com:50051" {
			t.Fatal("Control was dialed directly")
		}
	}
}

func TestRelaysBackoffIsBounded(t *testing.T) {
	f := newFakeRelays(t, "a:1")
	f.set("a:1", 0, true)
	for i := 0; i < 40; i++ {
		f.failed(0)
	}
	f.mu.Lock()
	now := f.clock
	f.mu.Unlock()
	if wait := f.state[0].retryAt.Sub(now); wait <= 0 || wait > relayBackoffMax {
		t.Fatalf("backoff = %s, want at most %s", wait, relayBackoffMax)
	}
}
