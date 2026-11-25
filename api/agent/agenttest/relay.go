package agenttest

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
)

// Relay is an in-process region relay (anix-control cmd/anix-relay): it
// accepts TCP connections and copies them byte for byte to Upstream. Broken
// makes it accept and close at once, as a relay whose way to Control is
// down.
type Relay struct {
	// Address is the relay's host:port.
	Address string
	// Upstream is where it forwards.
	Upstream string

	listener net.Listener
	broken   atomic.Bool
	accepted atomic.Int64
	carried  atomic.Int64
	wg       sync.WaitGroup
}

// StartRelay starts a relay to upstream, stopped when the test ends.
func StartRelay(t testing.TB, upstream string) *Relay {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay := &Relay{Address: listener.Addr().String(), Upstream: upstream, listener: listener}
	relay.wg.Add(1)
	go relay.serve()
	t.Cleanup(func() {
		_ = listener.Close()
		relay.wg.Wait()
	})
	return relay
}

// SetBroken makes the relay accept and close every connection (true), or
// forward again (false).
func (r *Relay) SetBroken(broken bool) { r.broken.Store(broken) }

// Accepted is how many TCP connections the relay accepted.
func (r *Relay) Accepted() int64 { return r.accepted.Load() }

// Carried is how many connections the relay forwarded to Upstream.
func (r *Relay) Carried() int64 { return r.carried.Load() }

func (r *Relay) serve() {
	defer r.wg.Done()
	for {
		node, err := r.listener.Accept()
		if err != nil {
			return
		}
		r.accepted.Add(1)
		if r.broken.Load() {
			_ = node.Close()
			continue
		}
		// Forwarding ends when either side closes; the test's client and
		// Control close theirs when the test ends.
		go func() {
			defer func() { _ = node.Close() }()
			upstream, err := net.Dial("tcp", r.Upstream)
			if err != nil {
				return
			}
			defer func() { _ = upstream.Close() }()
			r.carried.Add(1)
			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(upstream, node); done <- struct{}{} }()
			go func() { _, _ = io.Copy(node, upstream); done <- struct{}{} }()
			<-done
		}()
	}
}
