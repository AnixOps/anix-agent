package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

// Region relays (anix-control docs/design/region-relay): machines inside the
// node's region that forward its connection to Control byte for byte. The
// Agent dials a relay instead of Control, and everything above TCP stays
// as it was: the gRPC target, the TLS server name it verifies Control's
// certificate by, and the client certificate it presents are Control's and
// its own. A relay never sees a key and cannot read or change the stream.
//
// A node with relays never dials Control directly: in a region that goes
// through relays (mainland China), only the relays may reach Control.
//
// A relay accepts the TCP connection before it reaches Control, so a relay
// whose way to Control is down still accepts. A relay therefore counts as
// working only once Control's first bytes (the TLS ServerHello) arrive
// through it; a connection that ends or is closed before that is a failure
// of the relay, and the relay is passed over with a growing backoff.

// Relay selection constants. Variables so tests can shorten them.
var (
	// relayDialTimeout bounds one relay dial.
	relayDialTimeout = 5 * time.Second
	// relayProbeInterval is how often the relays are measured again.
	relayProbeInterval = 10 * time.Minute
	// relayBackoffMin and relayBackoffMax bound how long a relay that
	// failed is passed over.
	relayBackoffMin = 5 * time.Second
	relayBackoffMax = 5 * time.Minute
	// relayAnswerTimeout is how long Control may take to answer through a
	// relay (its first bytes after the TCP connect) before the relay is
	// given up as hanging, ahead of the caller's longer dial timeout.
	relayAnswerTimeout = 5 * time.Second
)

// relaySwitchRatio is how much faster another relay must be before new
// connections move to it: 30% lower connect time. Smaller differences keep
// the current relay, so nodes do not flap between two similar relays.
const relaySwitchRatio = 0.7

// Relays dials Control through the region relays: the current relay first,
// then the others by measured connect time, passing over relays that failed
// recently.
type Relays struct {
	addresses []string
	// connect dials address and answers how long the connection took.
	connect func(ctx context.Context, address string) (net.Conn, time.Duration, error)
	now     func() time.Time
	// background runs a periodic measurement off the dial path (tests run
	// it inline).
	background func(func())

	mu      sync.Mutex
	state   []relayState
	current int
	probed  time.Time
	probing bool
}

type relayState struct {
	// rtt is the last measured connect time; zero is unmeasured.
	rtt time.Duration
	// failures counts the consecutive failures: dials, and connections
	// that ended before Control answered through the relay.
	failures int
	// retryAt is when a failed relay may be tried again.
	retryAt time.Time
}

// NewRelays returns the dialer of addresses (host:port), nil when there are
// none. An address that is not host:port is an error: a relay list with a
// typo must not silently leave the node without a path to Control.
func NewRelays(addresses []string) (*Relays, error) {
	cleaned, err := cleanRelayAddresses(addresses)
	if err != nil || len(cleaned) == 0 {
		return nil, err
	}
	dialer := &net.Dialer{KeepAlive: 30 * time.Second}
	return &Relays{
		addresses: cleaned,
		connect: func(ctx context.Context, address string) (net.Conn, time.Duration, error) {
			started := time.Now()
			conn, err := dialer.DialContext(ctx, "tcp", address)
			return conn, time.Since(started), err
		},
		now:        time.Now,
		background: func(f func()) { go f() },
		state:      make([]relayState, len(cleaned)),
		current:    -1,
	}, nil
}

// cleanRelayAddresses trims, checks and deduplicates relay addresses.
func cleanRelayAddresses(addresses []string) ([]string, error) {
	var cleaned []string
	seen := map[string]bool{}
	for _, address := range addresses {
		address = strings.TrimSpace(address)
		if address == "" {
			continue
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil || strings.TrimSpace(host) == "" {
			return nil, fmt.Errorf("relay %q is not host:port", address)
		}
		if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
			return nil, fmt.Errorf("relay %q has no valid port", address)
		}
		if !seen[address] {
			seen[address] = true
			cleaned = append(cleaned, address)
		}
	}
	return cleaned, nil
}

// Addresses are the relays, in configuration order.
func (r *Relays) Addresses() []string { return append([]string(nil), r.addresses...) }

// DialContext wraps dial so that every gRPC connection it opens goes
// through the relays. The target and every option stay as they are.
func (r *Relays) DialContext(dial DialContextFunc) DialContextFunc {
	if dial == nil {
		dial = grpc.DialContext
	}
	return func(ctx context.Context, target string, options ...grpc.DialOption) (*grpc.ClientConn, error) {
		return dial(ctx, target, append(append([]grpc.DialOption(nil), options...), grpc.WithContextDialer(r.Dial))...)
	}
}

// Dial opens a TCP connection to a relay. address is Control's target,
// which only the relay dials. The first dial measures every relay at once
// and keeps the connection that answered first; later dials go to the
// current relay, then the others by connect time, and the measurement is
// repeated in the background.
func (r *Relays) Dial(ctx context.Context, address string) (net.Conn, error) {
	if conn, raced, err := r.raceIfUnmeasured(ctx); raced {
		if err != nil {
			return nil, fmt.Errorf("no region relay answered for %s: %w", address, err)
		}
		return conn, nil
	}
	r.probeIfDue()
	var errs []error
	for _, index := range r.order() {
		dialCtx, cancel := context.WithTimeout(ctx, relayDialTimeout)
		conn, rtt, err := r.connect(dialCtx, r.addresses[index])
		cancel()
		if err == nil {
			return r.connected(index, rtt, conn), nil
		}
		if ctx.Err() != nil {
			// The caller gave up (shutdown or its own deadline): that says
			// nothing about the relay.
			errs = append(errs, ctx.Err())
			break
		}
		r.failed(index)
		errs = append(errs, fmt.Errorf("relay %s: %w", r.addresses[index], err))
	}
	return nil, fmt.Errorf("no region relay answered for %s: %w", address, errors.Join(errs...))
}

// raceIfUnmeasured dials every relay at once when none was measured yet,
// and keeps the first connection: the relay that answers first is the
// fastest. Every connect time is recorded; the other connections are
// closed. raced is false once the relays have been measured.
func (r *Relays) raceIfUnmeasured(ctx context.Context) (conn net.Conn, raced bool, err error) {
	r.mu.Lock()
	if !r.probed.IsZero() {
		r.mu.Unlock()
		return nil, false, nil
	}
	r.probed = r.now()
	r.mu.Unlock()

	type result struct {
		index int
		conn  net.Conn
		rtt   time.Duration
		err   error
	}
	results := make(chan result, len(r.addresses))
	raceCtx, cancel := context.WithTimeout(ctx, relayDialTimeout)
	for i, address := range r.addresses {
		go func() {
			conn, rtt, err := r.connect(raceCtx, address)
			results <- result{index: i, conn: conn, rtt: rtt, err: err}
		}()
	}
	var errs []error
	for received := 0; received < len(r.addresses); received++ {
		got := <-results
		if got.err != nil {
			if ctx.Err() == nil {
				r.failed(got.index)
			}
			errs = append(errs, fmt.Errorf("relay %s: %w", r.addresses[got.index], got.err))
			continue
		}
		wrapped := r.connected(got.index, got.rtt, got.conn)
		// The others finish in the background: their connect times are
		// recorded and their connections closed.
		remaining := len(r.addresses) - received - 1
		go func() {
			defer cancel()
			for ; remaining > 0; remaining-- {
				other := <-results
				if other.err != nil {
					continue
				}
				r.measured(other.index, other.rtt)
				_ = other.conn.Close()
			}
		}()
		return wrapped, true, nil
	}
	cancel()
	if ctx.Err() != nil {
		errs = append(errs, ctx.Err())
	}
	return nil, true, errors.Join(errs...)
}

// order is the relays to try: the current one, then the others by connect
// time (unmeasured last, configuration order among equals); relays in
// backoff go last, so that with every relay failing they are still tried.
func (r *Relays) order() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	indexes := make([]int, len(r.addresses))
	for i := range indexes {
		indexes[i] = i
	}
	sort.SliceStable(indexes, func(a, b int) bool {
		i, j := indexes[a], indexes[b]
		iWaiting, jWaiting := now.Before(r.state[i].retryAt), now.Before(r.state[j].retryAt)
		if iWaiting != jWaiting {
			return !iWaiting
		}
		if (i == r.current) != (j == r.current) {
			return i == r.current
		}
		return lessRTT(r.state[i].rtt, r.state[j].rtt)
	})
	return indexes
}

func lessRTT(a, b time.Duration) bool {
	switch {
	case a == 0:
		return false
	case b == 0:
		return true
	default:
		return a < b
	}
}

// connected records a TCP connection to relay index and answers it wrapped,
// so that whether Control answers through it settles the relay's health.
// The TCP connection alone clears nothing: the relay accepts it before it
// reaches Control.
func (r *Relays) connected(index int, rtt time.Duration, conn net.Conn) net.Conn {
	r.measured(index, rtt)
	r.mu.Lock()
	r.setCurrent(index)
	r.mu.Unlock()
	setRelayUserTimeout(conn, controlKeepaliveTimeout)
	wrapped := &relayConn{Conn: conn, relays: r, index: index, answered: make(chan struct{})}
	go wrapped.awaitAnswer(relayAnswerTimeout)
	return wrapped
}

// measured records a connect time of relay index.
func (r *Relays) measured(index int, rtt time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// A zero duration would read as "unmeasured".
	r.state[index].rtt = max(rtt, time.Nanosecond)
}

// working records that Control answered through relay index.
func (r *Relays) working(index int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := &r.state[index]
	state.failures, state.retryAt = 0, time.Time{}
}

// setCurrent makes index the current relay; the caller holds mu.
func (r *Relays) setCurrent(index int) {
	if r.current == index {
		return
	}
	if r.current >= 0 {
		log.WithField("relay", r.addresses[index]).WithField("previous", r.addresses[r.current]).Info("Control is now reached through another region relay")
	} else {
		log.WithField("relay", r.addresses[index]).Info("Control is reached through a region relay")
	}
	r.current = index
}

func (r *Relays) failed(index int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := &r.state[index]
	state.failures++
	backoff := relayBackoffMin << min(state.failures-1, 16)
	if backoff > relayBackoffMax || backoff <= 0 {
		backoff = relayBackoffMax
	}
	state.retryAt = r.now().Add(backoff)
	if r.current == index {
		r.current = -1
	}
	if state.failures == 1 || state.failures%10 == 0 {
		log.WithField("relay", r.addresses[index]).WithField("failures", state.failures).WithField("retry_in", backoff.String()).Warn("A region relay did not carry the connection to Control; passing over it")
	}
}

// probeIfDue measures every relay's connect time in the background when
// relayProbeInterval has passed, and moves new connections to a relay that
// is clearly faster than the current one. A measurement only times the TCP
// connect: it neither clears a relay's backoff nor moves to a relay in
// backoff, since only Control answering through a relay shows it works.
func (r *Relays) probeIfDue() {
	r.mu.Lock()
	due := !r.probing && r.now().Sub(r.probed) >= relayProbeInterval && len(r.addresses) > 1
	if due {
		r.probed, r.probing = r.now(), true
	}
	r.mu.Unlock()
	if due {
		r.background(r.probe)
	}
}

func (r *Relays) probe() {
	defer func() {
		r.mu.Lock()
		r.probing = false
		r.mu.Unlock()
	}()
	results := make([]time.Duration, len(r.addresses))
	var wg sync.WaitGroup
	for i, address := range r.addresses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			probeCtx, cancel := context.WithTimeout(context.Background(), relayDialTimeout)
			defer cancel()
			conn, rtt, err := r.connect(probeCtx, address)
			if err != nil {
				return
			}
			results[i] = max(rtt, time.Nanosecond)
			_ = conn.Close()
		}()
	}
	wg.Wait()

	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	best := -1
	for i, rtt := range results {
		if rtt == 0 {
			continue
		}
		r.state[i].rtt = rtt
		if now.Before(r.state[i].retryAt) {
			continue
		}
		if best < 0 || rtt < results[best] {
			best = i
		}
	}
	if best < 0 || best == r.current {
		return
	}
	if r.current < 0 || results[r.current] == 0 ||
		float64(results[best]) < relaySwitchRatio*float64(results[r.current]) {
		if r.current >= 0 {
			log.WithField("relay", r.addresses[best]).WithField("previous", r.addresses[r.current]).Info("A clearly faster region relay takes the next connections")
		}
		r.current = best
	}
}

// relayConn is a connection through relay index. Its first read settles
// the relay's health: bytes from Control mean the relay works; an error, a
// close, or relayAnswerTimeout passing before any byte means it did not
// carry the connection. It hides the *net.TCPConn from gRPC, which then
// cannot set TCP_USER_TIMEOUT; connected sets it.
type relayConn struct {
	net.Conn
	relays   *Relays
	index    int
	settled  atomic.Bool
	answered chan struct{}
}

// awaitAnswer gives up the relay as hanging when Control has not answered
// through it within timeout.
func (c *relayConn) awaitAnswer(timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-c.answered:
	case <-timer.C:
		if c.settle(false) {
			log.WithField("relay", c.relays.addresses[c.index]).Warn("Control did not answer through the region relay in time; closing the connection")
			_ = c.Conn.Close()
		}
	}
}

func (c *relayConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	switch {
	case n > 0:
		c.settle(true)
	case err != nil:
		c.settle(false)
	}
	return n, err
}

func (c *relayConn) Close() error {
	c.settle(false)
	return c.Conn.Close()
}

// settle records the relay's health once, and reports whether this call
// did.
func (c *relayConn) settle(working bool) bool {
	if !c.settled.CompareAndSwap(false, true) {
		return false
	}
	close(c.answered)
	if working {
		c.relays.working(c.index)
	} else {
		c.relays.failed(c.index)
	}
	return true
}
