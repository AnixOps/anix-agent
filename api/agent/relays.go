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

	mu      sync.Mutex
	state   []relayState
	current int
	probed  time.Time
}

type relayState struct {
	// rtt is the last measured connect time; zero is unmeasured.
	rtt time.Duration
	// failures counts the consecutive failed dials and probes.
	failures int
	// retryAt is when a failed relay may be tried again.
	retryAt time.Time
}

// NewRelays returns the dialer of addresses (host:port), nil when there are
// none. An address that is not host:port is an error: a relay list with a
// typo must not silently leave the node without a path to Control.
func NewRelays(addresses []string) (*Relays, error) {
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
	if len(cleaned) == 0 {
		return nil, nil
	}
	dialer := &net.Dialer{KeepAlive: 30 * time.Second}
	return &Relays{
		addresses: cleaned,
		connect: func(ctx context.Context, address string) (net.Conn, time.Duration, error) {
			started := time.Now()
			conn, err := dialer.DialContext(ctx, "tcp", address)
			return conn, time.Since(started), err
		},
		now:     time.Now,
		state:   make([]relayState, len(cleaned)),
		current: -1,
	}, nil
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
// which only the relay dials.
func (r *Relays) Dial(ctx context.Context, address string) (net.Conn, error) {
	r.probeIfDue(ctx)
	var errs []error
	for _, index := range r.order() {
		dialCtx, cancel := context.WithTimeout(ctx, relayDialTimeout)
		conn, rtt, err := r.connect(dialCtx, r.addresses[index])
		cancel()
		if err == nil {
			r.succeeded(index, rtt)
			return conn, nil
		}
		r.failed(index)
		errs = append(errs, fmt.Errorf("relay %s: %w", r.addresses[index], err))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("no region relay answered for %s: %w", address, errors.Join(errs...))
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

func (r *Relays) succeeded(index int, rtt time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := &r.state[index]
	state.failures, state.retryAt = 0, time.Time{}
	if state.rtt == 0 {
		state.rtt = rtt
	}
	if r.current != index {
		if r.current >= 0 {
			log.WithField("relay", r.addresses[index]).WithField("previous", r.addresses[r.current]).Info("Control is now reached through another region relay")
		} else {
			log.WithField("relay", r.addresses[index]).Info("Control is reached through a region relay")
		}
		r.current = index
	}
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
}

// probeIfDue measures every relay's connect time when they were never
// measured or relayProbeInterval has passed, and moves new connections to
// a relay that is clearly faster than the current one.
func (r *Relays) probeIfDue(ctx context.Context) {
	r.mu.Lock()
	due := r.probed.IsZero() || r.now().Sub(r.probed) >= relayProbeInterval
	if due {
		r.probed = r.now()
	}
	r.mu.Unlock()
	if !due || len(r.addresses) < 2 {
		return
	}
	results := make([]time.Duration, len(r.addresses))
	var wg sync.WaitGroup
	for i, address := range r.addresses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			probeCtx, cancel := context.WithTimeout(ctx, relayDialTimeout)
			defer cancel()
			conn, rtt, err := r.connect(probeCtx, address)
			if err != nil {
				return
			}
			// A zero duration would read as "unmeasured".
			results[i] = max(rtt, time.Nanosecond)
			_ = conn.Close()
		}()
	}
	wg.Wait()

	r.mu.Lock()
	defer r.mu.Unlock()
	best := -1
	for i, rtt := range results {
		if rtt > 0 {
			r.state[i].rtt = rtt
			r.state[i].failures, r.state[i].retryAt = 0, time.Time{}
			if best < 0 || rtt < results[best] {
				best = i
			}
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
