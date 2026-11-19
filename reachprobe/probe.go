// Package reachprobe runs the reach.probe check of the agent.diagnostic
// operation (anix-control sdk/api/agent/v1/PROTOCOL.md, "Reachability
// probe"): from the node's own network, whether other nodes' public
// addresses answer. Control asks nodes in different regions and compares
// their answers to tell a node that is down from one that is unreachable
// from some regions only.
//
// A probe only opens TCP connections and closes them at once: it sends no
// data and carries no user traffic. Host names resolve with the node's
// resolver, and an address that is not public is refused, so Control cannot
// make the node dial into its own network.
package reachprobe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AnixOps/anix-agent/v5/realityprobe"
)

// Action is the check's action and Capability the capability an Agent that
// runs it lists.
const (
	Action     = "reach.probe"
	Capability = "reach.probe"
)

const (
	defaultTimeout = 3 * time.Second
	minTimeout     = 100 * time.Millisecond
	maxTimeout     = 10 * time.Second
	maxTargets     = 64
	maxPorts       = 4
	parallel       = 16
)

// The states of one port.
const (
	StateOpen        = "open"        // connected
	StateRefused     = "refused"     // the host answered with a reset: it is reachable
	StateTimeout     = "timeout"     // no answer
	StateReset       = "reset"       // the connection was reset while it was set up
	StateUnreachable = "unreachable" // the network says there is no route
	StateError       = "error"
)

// Port is one port's answer.
type Port struct {
	Port  int    `json:"port"`
	State string `json:"state"`
	MS    int64  `json:"ms,omitempty"`
}

// Target is one target's answer. Reachable is true when any port connected
// or refused.
type Target struct {
	Host      string `json:"host"`
	Address   string `json:"address,omitempty"`
	Reachable bool   `json:"reachable"`
	Ports     []Port `json:"ports,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Result is the probe's answer, the diagnostic state's result.
type Result struct {
	Targets []Target `json:"targets"`
}

// Prober runs reach.probe; the zero value uses the system's resolver.
type Prober struct {
	// Lookup resolves a host; nil uses net.DefaultResolver.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// AllowPrivate lets a probe dial a non-public address (tests).
	AllowPrivate bool
}

// IsCheck reports whether action is reach.probe.
func (p *Prober) IsCheck(action string) bool { return action == Action }

// Check runs one probe (diagnostic.Checker). It fails only on malformed
// parameters; the verdict is "ok" when every target is reachable.
func (p *Prober) Check(ctx context.Context, action string, params map[string]any) (any, string, string, error) {
	if action != Action {
		return nil, "", "", fmt.Errorf("%q is not %s", action, Action)
	}
	targets, timeout, err := ParseParams(params)
	if err != nil {
		return nil, "", "", err
	}
	result := p.Probe(ctx, targets, timeout)
	reachable := 0
	for _, target := range result.Targets {
		if target.Reachable {
			reachable++
		}
	}
	verdict := "ok"
	if reachable < len(result.Targets) {
		verdict = "failed"
	}
	return result, verdict, fmt.Sprintf("%d of %d targets reachable", reachable, len(result.Targets)), nil
}

// Request is one target to probe.
type Request struct {
	Host  string
	Ports []int
}

// ParseParams reads targets ([{"host", "ports"}], 1 to 64 targets, 1 to 4
// ports each) and timeout_ms (per connection, 3000 when absent, clamped to
// 100 to 10000).
func ParseParams(params map[string]any) ([]Request, time.Duration, error) {
	raw, _ := params["targets"].([]any)
	if len(raw) == 0 || len(raw) > maxTargets {
		return nil, 0, fmt.Errorf("targets must list 1 to %d targets", maxTargets)
	}
	targets := make([]Request, 0, len(raw))
	for _, item := range raw {
		entry, _ := item.(map[string]any)
		host, _ := entry["host"].(string)
		host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
		if host == "" || len(host) > 253 {
			return nil, 0, errors.New("each target needs a host")
		}
		ports, _ := entry["ports"].([]any)
		if len(ports) == 0 || len(ports) > maxPorts {
			return nil, 0, fmt.Errorf("each target lists 1 to %d ports", maxPorts)
		}
		request := Request{Host: host}
		for _, port := range ports {
			n, ok := port.(float64)
			if !ok || n != float64(int(n)) || n < 1 || n > 65535 {
				return nil, 0, errors.New("a port must be an integer from 1 to 65535")
			}
			request.Ports = append(request.Ports, int(n))
		}
		targets = append(targets, request)
	}
	timeout := defaultTimeout
	if n, ok := params["timeout_ms"].(float64); ok {
		timeout = min(max(time.Duration(n)*time.Millisecond, minTimeout), maxTimeout)
	}
	return targets, timeout, nil
}

// Probe probes every target, at most 16 connections at a time, each bounded
// by timeout.
func (p *Prober) Probe(ctx context.Context, targets []Request, timeout time.Duration) *Result {
	result := &Result{Targets: make([]Target, len(targets))}
	slots := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, request := range targets {
		target := &result.Targets[i]
		target.Host = request.Host
		addr, err := p.resolve(ctx, request.Host)
		if err != nil {
			target.Error = err.Error()
			continue
		}
		target.Address = addr.String()
		target.Ports = make([]Port, len(request.Ports))
		for j, port := range request.Ports {
			wg.Add(1)
			go func() {
				defer wg.Done()
				slots <- struct{}{}
				defer func() { <-slots }()
				target.Ports[j] = dial(ctx, addr, port, timeout)
			}()
		}
	}
	wg.Wait()
	for i := range result.Targets {
		for _, port := range result.Targets[i].Ports {
			if port.State == StateOpen || port.State == StateRefused {
				result.Targets[i].Reachable = true
			}
		}
	}
	return result
}

func dial(ctx context.Context, addr netip.Addr, port int, timeout time.Duration) Port {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	started := time.Now()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(port)))
	answer := Port{Port: port, State: classify(err), MS: time.Since(started).Milliseconds()}
	if err == nil {
		_ = conn.Close()
	}
	if answer.State == StateTimeout {
		answer.MS = 0
	}
	return answer
}

func classify(err error) string {
	var netErr net.Error
	switch {
	case err == nil:
		return StateOpen
	case errors.Is(err, syscall.ECONNREFUSED):
		return StateRefused
	case errors.Is(err, syscall.ECONNRESET):
		return StateReset
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return StateUnreachable
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return StateTimeout
	}
	return StateError
}

var errNotPublic = errors.New("the host resolves to no public address")

// resolve answers the host's first public address, IPv4 first.
func (p *Prober) resolve(ctx context.Context, host string) (netip.Addr, error) {
	addrs := []netip.Addr{}
	if addr, err := netip.ParseAddr(host); err == nil {
		addrs = append(addrs, addr)
	} else if p.Lookup != nil {
		if addrs, err = p.Lookup(ctx, host); err != nil {
			return netip.Addr{}, err
		}
	} else if addrs, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host); err != nil {
		return netip.Addr{}, err
	}
	var v6 netip.Addr
	for _, addr := range addrs {
		addr = addr.Unmap()
		if !p.AllowPrivate && !realityprobe.PublicAddr(addr) {
			continue
		}
		if addr.Is4() {
			return addr, nil
		}
		if !v6.IsValid() {
			v6 = addr
		}
	}
	if v6.IsValid() {
		return v6, nil
	}
	return netip.Addr{}, errNotPublic
}
