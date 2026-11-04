// Package kernelfwd runs the network plan's kernel forwards (anix-control
// network.v1 KernelForward, forward.v1 ENGINE_NFTABLES hops): connections
// to a forward's port are rewritten in the kernel towards its targets
// (nftables DNAT and masquerade), so no process listens on the port. The
// Agent owns one table, replaced whole with `nft -f`; its counters carry
// over each replacement. A loop checks the targets (TCP connect) and
// leaves the failing ones out while one is healthy.
package kernelfwd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
)

// Table is the Agent's nftables table (family inet).
const Table = "edge_nat"

const (
	defaultInterval = 5 * time.Second
	defaultTimeout  = 2 * time.Second
	// maxEntries caps a balancing map (weights repeat a target).
	maxEntries = 256
)

// Manager runs the kernel forwards.
type Manager struct {
	// NFT runs nft with args and stdin; nil runs the nft binary.
	NFT func(stdin string, args ...string) ([]byte, error)
	// Proc is the root of the sysctl files ("/proc/sys" when empty).
	Proc string

	mu       sync.Mutex
	forwards []*networkv1.KernelForward
	targets  map[string][]*target
	applied  string
	err      error
	stop     chan struct{}
}

type target struct {
	host     string
	port     uint32
	weight   uint32
	priority uint32
	addrs    []netip.Addr
	health   health
}

// health is a target's last check.
type health struct {
	state     networkv1.TargetHealthState
	failures  uint32
	rttUs     uint32
	checkedAt int64
}

// Apply replaces the forwards: the table follows at once and the loop
// keeps it on the healthy targets. No forwards delete the table.
func (m *Manager) Apply(forwards []*networkv1.KernelForward) error {
	m.mu.Lock()
	old := m.targets
	m.forwards, m.targets, m.applied = forwards, map[string][]*target{}, ""
	for _, forward := range forwards {
		for _, t := range forward.GetTargets() {
			next := &target{host: t.GetHost(), port: t.GetPort(), weight: max(t.GetWeight(), 1), priority: t.GetPriority()}
			for _, prev := range old[forward.GetId()] {
				if prev.host == next.host && prev.port == next.port {
					next.addrs, next.health = prev.addrs, prev.health
				}
			}
			m.targets[forward.GetId()] = append(m.targets[forward.GetId()], next)
		}
	}
	if m.stop != nil {
		close(m.stop)
		m.stop = nil
	}
	m.mu.Unlock()
	if len(forwards) == 0 {
		_, _ = m.nft("", "delete", "table", "inet", Table)
		m.mu.Lock()
		m.err = nil
		m.mu.Unlock()
		return nil
	}
	m.check(context.Background())
	err := m.sync()
	m.mu.Lock()
	m.stop = make(chan struct{})
	go m.loop(m.stop, interval(forwards))
	m.mu.Unlock()
	return err
}

// Close stops the checks; the table stays, so forwarding goes on.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stop != nil {
		close(m.stop)
		m.stop = nil
	}
}

func (m *Manager) loop(stop chan struct{}, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			m.check(context.Background())
			_ = m.sync()
		}
	}
}

func interval(forwards []*networkv1.KernelForward) time.Duration {
	every := defaultInterval
	for _, forward := range forwards {
		if ms := forward.GetPolicy().GetHealth().GetIntervalMs(); ms > 0 {
			every = min(every, max(time.Duration(ms)*time.Millisecond, time.Second))
		}
	}
	return every
}

// check resolves every target and, on a TCP forward with checks on,
// connects to it.
func (m *Manager) check(ctx context.Context) {
	m.mu.Lock()
	type job struct {
		t       *target
		probe   bool
		timeout time.Duration
	}
	var jobs []job
	for _, forward := range m.forwards {
		health := forward.GetPolicy().GetHealth()
		timeout := defaultTimeout
		if health.GetTimeoutMs() > 0 {
			timeout = time.Duration(health.GetTimeoutMs()) * time.Millisecond
		}
		probe := !health.GetDisabled() && hasTCP(forward)
		for _, t := range m.targets[forward.GetId()] {
			jobs = append(jobs, job{t, probe, timeout})
		}
	}
	m.mu.Unlock()
	var wg sync.WaitGroup
	results := make([]health, len(jobs))
	addrs := make([][]netip.Addr, len(jobs))
	for i, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addrs[i] = resolve(ctx, j.t.host)
			if !j.probe {
				return
			}
			started := time.Now()
			conn, err := (&net.Dialer{Timeout: j.timeout}).DialContext(ctx, "tcp", net.JoinHostPort(j.t.host, strconv.Itoa(int(j.t.port))))
			results[i].checkedAt = started.UnixMilli()
			results[i].state = networkv1.TargetHealthState_TARGET_HEALTH_STATE_UNHEALTHY
			if err == nil {
				_ = conn.Close()
				results[i].state = networkv1.TargetHealthState_TARGET_HEALTH_STATE_HEALTHY
				results[i].rttUs = uint32(min(time.Since(started).Microseconds(), 1<<31)) // #nosec G115 -- capped above.
			}
		}()
	}
	wg.Wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, j := range jobs {
		if len(addrs[i]) > 0 {
			j.t.addrs = addrs[i]
		}
		if !j.probe {
			continue
		}
		if results[i].state == networkv1.TargetHealthState_TARGET_HEALTH_STATE_UNHEALTHY {
			results[i].failures = j.t.health.failures + 1
		}
		j.t.health = results[i]
	}
}

func resolve(ctx context.Context, host string) []netip.Addr {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr.Unmap()}
	}
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	found, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil
	}
	for i := range found {
		found[i] = found[i].Unmap()
	}
	return found
}

func hasTCP(forward *networkv1.KernelForward) bool {
	for _, protocol := range forward.GetProtocols() {
		if protocol == "tcp" {
			return true
		}
	}
	return false
}

// sync replaces the table when its rules changed, seeding the counters
// with their current values.
func (m *Manager) sync() error {
	m.mu.Lock()
	rules, v6 := render(m.forwards, m.targets)
	if rules == m.applied {
		m.mu.Unlock()
		return nil
	}
	ids := make([]string, 0, len(m.forwards))
	for _, forward := range m.forwards {
		ids = append(ids, forward.GetId())
	}
	m.mu.Unlock()
	err := m.enableForwarding(v6)
	if err == nil {
		_, err = m.nft(script(rules, ids, m.counters()), "-f", "-")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err = err; err == nil {
		m.applied = rules
	}
	return err
}

// enableForwarding turns IPv4 forwarding on; IPv6 forwarding changes how
// the host takes router advertisements, so it is the operator's to turn
// on.
func (m *Manager) enableForwarding(v6 bool) error {
	proc := m.Proc
	if proc == "" {
		proc = "/proc/sys"
	}
	if err := os.WriteFile(proc+"/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil { // #nosec G306 -- a sysctl file.
		return fmt.Errorf("enable IPv4 forwarding: %w", err)
	}
	if v6 {
		if on, _ := os.ReadFile(proc + "/net/ipv6/conf/all/forwarding"); strings.TrimSpace(string(on)) != "1" {
			return fmt.Errorf("an IPv6 target needs net.ipv6.conf.all.forwarding=1 on this host")
		}
	}
	return nil
}

func counterName(direction, id string) string {
	return direction + "_" + strings.ReplaceAll(id, "-", "_")
}

type counter struct{ Packets, Bytes uint64 }

// counters reads the table's counters by name; none without the table.
func (m *Manager) counters() map[string]counter {
	out, err := m.nft("", "-j", "list", "counters", "table", "inet", Table)
	if err != nil {
		return nil
	}
	var listed struct {
		Nftables []struct {
			Counter *struct {
				Name    string `json:"name"`
				Packets uint64 `json:"packets"`
				Bytes   uint64 `json:"bytes"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if json.Unmarshal(out, &listed) != nil {
		return nil
	}
	counters := map[string]counter{}
	for _, item := range listed.Nftables {
		if c := item.Counter; c != nil {
			counters[c.Name] = counter{c.Packets, c.Bytes}
		}
	}
	return counters
}

// Status answers each forward as a port forward of its route.
func (m *Manager) Status() []*networkv1.PortForwardStatus {
	counters := map[string]counter{}
	m.mu.Lock()
	running := len(m.forwards) > 0
	m.mu.Unlock()
	if running {
		counters = m.counters()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*networkv1.PortForwardStatus, 0, len(m.forwards))
	for _, forward := range m.forwards {
		status := &networkv1.PortForwardStatus{Id: forward.GetId(), State: networkv1.ComponentState_COMPONENT_STATE_APPLIED,
			UpBytes: counters[counterName("u", forward.GetId())].Bytes, DownBytes: counters[counterName("d", forward.GetId())].Bytes}
		if m.err != nil {
			status.State, status.Detail = networkv1.ComponentState_COMPONENT_STATE_ERROR, truncate(m.err.Error())
		}
		for _, t := range m.targets[forward.GetId()] {
			status.Targets = append(status.Targets, &networkv1.ForwardTargetHealth{Host: t.host, Port: t.port, State: t.health.state,
				ConsecutiveFailures: t.health.failures, RttUs: t.health.rttUs, CheckedAtUnixMs: t.health.checkedAt})
		}
		out = append(out, status)
	}
	return out
}

func truncate(text string) string {
	if len(text) > 512 {
		return text[:512]
	}
	return text
}

func (m *Manager) nft(stdin string, args ...string) ([]byte, error) {
	if m.NFT != nil {
		return m.NFT(stdin, args...)
	}
	cmd := exec.Command("nft", args...) // #nosec G204 -- fixed binary, arguments built here.
	cmd.Stdin = strings.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// script is the whole table: rules with the counters declared first.
func script(rules string, ids []string, counters map[string]counter) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\ntable inet %s {\n", Table, Table, Table)
	for _, id := range ids {
		for _, direction := range []string{"u", "d"} {
			name := counterName(direction, id)
			c := counters[name]
			fmt.Fprintf(&b, "\tcounter %s { packets %d bytes %d }\n", name, c.Packets, c.Bytes)
		}
	}
	b.WriteString(rules)
	b.WriteString("}\n")
	return b.String()
}

// render answers the table's chains, and whether a target is IPv6.
func render(forwards []*networkv1.KernelForward, targets map[string][]*target) (string, bool) {
	var pre, post, fwd strings.Builder
	v6 := false
	for _, forward := range forwards {
		id, port := forward.GetId(), forward.GetListen().GetPort()
		l4 := "meta l4proto " + strings.Join(forward.GetProtocols(), "")
		if len(forward.GetProtocols()) > 1 {
			l4 = "meta l4proto { tcp, udp }"
		}
		listen, _ := netip.ParseAddr(forward.GetListen().GetAddress())
		listen = listen.Unmap()
		for _, family := range []string{"ip", "ip6"} {
			if !listen.IsUnspecified() && (listen.Is4() != (family == "ip")) {
				continue
			}
			backends := backends(forward, targets[id], family == "ip6")
			if len(backends) == 0 {
				continue
			}
			v6 = v6 || family == "ip6"
			match := l4 + " th dport " + strconv.Itoa(int(port)) + " fib daddr type local"
			if !listen.IsUnspecified() {
				match = family + " daddr " + listen.String() + " " + match
			}
			fmt.Fprintf(&pre, "\t\t%s dnat %s %s\n", match, family, dnatTo(family, forward.GetPolicy().GetBalance(), backends))
		}
		original := l4 + " ct status dnat ct original proto-dst " + strconv.Itoa(int(port))
		fmt.Fprintf(&post, "\t\t%s masquerade\n", original)
		fmt.Fprintf(&fwd, "\t\t%s ct direction original counter name %s\n", original, counterName("u", id))
		fmt.Fprintf(&fwd, "\t\t%s ct direction reply counter name %s\n", original, counterName("d", id))
	}
	return "\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n" + pre.String() + "\t}\n" +
		"\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n" + post.String() + "\t}\n" +
		"\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n" + fwd.String() + "\t}\n", v6
}

type backend struct {
	addr   netip.Addr
	port   uint32
	weight uint32
}

// backends answers the forward's targets of a family to send to: the
// healthy and unchecked ones, or every one while none is; failover keeps
// the first by priority.
func backends(forward *networkv1.KernelForward, targets []*target, v6 bool) []backend {
	var up []*target
	for _, t := range targets {
		if t.health.state != networkv1.TargetHealthState_TARGET_HEALTH_STATE_UNHEALTHY {
			up = append(up, t)
		}
	}
	if len(up) == 0 {
		up = targets
	}
	var out []backend
	if forward.GetPolicy().GetBalance() == "failover" {
		up = append([]*target(nil), up...)
		sort.SliceStable(up, func(i, j int) bool { return up[i].priority < up[j].priority })
	}
	for _, t := range up {
		for _, addr := range t.addrs {
			if addr.Is6() == v6 {
				out = append(out, backend{addr, t.port, t.weight})
				break
			}
		}
		if len(out) > 0 && forward.GetPolicy().GetBalance() == "failover" {
			break
		}
	}
	return out
}

func endpoint(family string, b backend) string {
	if family == "ip6" {
		return "[" + b.addr.String() + "]:" + strconv.Itoa(int(b.port))
	}
	return b.addr.String() + ":" + strconv.Itoa(int(b.port))
}

// dnatTo answers the target of a dnat statement: one backend, or a map
// from a balancing number to address and port.
func dnatTo(family, balance string, backends []backend) string {
	if len(backends) == 1 {
		return "to " + endpoint(family, backends[0])
	}
	var entries []string
	for _, b := range backends {
		for range min(b.weight, maxEntries) {
			if len(entries) < maxEntries {
				entries = append(entries, b.addr.String()+" . "+strconv.Itoa(int(b.port)))
			}
		}
	}
	n := strconv.Itoa(len(entries))
	selector := "numgen inc mod " + n
	switch balance {
	case "random":
		selector = "numgen random mod " + n
	case "ip_hash":
		selector = "jhash " + family + " saddr mod " + n
	}
	items := make([]string, len(entries))
	for i, entry := range entries {
		items[i] = strconv.Itoa(i) + " : " + entry
	}
	return "addr . port to " + selector + " map { " + strings.Join(items, ", ") + " }"
}
