package wireguard

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
)

type networkPathRuntime struct {
	name         string
	iface        string
	source       netip.Addr
	gateway      netip.Addr
	priority     int
	table        int
	rulePriority int
	failures     int
	successes    int
	healthy      bool
}

type networkPolicyRuntime struct {
	mu             sync.Mutex
	paths          []*networkPathRuntime
	server         netip.Addr
	serverPort     int
	active         int
	activeTable    int
	activePriority int
	interval       time.Duration
	timeout        time.Duration
	failureLimit   int
	recoveryLimit  int
	failbackDelay  time.Duration
	lastSwitch     time.Time
	stop           chan struct{}
	stopped        chan struct{}
}

func validateNetworkPolicyConfig(node *panel.WireGuardNode) error {
	policy := node.Relay.NetworkPolicy
	if len(policy.Paths) == 0 {
		return nil
	}
	mode, err := wireGuardGostMode(node)
	if err != nil {
		return err
	}
	if mode != "relay+wss" {
		return errors.New("wireguard network_policy v1 requires a WSS relay for TCP health checks")
	}
	if policy.Version != 0 && policy.Version != 1 {
		return fmt.Errorf("wireguard network_policy version is not supported: %d", policy.Version)
	}
	if strategy := strings.ToLower(strings.TrimSpace(policy.Strategy)); strategy != "" && strategy != "failover" {
		return fmt.Errorf("wireguard network_policy strategy is not supported: %q", policy.Strategy)
	}
	if _, err := netip.ParseAddr(strings.TrimSpace(node.Relay.Server)); err != nil {
		return errors.New("wireguard network_policy requires a literal relay server IP")
	}
	seen := make(map[string]struct{}, len(policy.Paths))
	for _, path := range policy.Paths {
		name := strings.TrimSpace(path.Name)
		iface := strings.TrimSpace(path.Interface)
		source, sourceErr := netip.ParseAddr(strings.TrimSpace(path.Source))
		gateway, gatewayErr := netip.ParseAddr(strings.TrimSpace(path.Gateway))
		if name == "" || iface == "" || len(iface) > 15 || strings.ContainsAny(iface, " \t\r\n/\\") {
			return fmt.Errorf("wireguard network path %q has an invalid name or interface", name)
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("wireguard network path name is duplicated: %q", name)
		}
		seen[name] = struct{}{}
		if sourceErr != nil || gatewayErr != nil || source.Is4() != gateway.Is4() {
			return fmt.Errorf("wireguard network path %q has invalid source/gateway", name)
		}
		if path.Priority < 0 || path.RoutingTable < 0 || path.RulePriority < 0 || path.RulePriority >= 32766 {
			return fmt.Errorf("wireguard network path %q has invalid routing values", name)
		}
	}
	return nil
}

func (w *WireGuard) applyNetworkPolicy(state *nodeState) error {
	configured := state.info.WireGuard.Relay.NetworkPolicy
	if len(configured.Paths) == 0 {
		w.cleanupNetworkPolicy(state)
		return nil
	}
	desired, err := newNetworkPolicyRuntime(state.tag, state.info.WireGuard.Relay)
	if err != nil {
		return err
	}
	if sameNetworkPolicy(state.networkPolicy, desired) {
		return nil
	}
	w.cleanupNetworkPolicy(state)
	for _, path := range desired.paths {
		if err := w.applySourcePath(path); err != nil {
			w.cleanupNetworkPolicyRuntime(desired)
			return fmt.Errorf("apply network path %q: %w", path.name, err)
		}
	}
	if err := w.applyActivePath(desired, desired.active); err != nil {
		w.cleanupNetworkPolicyRuntime(desired)
		return fmt.Errorf("activate network path %q: %w", desired.paths[desired.active].name, err)
	}
	state.networkPolicy = desired
	go w.watchNetworkPolicy(state, desired)
	slog.Info("wireguard relay network path activated", "tag", state.tag, "path", desired.paths[desired.active].name)
	return nil
}

func newNetworkPolicyRuntime(tag string, relay panel.WireGuardRelay) (*networkPolicyRuntime, error) {
	server, err := netip.ParseAddr(strings.TrimSpace(relay.Server))
	if err != nil {
		return nil, errors.New("wireguard network_policy requires a literal relay server IP")
	}
	policy := relay.NetworkPolicy
	paths := make([]*networkPathRuntime, 0, len(policy.Paths))
	for index, item := range policy.Paths {
		source, sourceErr := netip.ParseAddr(strings.TrimSpace(item.Source))
		gateway, gatewayErr := netip.ParseAddr(strings.TrimSpace(item.Gateway))
		if sourceErr != nil || gatewayErr != nil || source.Is4() != gateway.Is4() {
			return nil, fmt.Errorf("wireguard network path %q has invalid source/gateway", item.Name)
		}
		table := item.RoutingTable
		if table <= 0 {
			table = networkPathTable(tag, index)
		}
		rulePriority := item.RulePriority
		if rulePriority <= 0 {
			rulePriority = networkPathRulePriority(tag, index)
		}
		paths = append(paths, &networkPathRuntime{
			name: strings.TrimSpace(item.Name), iface: strings.TrimSpace(item.Interface),
			source: source, gateway: gateway, priority: item.Priority,
			table: table, rulePriority: rulePriority, healthy: true,
		})
	}
	sort.SliceStable(paths, func(i, j int) bool { return paths[i].priority < paths[j].priority })
	active := -1
	for index, path := range paths {
		if path.source.Is4() == server.Is4() {
			active = index
			break
		}
	}
	if active < 0 {
		return nil, errors.New("wireguard network_policy has no path matching relay server address family")
	}
	health := policy.HealthCheck
	return &networkPolicyRuntime{
		paths: paths, server: server, serverPort: relay.ServerPort, active: active,
		activeTable:    positiveOr(policy.ActiveTable, networkActiveTable(tag)),
		activePriority: positiveOr(policy.ActivePriority, networkActivePriority(tag)),
		interval:       time.Duration(positiveOr(health.IntervalSeconds, 10)) * time.Second,
		timeout:        time.Duration(positiveOr(health.TimeoutSeconds, 3)) * time.Second,
		failureLimit:   positiveOr(health.FailureThreshold, 3),
		recoveryLimit:  positiveOr(health.RecoveryThreshold, 2),
		failbackDelay:  time.Duration(nonNegativeOr(health.FailbackDelaySeconds, 300)) * time.Second,
		lastSwitch:     time.Now(), stop: make(chan struct{}), stopped: make(chan struct{}),
	}, nil
}

func (w *WireGuard) applySourcePath(path *networkPathRuntime) error {
	family := ipFamilyFlag(path.source)
	_ = w.executor.Run(w.cfg.IPPath, family, "rule", "delete", "from", hostPrefix(path.source), "table", strconv.Itoa(path.table), "priority", strconv.Itoa(path.rulePriority))
	if err := w.executor.Run(w.cfg.IPPath, family, "route", "replace", "default", "via", path.gateway.String(), "dev", path.iface, "src", path.source.String(), "table", strconv.Itoa(path.table)); err != nil {
		return err
	}
	return w.executor.Run(w.cfg.IPPath, family, "rule", "add", "from", hostPrefix(path.source), "table", strconv.Itoa(path.table), "priority", strconv.Itoa(path.rulePriority))
}

func (w *WireGuard) applyActivePath(runtime *networkPolicyRuntime, index int) error {
	path := runtime.paths[index]
	family := ipFamilyFlag(runtime.server)
	if err := w.executor.Run(w.cfg.IPPath, family, "route", "replace", "default", "via", path.gateway.String(), "dev", path.iface, "src", path.source.String(), "table", strconv.Itoa(runtime.activeTable)); err != nil {
		return err
	}
	_ = w.executor.Run(w.cfg.IPPath, family, "rule", "delete", "to", hostPrefix(runtime.server), "table", strconv.Itoa(runtime.activeTable), "priority", strconv.Itoa(runtime.activePriority))
	if err := w.executor.Run(w.cfg.IPPath, family, "rule", "add", "to", hostPrefix(runtime.server), "table", strconv.Itoa(runtime.activeTable), "priority", strconv.Itoa(runtime.activePriority)); err != nil {
		return err
	}
	runtime.active = index
	runtime.lastSwitch = time.Now()
	return nil
}

func (w *WireGuard) watchNetworkPolicy(state *nodeState, runtime *networkPolicyRuntime) {
	defer close(runtime.stopped)
	ticker := time.NewTicker(runtime.interval)
	defer ticker.Stop()
	for {
		select {
		case <-runtime.stop:
			return
		case <-ticker.C:
			w.checkNetworkPaths(state, runtime)
		}
	}
}

func (w *WireGuard) checkNetworkPaths(state *nodeState, runtime *networkPolicyRuntime) {
	runtime.mu.Lock()
	for _, path := range runtime.paths {
		if path.source.Is4() != runtime.server.Is4() {
			continue
		}
		if probeNetworkPath(path, runtime.server, runtime.serverPort, runtime.timeout) == nil {
			path.failures = 0
			path.successes++
			if path.successes >= runtime.recoveryLimit {
				path.healthy = true
			}
		} else {
			path.successes = 0
			path.failures++
			if path.failures >= runtime.failureLimit {
				path.healthy = false
			}
		}
	}
	desired := runtime.active
	foundHealthy := false
	for index, path := range runtime.paths {
		if path.source.Is4() == runtime.server.Is4() && path.healthy {
			desired = index
			foundHealthy = true
			break
		}
	}
	if !foundHealthy {
		runtime.mu.Unlock()
		state.setRuntimeHealth(false, "all relay network paths are unhealthy")
		return
	}
	activeHealthy := runtime.paths[runtime.active].healthy
	if desired == runtime.active || (activeHealthy && desired < runtime.active && time.Since(runtime.lastSwitch) < runtime.failbackDelay) {
		runtime.mu.Unlock()
		return
	}
	runtime.mu.Unlock()
	state.applyMu.Lock()
	defer state.applyMu.Unlock()
	if state.networkPolicy != runtime {
		return
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if err := w.applyActivePath(runtime, desired); err != nil {
		state.setRuntimeHealth(false, fmt.Sprintf("network path switch failed: %v", err))
		return
	}
	state.setRuntimeHealth(false, "relay network path switched to "+runtime.paths[desired].name+", reconnecting")
	slog.Warn("wireguard relay network path switched", "tag", state.tag, "path", runtime.paths[desired].name)
	if state.gost != nil {
		_ = state.gost.Stop()
	}
}

func probeNetworkPath(path *networkPathRuntime, server netip.Addr, port int, timeout time.Duration) error {
	dialer := net.Dialer{Timeout: timeout}
	if path.source.Is4() {
		dialer.LocalAddr = &net.TCPAddr{IP: net.IP(path.source.AsSlice())}
	} else {
		dialer.LocalAddr = &net.TCPAddr{IP: net.IP(path.source.AsSlice()), Zone: path.iface}
	}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(server.String(), strconv.Itoa(port)))
	if err == nil {
		_ = conn.Close()
	}
	return err
}

func (w *WireGuard) cleanupNetworkPolicy(state *nodeState) {
	if state == nil || state.networkPolicy == nil {
		return
	}
	runtime := state.networkPolicy
	state.networkPolicy = nil
	close(runtime.stop)
	select {
	case <-runtime.stopped:
	case <-time.After(2 * time.Second):
	}
	w.cleanupNetworkPolicyRuntime(runtime)
}

func (w *WireGuard) cleanupNetworkPolicyRuntime(runtime *networkPolicyRuntime) {
	if runtime == nil {
		return
	}
	family := ipFamilyFlag(runtime.server)
	_ = w.executor.Run(w.cfg.IPPath, family, "rule", "delete", "to", hostPrefix(runtime.server), "table", strconv.Itoa(runtime.activeTable), "priority", strconv.Itoa(runtime.activePriority))
	_ = w.executor.Run(w.cfg.IPPath, family, "route", "flush", "table", strconv.Itoa(runtime.activeTable))
	for _, path := range runtime.paths {
		family = ipFamilyFlag(path.source)
		_ = w.executor.Run(w.cfg.IPPath, family, "rule", "delete", "from", hostPrefix(path.source), "table", strconv.Itoa(path.table), "priority", strconv.Itoa(path.rulePriority))
		_ = w.executor.Run(w.cfg.IPPath, family, "route", "flush", "table", strconv.Itoa(path.table))
	}
}

func sameNetworkPolicy(a, b *networkPolicyRuntime) bool {
	if a == nil || b == nil || a.server != b.server || a.serverPort != b.serverPort || a.activeTable != b.activeTable || a.activePriority != b.activePriority || len(a.paths) != len(b.paths) {
		return false
	}
	for index := range a.paths {
		x, y := a.paths[index], b.paths[index]
		if x.name != y.name || x.iface != y.iface || x.source != y.source || x.gateway != y.gateway || x.priority != y.priority || x.table != y.table || x.rulePriority != y.rulePriority {
			return false
		}
	}
	return a.interval == b.interval && a.timeout == b.timeout && a.failureLimit == b.failureLimit && a.recoveryLimit == b.recoveryLimit && a.failbackDelay == b.failbackDelay
}

func networkPathTable(tag string, index int) int {
	return 50000 + networkHash(tag+":path:"+strconv.Itoa(index))%10000
}
func networkPathRulePriority(tag string, index int) int {
	return 3000 + networkHash(tag+":source:"+strconv.Itoa(index))%3000
}
func networkActiveTable(tag string) int    { return 60000 + networkHash(tag+":active")%5000 }
func networkActivePriority(tag string) int { return 6000 + networkHash(tag+":active-priority")%2000 }
func networkHash(value string) int {
	sum := sha1Sum(value)
	return int(sum[0])<<8 | int(sum[1])
}

func networkPolicySignature(policy panel.WireGuardNetworkPolicy) string {
	encoded, _ := json.Marshal(policy)
	sum := sha1.Sum(encoded)
	return hex.EncodeToString(sum[:])
}
func sha1Sum(value string) [20]byte { return sha1.Sum([]byte(value)) }
func positiveOr(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}
func nonNegativeOr(value, fallback int) int {
	if value >= 0 {
		return value
	}
	return fallback
}
func ipFamilyFlag(addr netip.Addr) string {
	if addr.Is4() {
		return "-4"
	}
	return "-6"
}
func hostPrefix(addr netip.Addr) string {
	if addr.Is4() {
		return addr.String() + "/32"
	}
	return addr.String() + "/128"
}
