package wireguard

import (
	"crypto/ecdh"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
	vCore "github.com/AnixOps/anix-agent/v5/core"
)

var _ vCore.Core = (*WireGuard)(nil)
var _ vCore.OnlineDeviceProvider = (*WireGuard)(nil)
var _ vCore.RuntimeHealthProvider = (*WireGuard)(nil)
var _ vCore.RateLimitUpdater = (*WireGuard)(nil)
var _ vCore.TrafficRollbacker = (*WireGuard)(nil)

type commandExecutor interface {
	Run(name string, args ...string) error
	Output(name string, args ...string) ([]byte, error)
}

type osExecutor struct{}

func (osExecutor) Run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (osExecutor) Output(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.Output()
}

type WireGuard struct {
	cfg      *conf.WireGuardConfig
	executor commandExecutor
	mu       sync.Mutex
	nodes    map[string]*nodeState
	traffic  map[string]map[string]trafficPair
}

type nodeState struct {
	tag                   string
	iface                 string
	info                  *panel.NodeInfo
	users                 map[string]panel.UserInfo
	applyMu               sync.Mutex
	runtimeMu             sync.RWMutex
	nodeSpeedLimit        int
	tcConfigured          bool
	runtimeHealthy        bool
	runtimeError          string
	cfgPath               string
	reportMinTrafficBytes int64
}

type trafficPair struct {
	upload   int64
	download int64
}

func init() {
	vCore.RegisterCore("wireguard", New)
}

func New(c *conf.CoreConfig) (vCore.Core, error) {
	cfg := conf.NewWireGuardConfig()
	if c != nil && c.WireGuardConfig != nil {
		cfg = c.WireGuardConfig
	}
	return &WireGuard{
		cfg:      cfg,
		executor: osExecutor{},
		nodes:    make(map[string]*nodeState),
		traffic:  make(map[string]map[string]trafficPair),
	}, nil
}

func (w *WireGuard) Start() error { return nil }

func (w *WireGuard) Close() error {
	w.mu.Lock()
	tags := make([]string, 0, len(w.nodes))
	for tag := range w.nodes {
		tags = append(tags, tag)
	}
	w.mu.Unlock()

	var errs []error
	for _, tag := range tags {
		if err := w.DelNode(tag); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (w *WireGuard) AddNode(tag string, info *panel.NodeInfo, config *conf.Options) error {
	if err := validateWireGuardNode(info); err != nil {
		return err
	}

	w.mu.Lock()
	if _, exists := w.nodes[tag]; exists {
		w.mu.Unlock()
		return fmt.Errorf("wireguard node %q already exists", tag)
	}
	state := &nodeState{
		tag:            tag,
		iface:          interfaceName(tag),
		info:           info,
		users:          make(map[string]panel.UserInfo),
		runtimeHealthy: true,
		cfgPath:        filepath.Join(w.cfg.RuntimeDir, interfaceName(tag)+".conf"),
	}
	if config != nil {
		state.reportMinTrafficBytes = config.ReportMinTraffic * 1024
		state.nodeSpeedLimit = speedLimitMbpsToBytesPerSecond(config.LimitConfig.SpeedLimit)
	}
	w.nodes[tag] = state
	w.mu.Unlock()

	if err := w.apply(state); err != nil {
		w.cleanupPeerRateLimits(state)
		_ = os.Remove(state.cfgPath)
		_ = w.executor.Run(w.cfg.IPPath, "link", "delete", state.iface)
		w.mu.Lock()
		delete(w.nodes, tag)
		delete(w.traffic, tag)
		w.mu.Unlock()
		return err
	}
	return nil
}

func (w *WireGuard) DelNode(tag string) error {
	w.mu.Lock()
	state, ok := w.nodes[tag]
	w.mu.Unlock()
	if !ok {
		return vCore.ErrNodeNotFound
	}
	state.applyMu.Lock()
	defer state.applyMu.Unlock()
	w.mu.Lock()
	if current, exists := w.nodes[tag]; !exists || current != state {
		w.mu.Unlock()
		return vCore.ErrNodeNotFound
	}
	delete(w.nodes, tag)
	delete(w.traffic, tag)
	w.mu.Unlock()
	w.cleanupPeerRateLimits(state)
	_ = os.Remove(state.cfgPath)
	return w.executor.Run(w.cfg.IPPath, "link", "delete", state.iface)
}

func (w *WireGuard) AddUsers(p *vCore.AddUsersParams) (int, error) {
	if p == nil {
		return 0, errors.New("wireguard add users params is nil")
	}
	w.mu.Lock()
	state, ok := w.nodes[p.Tag]
	w.mu.Unlock()
	if !ok {
		return 0, errors.New("the node is not have")
	}
	state.applyMu.Lock()
	defer state.applyMu.Unlock()
	w.mu.Lock()
	if current, exists := w.nodes[p.Tag]; !exists || current != state {
		w.mu.Unlock()
		return 0, errors.New("the node is not have")
	}
	previous := cloneWireGuardUsers(state.users)
	for _, user := range p.Users {
		if err := validateWireGuardUser(user); err != nil {
			w.mu.Unlock()
			return 0, err
		}
		state.users[user.Uuid] = user
	}
	w.mu.Unlock()
	if err := w.applyLocked(state); err != nil {
		w.mu.Lock()
		state.users = previous
		w.mu.Unlock()
		_ = w.applyLocked(state)
		return 0, err
	}
	return len(p.Users), nil
}

func (w *WireGuard) DelUsers(users []panel.UserInfo, tag string, _ *panel.NodeInfo) error {
	w.mu.Lock()
	state, ok := w.nodes[tag]
	w.mu.Unlock()
	if !ok {
		return errors.New("the node is not have")
	}
	state.applyMu.Lock()
	defer state.applyMu.Unlock()
	w.mu.Lock()
	if current, exists := w.nodes[tag]; !exists || current != state {
		w.mu.Unlock()
		return errors.New("the node is not have")
	}
	previous := cloneWireGuardUsers(state.users)
	for _, user := range users {
		delete(state.users, user.Uuid)
	}
	w.mu.Unlock()
	if err := w.applyLocked(state); err != nil {
		w.mu.Lock()
		state.users = previous
		w.mu.Unlock()
		_ = w.applyLocked(state)
		return err
	}
	return nil
}

// UpdateUserRateLimit refreshes the Linux peer shaping rule after the panel
// limiter changes a user's effective speed. It is intentionally optional on
// the core interface so existing proxy cores keep their current hooks.
func (w *WireGuard) UpdateUserRateLimit(tag, uuid string, speedLimit int) error {
	w.mu.Lock()
	state, ok := w.nodes[tag]
	w.mu.Unlock()
	if !ok {
		return errors.New("the node is not have")
	}
	state.applyMu.Lock()
	defer state.applyMu.Unlock()
	w.mu.Lock()
	if current, exists := w.nodes[tag]; !exists || current != state {
		w.mu.Unlock()
		return errors.New("the node is not have")
	}
	user, ok := state.users[uuid]
	if !ok {
		w.mu.Unlock()
		return fmt.Errorf("wireguard user %q is not have", uuid)
	}
	if user.SpeedLimit == speedLimit {
		w.mu.Unlock()
		return nil
	}
	previous := cloneWireGuardUsers(state.users)
	user.SpeedLimit = speedLimit
	state.users[uuid] = user
	w.mu.Unlock()
	if err := w.applyLocked(state); err != nil {
		w.mu.Lock()
		state.users = previous
		w.mu.Unlock()
		_ = w.applyLocked(state)
		return err
	}
	return nil
}

func (w *WireGuard) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	w.mu.Lock()
	state, ok := w.nodes[tag]
	if !ok {
		w.mu.Unlock()
		return nil, errors.New("the node is not have")
	}
	publicKeyToUID := make(map[string]int, len(state.users))
	for _, user := range state.users {
		publicKeyToUID[user.WireGuardPublicKey] = user.Id
	}
	w.mu.Unlock()

	out, err := w.executor.Output(w.cfg.WGPath, "show", state.iface, "transfer")
	if err != nil {
		return nil, err
	}
	current := parseTransferOutput(out)

	w.mu.Lock()
	defer w.mu.Unlock()
	previous := w.traffic[tag]
	if previous == nil {
		previous = make(map[string]trafficPair)
		w.traffic[tag] = previous
	}

	trafficSlice := make([]panel.UserTraffic, 0, len(current))
	for publicKey, now := range current {
		uid := publicKeyToUID[publicKey]
		if uid == 0 {
			continue
		}
		report := now
		if reset {
			last := previous[publicKey]
			report.upload -= last.upload
			report.download -= last.download
			previous[publicKey] = now
		}
		if report.upload < 0 || report.download < 0 {
			report = now
		}
		if report.upload+report.download <= state.reportMinTrafficBytes {
			continue
		}
		trafficSlice = append(trafficSlice, panel.UserTraffic{
			UID:      uid,
			Upload:   report.upload,
			Download: report.download,
		})
	}
	if len(trafficSlice) == 0 {
		return nil, nil
	}
	return trafficSlice, nil
}

// RollbackUserTrafficSlice moves the WireGuard traffic cursor back by the
// report that the panel rejected. The next sample then includes the failed
// interval instead of silently losing billable traffic.
func (w *WireGuard) RollbackUserTrafficSlice(tag string, traffic []panel.UserTraffic) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	state, ok := w.nodes[tag]
	if !ok {
		return errors.New("the node is not have")
	}
	uidToPublicKey := make(map[int]string, len(state.users))
	for _, user := range state.users {
		uidToPublicKey[user.Id] = user.WireGuardPublicKey
	}
	previous := w.traffic[tag]
	for _, report := range traffic {
		publicKey, ok := uidToPublicKey[report.UID]
		if !ok {
			continue
		}
		cursor := previous[publicKey]
		cursor.upload -= report.Upload
		cursor.download -= report.Download
		if cursor.upload < 0 {
			cursor.upload = 0
		}
		if cursor.download < 0 {
			cursor.download = 0
		}
		previous[publicKey] = cursor
	}
	return nil
}

func (w *WireGuard) GetOnlineDevice(tag string) ([]panel.OnlineUser, error) {
	w.mu.Lock()
	state, ok := w.nodes[tag]
	if !ok {
		w.mu.Unlock()
		return nil, errors.New("the node is not have")
	}
	publicKeyToUID := make(map[string]int, len(state.users))
	for _, user := range state.users {
		publicKeyToUID[user.WireGuardPublicKey] = user.Id
	}
	iface := state.iface
	w.mu.Unlock()

	out, err := w.executor.Output(w.cfg.WGPath, "show", iface, "dump")
	if err != nil {
		return nil, err
	}
	return parseDumpOnline(out, publicKeyToUID, time.Now().Unix(), w.cfg.OnlineHandshakeTimeoutSeconds), nil
}

func (w *WireGuard) Protocols() []string {
	return []string{"wireguard"}
}

func (w *WireGuard) Type() string {
	return "wireguard"
}

func (w *WireGuard) RuntimeHealth(tag string) (bool, string) {
	w.mu.Lock()
	state, ok := w.nodes[tag]
	w.mu.Unlock()
	if !ok {
		return false, "wireguard node is not running"
	}
	state.runtimeMu.RLock()
	defer state.runtimeMu.RUnlock()
	return state.runtimeHealthy, state.runtimeError
}

func (w *WireGuard) apply(state *nodeState) error {
	state.applyMu.Lock()
	defer state.applyMu.Unlock()
	return w.applyLocked(state)
}

func (w *WireGuard) applyLocked(state *nodeState) error {
	if err := os.MkdirAll(w.cfg.RuntimeDir, 0700); err != nil {
		return err
	}
	cfg := renderConfig(state)
	if err := os.WriteFile(state.cfgPath, []byte(cfg), 0600); err != nil {
		return err
	}

	if err := w.executor.Run(w.cfg.IPPath, "link", "show", state.iface); err != nil {
		if err := w.executor.Run(w.cfg.IPPath, "link", "add", state.iface, "type", "wireguard"); err != nil {
			return err
		}
	}

	n := state.info.WireGuard
	if err := w.executor.Run(w.cfg.IPPath, "address", "flush", "dev", state.iface); err != nil {
		return err
	}
	if err := w.executor.Run(w.cfg.IPPath, "address", "add", n.ServerAddress, "dev", state.iface); err != nil {
		return err
	}
	if err := w.executor.Run(w.cfg.IPPath, "link", "set", "mtu", strconv.Itoa(wireGuardMTU(n)), "dev", state.iface); err != nil {
		return err
	}
	if err := w.executor.Run(w.cfg.WGPath, "setconf", state.iface, state.cfgPath); err != nil {
		return err
	}
	if err := w.executor.Run(w.cfg.IPPath, "link", "set", "up", "dev", state.iface); err != nil {
		return err
	}
	if err := w.applyPeerRateLimits(state); err != nil {
		return err
	}
	state.setRuntimeHealth(true, "")
	return nil
}

func (state *nodeState) setRuntimeHealth(healthy bool, message string) {
	state.runtimeMu.Lock()
	state.runtimeHealthy = healthy
	state.runtimeError = strings.TrimSpace(message)
	state.runtimeMu.Unlock()
}

func renderConfig(state *nodeState) string {
	n := state.info.WireGuard
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = " + n.ServerPrivateKey + "\n")
	b.WriteString("ListenPort = " + strconv.Itoa(state.info.Common.ServerPort) + "\n")

	users := make([]panel.UserInfo, 0, len(state.users))
	for _, user := range state.users {
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i].WireGuardPeerIP < users[j].WireGuardPeerIP
	})
	for _, user := range users {
		b.WriteString("\n[Peer]\n")
		b.WriteString("PublicKey = " + user.WireGuardPublicKey + "\n")
		if user.WireGuardPresharedKey != "" {
			b.WriteString("PresharedKey = " + user.WireGuardPresharedKey + "\n")
		}
		b.WriteString("AllowedIPs = " + peerAllowedIP(user.WireGuardPeerIP) + "\n")
	}
	return b.String()
}

func validateWireGuardUser(user panel.UserInfo) error {
	if strings.TrimSpace(user.Uuid) == "" {
		return errors.New("wireguard user uuid is required")
	}
	peerIP := strings.TrimSpace(user.WireGuardPeerIP)
	if peerIP == "" {
		return fmt.Errorf("wireguard peer_ip is required for user %s", user.Uuid)
	}
	if strings.TrimSpace(user.WireGuardPublicKey) == "" {
		return fmt.Errorf("wireguard public_key is required for user %s", user.Uuid)
	}
	if err := validateWireGuardKey(user.WireGuardPublicKey); err != nil {
		return fmt.Errorf("wireguard public_key for user %s is invalid: %w", user.Uuid, err)
	}
	if _, err := parseWireGuardPeerAddress(peerIP); err != nil {
		return fmt.Errorf("wireguard peer_ip for user %s is invalid: %w", user.Uuid, err)
	}
	if user.WireGuardPresharedKey != "" {
		if err := validateWireGuardKey(user.WireGuardPresharedKey); err != nil {
			return fmt.Errorf("wireguard preshared_key for user %s is invalid: %w", user.Uuid, err)
		}
	}
	return nil
}

func validateWireGuardNode(info *panel.NodeInfo) error {
	if info == nil || info.WireGuard == nil || info.Common == nil {
		return errors.New("wireguard node config is missing")
	}
	n := info.WireGuard
	// The relay (entry and exit nodes joined over gost) was removed with
	// gost; a node that still carries relay settings is refused.
	if hasWireGuardRelayConfig(n.Relay) {
		return errors.New("wireguard relay was removed (it ran on gost): clear the node's relay settings")
	}
	if strings.TrimSpace(n.ServerPrivateKey) == "" {
		return errors.New("wireguard server_private_key is required")
	}
	if err := validateWireGuardKey(n.ServerPrivateKey); err != nil {
		return fmt.Errorf("wireguard server_private_key is invalid: %w", err)
	}
	if n.ServerPublicKey != "" {
		if err := validateWireGuardKey(n.ServerPublicKey); err != nil {
			return fmt.Errorf("wireguard server_public_key is invalid: %w", err)
		}
		derived, err := wireGuardPublicKey(n.ServerPrivateKey)
		if err != nil || derived != n.ServerPublicKey {
			return errors.New("wireguard server_public_key does not match server_private_key")
		}
	}
	if strings.TrimSpace(n.ServerAddress) == "" {
		return errors.New("wireguard server_address is required")
	}
	serverPrefix, err := netip.ParsePrefix(strings.TrimSpace(n.ServerAddress))
	if err != nil {
		return fmt.Errorf("wireguard server_address is invalid: %w", err)
	}
	if serverPrefix.Addr() == serverPrefix.Masked().Addr() {
		return errors.New("wireguard server_address must not be the network address")
	}
	if strings.TrimSpace(n.CIDR) != "" {
		cidr, cidrErr := netip.ParsePrefix(strings.TrimSpace(n.CIDR))
		if cidrErr != nil || cidr.Bits() == 0 || (cidr.Addr().Is4() && cidr.Bits() > 30) || (cidr.Addr().Is6() && cidr.Bits() > 126) || cidr.Bits() != serverPrefix.Bits() || !cidr.Contains(serverPrefix.Addr()) {
			return fmt.Errorf("wireguard server_address is outside cidr %q", n.CIDR)
		}
		if cidr.Addr().Is4() && isWireGuardIPv4Broadcast(cidr, serverPrefix.Addr()) {
			return errors.New("wireguard server_address must not be the IPv4 broadcast address")
		}
	}
	if info.Common.ServerPort < 1 || info.Common.ServerPort > 65535 {
		return fmt.Errorf("wireguard server_port is invalid: %d", info.Common.ServerPort)
	}
	if n.MTU != 0 && (n.MTU < 576 || n.MTU > 1500) {
		return fmt.Errorf("wireguard mtu is invalid: %d", n.MTU)
	}
	return nil
}

func isWireGuardIPv4Broadcast(prefix netip.Prefix, addr netip.Addr) bool {
	if !prefix.Addr().Is4() || prefix.Bits() >= 31 {
		return false
	}
	base := prefix.Masked().Addr().As4()
	value := addr.As4()
	baseValue := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	addrValue := uint32(value[0])<<24 | uint32(value[1])<<16 | uint32(value[2])<<8 | uint32(value[3])
	hostMask := uint32(^uint32(0) >> uint(prefix.Bits()))
	return addrValue == baseValue|hostMask
}

func validateWireGuardKey(value string) error {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != 32 {
		return errors.New("must be a standard base64 encoded 32-byte key")
	}
	return nil
}

func wireGuardPublicKey(value string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != 32 {
		return "", errors.New("invalid private key")
	}
	private, err := ecdh.X25519().NewPrivateKey(decoded)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()), nil
}

func parseWireGuardPeerAddress(value string) (netip.Addr, error) {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Addr{}, err
		}
		if (prefix.Addr().Is4() && prefix.Bits() != 32) || (prefix.Addr().Is6() && prefix.Bits() != 128) {
			return netip.Addr{}, errors.New("peer address must be a host address")
		}
		return prefix.Addr(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, err
	}
	return addr, nil
}

func cloneWireGuardUsers(users map[string]panel.UserInfo) map[string]panel.UserInfo {
	clone := make(map[string]panel.UserInfo, len(users))
	for uuid, user := range users {
		clone[uuid] = user
	}
	return clone
}

func (w *WireGuard) applyPeerRateLimits(state *nodeState) error {
	if state == nil {
		return nil
	}
	limits := make([]wireGuardPeerRate, 0, len(state.users))
	for _, user := range state.users {
		rate := effectiveWireGuardRate(state.nodeSpeedLimit, user.SpeedLimit)
		if rate <= 0 {
			continue
		}
		ip, err := parseWireGuardPeerAddress(user.WireGuardPeerIP)
		if err != nil {
			return err
		}
		limits = append(limits, wireGuardPeerRate{ip: ip, rateMbps: rate})
	}
	if len(limits) == 0 {
		if state.tcConfigured {
			w.cleanupPeerRateLimits(state)
		}
		return nil
	}

	tcPath := w.cfg.TCPath
	if tcPath == "" {
		tcPath = "tc"
	}
	parentRate := state.nodeSpeedLimit
	if parentRate <= 0 {
		for _, limit := range limits {
			parentRate += limit.rateMbps
		}
	}
	if parentRate <= 0 {
		return nil
	}
	state.tcConfigured = true
	if err := w.executor.Run(tcPath, "qdisc", "replace", "dev", state.iface, "root", "handle", "1:", "htb", "default", "1"); err != nil {
		return err
	}
	if err := w.executor.Run(tcPath, "class", "replace", "dev", state.iface, "parent", "1:", "classid", "1:1", "htb", "rate", tcRate(parentRate), "ceil", tcRate(parentRate)); err != nil {
		return err
	}
	if err := w.executor.Run(tcPath, "qdisc", "replace", "dev", state.iface, "handle", "ffff:", "ingress"); err != nil {
		return err
	}
	for index, limit := range limits {
		classID := strconv.Itoa(index + 10)
		if err := w.executor.Run(tcPath, "class", "replace", "dev", state.iface, "parent", "1:1", "classid", "1:"+classID, "htb", "rate", tcRate(limit.rateMbps), "ceil", tcRate(limit.rateMbps)); err != nil {
			return err
		}
		pref := 1000 + index*4
		if err := w.applyWireGuardEgressFilter(tcPath, state.iface, limit.ip, pref, classID); err != nil {
			return err
		}
		if err := w.applyWireGuardIngressFilter(tcPath, state.iface, limit.ip, pref+2, limit.rateMbps); err != nil {
			return err
		}
	}
	return nil
}

type wireGuardPeerRate struct {
	ip       netip.Addr
	rateMbps int
}

func (w *WireGuard) applyWireGuardEgressFilter(path, iface string, ip netip.Addr, pref int, classID string) error {
	protocol := "ip"
	match := "ip"
	if ip.Is6() {
		protocol = "ipv6"
		match = "ip6"
	}
	address := ip.String()
	mask := "/32"
	if ip.Is6() {
		mask = "/128"
	}
	for offset, direction := range []string{"src", "dst"} {
		if err := w.executor.Run(path, "filter", "replace", "dev", iface, "parent", "1:", "protocol", protocol, "pref", strconv.Itoa(pref+offset), "u32", "match", match, direction, address+mask, "flowid", "1:"+classID); err != nil {
			return err
		}
	}
	return nil
}

func (w *WireGuard) applyWireGuardIngressFilter(path, iface string, ip netip.Addr, pref, rateMbps int) error {
	protocol := "ip"
	match := "ip"
	if ip.Is6() {
		protocol = "ipv6"
		match = "ip6"
	}
	address := ip.String()
	mask := "/32"
	if ip.Is6() {
		mask = "/128"
	}
	return w.executor.Run(path, "filter", "replace", "dev", iface, "parent", "ffff:", "protocol", protocol, "pref", strconv.Itoa(pref), "u32", "match", match, "src", address+mask, "police", "rate", tcRate(rateMbps), "burst", "64k", "conform-exceed", "drop")
}

func (w *WireGuard) cleanupPeerRateLimits(state *nodeState) {
	if state == nil || !state.tcConfigured {
		return
	}
	path := w.cfg.TCPath
	if path == "" {
		path = "tc"
	}
	_ = w.executor.Run(path, "qdisc", "del", "dev", state.iface, "root")
	_ = w.executor.Run(path, "qdisc", "del", "dev", state.iface, "ingress")
	state.tcConfigured = false
}

func effectiveWireGuardRate(nodeRate, userRate int) int {
	if nodeRate > 0 && userRate > 0 {
		if nodeRate < userRate {
			return nodeRate
		}
		return userRate
	}
	if nodeRate > 0 {
		return nodeRate
	}
	return userRate
}

func tcRate(mbps int) string {
	return strconv.FormatInt(int64(mbps)*8, 10) + "bit"
}

func speedLimitMbpsToBytesPerSecond(mbps int) int {
	if mbps <= 0 {
		return 0
	}
	return int((int64(mbps) * 1000000) / 8)
}

func interfaceName(tag string) string {
	sum := sha1.Sum([]byte(tag))
	return "wg" + hex.EncodeToString(sum[:])[:13]
}

func wireGuardMTU(n *panel.WireGuardNode) int {
	if n != nil && n.MTU > 0 {
		return n.MTU
	}
	return 1280
}

func hasWireGuardRelayConfig(relay panel.WireGuardRelay) bool {
	return strings.TrimSpace(relay.Backend) != "" ||
		len(relay.NetworkPolicy.Paths) > 0 ||
		strings.TrimSpace(relay.Mode) != "" ||
		strings.TrimSpace(relay.Role) != "" ||
		strings.TrimSpace(relay.Server) != "" ||
		relay.ServerPort != 0 ||
		strings.TrimSpace(relay.TunName) != "" ||
		relay.TunPort != 0 ||
		strings.TrimSpace(relay.TunAddress) != "" ||
		strings.TrimSpace(relay.EntryTunAddress) != "" ||
		strings.TrimSpace(relay.ExitTunAddress) != "" ||
		strings.TrimSpace(relay.OutboundIface) != "" ||
		relay.RoutingTable != 0 ||
		relay.RoutingPriority != 0 ||
		relay.WSSCompat ||
		strings.TrimSpace(relay.WSSPath) != "" ||
		relay.WSSSecure ||
		strings.TrimSpace(relay.WSSServerName) != "" ||
		strings.TrimSpace(relay.WSSCAFile) != "" ||
		strings.TrimSpace(relay.WSSCertFile) != "" ||
		strings.TrimSpace(relay.WSSKeyFile) != "" ||
		relay.ExitNAT ||
		relay.EntryStats
}

func peerAllowedIP(peerIP string) string {
	peerIP = strings.TrimSpace(peerIP)
	if strings.Contains(peerIP, "/") {
		return peerIP
	}
	if strings.Contains(peerIP, ":") {
		return peerIP + "/128"
	}
	return peerIP + "/32"
}

func parseTransferOutput(out []byte) map[string]trafficPair {
	result := make(map[string]trafficPair)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		rx, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		tx, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			continue
		}
		result[fields[0]] = trafficPair{
			upload:   rx,
			download: tx,
		}
	}
	return result
}

func parseDumpOnline(out []byte, publicKeyToUID map[string]int, now, timeoutSeconds int64) []panel.OnlineUser {
	if timeoutSeconds <= 0 {
		return nil
	}
	online := make([]panel.OnlineUser, 0)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		uid := publicKeyToUID[fields[0]]
		if uid == 0 {
			continue
		}
		ip := endpointIP(fields[2])
		if ip == "" {
			continue
		}
		latestHandshake, err := strconv.ParseInt(fields[4], 10, 64)
		if err != nil || latestHandshake <= 0 {
			continue
		}
		if now >= latestHandshake && now-latestHandshake > timeoutSeconds {
			continue
		}
		online = append(online, panel.OnlineUser{UID: uid, IP: ip})
	}
	return online
}

func endpointIP(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || endpoint == "(none)" {
		return ""
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err == nil {
		return strings.Trim(host, "[]")
	}
	if strings.HasPrefix(endpoint, "[") {
		if end := strings.Index(endpoint, "]"); end > 1 {
			return endpoint[1:end]
		}
	}
	if strings.Count(endpoint, ":") == 1 {
		host, _, _ = strings.Cut(endpoint, ":")
		return host
	}
	return strings.Trim(endpoint, "[]")
}
