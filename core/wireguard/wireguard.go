package wireguard

import (
	"crypto/ecdh"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/conf"
	vCore "github.com/AnixOps/anix-agent/v4/core"
)

var _ vCore.Core = (*WireGuard)(nil)
var _ vCore.OnlineDeviceProvider = (*WireGuard)(nil)
var _ vCore.RuntimeHealthProvider = (*WireGuard)(nil)
var _ vCore.RateLimitUpdater = (*WireGuard)(nil)
var _ vCore.TrafficRollbacker = (*WireGuard)(nil)

type commandExecutor interface {
	Run(name string, args ...string) error
	Output(name string, args ...string) ([]byte, error)
	Start(name string, args ...string) (process, error)
}

type process interface {
	Stop() error
}

type processWaiter interface {
	Wait() error
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

func (osExecutor) Start(name string, args ...string) (process, error) {
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &osProcess{cmd: cmd}, nil
}

type osProcess struct {
	cmd      *exec.Cmd
	waitOnce sync.Once
	waitErr  error
}

func (p *osProcess) Wait() error {
	if p == nil || p.cmd == nil {
		return nil
	}
	p.waitOnce.Do(func() {
		p.waitErr = p.cmd.Wait()
	})
	return p.waitErr
}

func (p *osProcess) Stop() error {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	if err := p.cmd.Process.Kill(); err != nil {
		return err
	}
	return p.Wait()
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
	gost                  process
	gostWatchStop         chan struct{}
	gostRuntime           *gostRuntime
	networkPolicy         *networkPolicyRuntime
	runtimeHealthy        bool
	runtimeError          string
	cfgPath               string
	reportMinTrafficBytes int64
}

type trafficPair struct {
	upload   int64
	download int64
}

type gostRuntime struct {
	role                         string
	mode                         string
	server                       string
	serverPort                   int
	tunPort                      int
	tunName                      string
	tunAddress                   string
	entryTunIP                   string
	wireGuardIface               string
	mtu                          int
	sourceCIDR                   string
	routingTable                 int
	routingPriority              int
	exitNAT                      bool
	outboundIface                string
	wssPath                      string
	wssSecure                    bool
	wssServerName                string
	wssCAFile                    string
	wssCertFile                  string
	wssKeyFile                   string
	networkPolicySignature       string
	natRuleAdded                 bool
	forwardRuleAdded             bool
	reverseForwardRuleAdded      bool
	entryForwardRuleAdded        bool
	entryReverseForwardRuleAdded bool
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
		if state.gost != nil {
			w.cleanupGost(state)
		}
		w.cleanupNetworkPolicy(state)
		_ = os.Remove(state.cfgPath)
		if !isWireGuardExitNode(state.info) {
			_ = w.executor.Run(w.cfg.IPPath, "link", "delete", state.iface)
		}
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
	if state.gost != nil {
		w.cleanupGost(state)
	}
	w.cleanupNetworkPolicy(state)
	w.cleanupPeerRateLimits(state)
	_ = os.Remove(state.cfgPath)
	if isWireGuardExitNode(state.info) {
		return nil
	}
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
	if isWireGuardExitNode(state.info) {
		w.mu.Unlock()
		return len(p.Users), nil
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
	if isWireGuardExitNode(state.info) {
		w.mu.Unlock()
		return nil
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
	if isWireGuardExitNode(state.info) {
		w.mu.Unlock()
		return nil
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
	if isWireGuardExitNode(state.info) {
		w.mu.Unlock()
		return nil, nil
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
	if isWireGuardExitNode(state.info) {
		return nil
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
	if isWireGuardExitNode(state.info) {
		w.mu.Unlock()
		return nil, nil
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
	if isWireGuardExitNode(state.info) {
		w.cleanupPeerRateLimits(state)
		return w.applyGost(state)
	}
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
	return w.applyGost(state)
}

func isWireGuardExitNode(info *panel.NodeInfo) bool {
	return info != nil && info.WireGuard != nil && wireGuardRelayRole(info.WireGuard) == "exit"
}

func (w *WireGuard) applyGost(state *nodeState) error {
	n := state.info.WireGuard
	backend := wireGuardRelayBackend(n)
	if backend == "" {
		if err := w.cleanupGost(state); err != nil {
			return err
		}
		w.cleanupNetworkPolicy(state)
		state.setRuntimeHealth(true, "")
		return nil
	}
	if backend != "gost" {
		return fmt.Errorf("wireguard relay backend is not supported: %q", n.Relay.Backend)
	}
	if err := w.applyNetworkPolicy(state); err != nil {
		return err
	}

	role := wireGuardRelayRole(n)
	mode, err := wireGuardGostMode(n)
	if err != nil {
		return err
	}
	tunPort := n.Relay.TunPort
	if tunPort <= 0 {
		tunPort = 8421
	}
	tunName := strings.TrimSpace(n.Relay.TunName)
	if tunName == "" {
		tunName = gostTunName(state.tag)
	}
	sourceCIDR := strings.TrimSpace(n.CIDR)
	if sourceCIDR == "" {
		return errors.New("wireguard cidr is required for gost relay routing")
	}
	runtime := &gostRuntime{
		role:                   role,
		mode:                   mode,
		server:                 strings.TrimSpace(n.Relay.Server),
		serverPort:             n.Relay.ServerPort,
		tunPort:                tunPort,
		tunName:                tunName,
		tunAddress:             relayTunAddress(n, role),
		entryTunIP:             relayTunIP(n.Relay.EntryTunAddress),
		wireGuardIface:         state.iface,
		mtu:                    wireGuardMTU(n),
		sourceCIDR:             sourceCIDR,
		routingTable:           relayRoutingTable(state.tag, n.Relay.RoutingTable),
		routingPriority:        relayRoutingPriority(state.tag, n.Relay.RoutingPriority),
		exitNAT:                n.Relay.ExitNAT,
		outboundIface:          strings.TrimSpace(n.Relay.OutboundIface),
		wssPath:                wireGuardWSSPath(n),
		wssSecure:              n.Relay.WSSSecure,
		wssServerName:          strings.TrimSpace(n.Relay.WSSServerName),
		wssCAFile:              strings.TrimSpace(n.Relay.WSSCAFile),
		wssCertFile:            strings.TrimSpace(n.Relay.WSSCertFile),
		wssKeyFile:             strings.TrimSpace(n.Relay.WSSKeyFile),
		networkPolicySignature: networkPolicySignature(n.Relay.NetworkPolicy),
	}
	if state.gost != nil && sameGostRuntime(state.gostRuntime, runtime) {
		state.setRuntimeHealth(true, "")
		return nil
	}
	if err := w.cleanupGost(state); err != nil {
		return err
	}
	if err := w.enableIPv4Forwarding(); err != nil {
		return err
	}

	var proc process
	switch role {
	case "exit":
		proc, err = w.startGostExit(state, mode, tunName, tunPort)
		if err == nil {
			err = w.applyExitFirewall(runtime)
		}
	default:
		proc, err = w.startGostEntry(state, mode, tunName, tunPort)
		if err == nil {
			err = w.applyEntryRouting(runtime)
		}
		if err == nil {
			err = w.applyEntryForwarding(runtime)
		}
	}
	if err != nil {
		if proc != nil {
			_ = proc.Stop()
		}
		if runtime.role == "exit" {
			w.cleanupExitFirewall(runtime)
		} else {
			w.cleanupEntryForwarding(runtime)
			w.cleanupEntryRouting(runtime)
		}
		return err
	}
	state.gost = proc
	state.gostRuntime = runtime
	state.setRuntimeHealth(true, "")
	w.watchGostProcess(state, proc)
	return nil
}

func sameGostRuntime(current, desired *gostRuntime) bool {
	if current == nil || desired == nil {
		return false
	}
	return current.role == desired.role &&
		current.mode == desired.mode &&
		current.server == desired.server &&
		current.serverPort == desired.serverPort &&
		current.tunPort == desired.tunPort &&
		current.tunName == desired.tunName &&
		current.tunAddress == desired.tunAddress &&
		current.entryTunIP == desired.entryTunIP &&
		current.wireGuardIface == desired.wireGuardIface &&
		current.mtu == desired.mtu &&
		current.sourceCIDR == desired.sourceCIDR &&
		current.routingTable == desired.routingTable &&
		current.routingPriority == desired.routingPriority &&
		current.exitNAT == desired.exitNAT &&
		current.outboundIface == desired.outboundIface &&
		current.wssPath == desired.wssPath &&
		current.wssSecure == desired.wssSecure &&
		current.wssServerName == desired.wssServerName &&
		current.wssCAFile == desired.wssCAFile &&
		current.wssCertFile == desired.wssCertFile &&
		current.wssKeyFile == desired.wssKeyFile &&
		current.networkPolicySignature == desired.networkPolicySignature
}

func (w *WireGuard) watchGostProcess(state *nodeState, proc process) {
	waiter, ok := proc.(processWaiter)
	if !ok {
		return
	}
	stop := make(chan struct{})
	state.gostWatchStop = stop
	go func() {
		err := waiter.Wait()
		select {
		case <-stop:
			return
		default:
		}
		w.handleGostExit(state, proc, err)
	}()
}

func (w *WireGuard) handleGostExit(state *nodeState, proc process, waitErr error) {
	state.applyMu.Lock()
	w.mu.Lock()
	current, exists := w.nodes[state.tag]
	if !exists || current != state || state.gost != proc {
		w.mu.Unlock()
		state.applyMu.Unlock()
		return
	}
	state.gost = nil
	state.gostWatchStop = nil
	w.mu.Unlock()

	message := "gost relay exited"
	if waitErr != nil {
		message = fmt.Sprintf("gost relay exited: %v", waitErr)
	}
	state.setRuntimeHealth(false, message)
	slog.Error("wireguard gost relay exited", "tag", state.tag, "error", waitErr)
	_ = w.cleanupGost(state)
	state.applyMu.Unlock()

	delay := w.cfg.GostRestartDelaySeconds
	if delay <= 0 {
		delay = 3
	}
	for {
		time.Sleep(time.Duration(delay) * time.Second)

		state.applyMu.Lock()
		w.mu.Lock()
		current, exists = w.nodes[state.tag]
		w.mu.Unlock()
		if !exists || current != state {
			state.applyMu.Unlock()
			return
		}
		err := w.applyGost(state)
		state.applyMu.Unlock()
		if err == nil {
			return
		}
		state.setRuntimeHealth(false, fmt.Sprintf("gost relay restart failed: %v", err))
		slog.Error("wireguard gost relay restart failed", "tag", state.tag, "error", err)
	}
}

func (state *nodeState) setRuntimeHealth(healthy bool, message string) {
	state.runtimeMu.Lock()
	state.runtimeHealthy = healthy
	state.runtimeError = strings.TrimSpace(message)
	state.runtimeMu.Unlock()
}

func (w *WireGuard) cleanupGost(state *nodeState) error {
	if state == nil {
		return nil
	}
	if state.gostWatchStop != nil {
		close(state.gostWatchStop)
		state.gostWatchStop = nil
	}
	if state.gost != nil {
		_ = state.gost.Stop()
		state.gost = nil
	}
	runtime := state.gostRuntime
	state.gostRuntime = nil
	if runtime == nil {
		return nil
	}
	if runtime.role == "exit" {
		w.cleanupExitFirewall(runtime)
		return nil
	}
	w.cleanupEntryForwarding(runtime)
	w.cleanupEntryRouting(runtime)
	return nil
}

func (w *WireGuard) startGostEntry(state *nodeState, mode, tunName string, tunPort int) (process, error) {
	n := state.info.WireGuard
	if strings.TrimSpace(n.Relay.Server) == "" || n.Relay.ServerPort <= 0 {
		return nil, errors.New("wireguard gost entry requires relay.server and relay.server_port")
	}
	tunAddress := relayTunAddress(n, "entry")
	if tunAddress == "" {
		return nil, errors.New("wireguard gost entry requires relay.entry_tun_address or relay.tun_address")
	}
	listener := fmt.Sprintf(
		"tun://:0/:%d?net=%s&name=%s&mtu=%d",
		tunPort,
		tunAddress,
		tunName,
		wireGuardMTU(n),
	)
	forwarder := gostRelayEndpoint(n, mode, n.Relay.Server, n.Relay.ServerPort, false)
	return w.executor.Start(w.cfg.GostPath, "-L", listener, "-F", forwarder)
}

func (w *WireGuard) startGostExit(state *nodeState, mode, tunName string, tunPort int) (process, error) {
	n := state.info.WireGuard
	if n.Relay.ServerPort <= 0 {
		return nil, errors.New("wireguard gost exit requires relay.server_port")
	}
	tunAddress := relayTunAddress(n, "exit")
	if tunAddress == "" {
		return nil, errors.New("wireguard gost exit requires relay.exit_tun_address or relay.tun_address")
	}
	entryTunIP := relayTunIP(n.Relay.EntryTunAddress)
	if entryTunIP == "" {
		return nil, errors.New("wireguard gost exit requires relay.entry_tun_address")
	}
	listener := fmt.Sprintf(
		"tun://:%d?net=%s&name=%s&mtu=%d&route=%s&gw=%s",
		tunPort,
		tunAddress,
		tunName,
		wireGuardMTU(n),
		n.CIDR,
		entryTunIP,
	)
	relayListener := gostRelayEndpoint(n, mode, "", n.Relay.ServerPort, true)
	return w.executor.Start(w.cfg.GostPath, "-L", listener, "-L", relayListener)
}

func (w *WireGuard) enableIPv4Forwarding() error {
	if w.cfg.SysctlPath == "" {
		return nil
	}
	return w.executor.Run(w.cfg.SysctlPath, "-w", "net.ipv4.ip_forward=1")
}

func (w *WireGuard) applyEntryRouting(runtime *gostRuntime) error {
	w.cleanupEntryRouting(runtime)
	routeArgs := []string{
		"route", "replace", "default", "dev", runtime.tunName, "table", strconv.Itoa(runtime.routingTable),
	}
	var routeErr error
	for attempt := 0; attempt < 30; attempt++ {
		routeErr = w.executor.Run(w.cfg.IPPath, routeArgs...)
		if routeErr == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if routeErr != nil {
		return routeErr
	}
	return w.executor.Run(
		w.cfg.IPPath,
		"rule", "add", "from", runtime.sourceCIDR,
		"table", strconv.Itoa(runtime.routingTable),
		"priority", strconv.Itoa(runtime.routingPriority),
	)
}

func (w *WireGuard) cleanupEntryRouting(runtime *gostRuntime) {
	if runtime == nil {
		return
	}
	_ = w.executor.Run(
		w.cfg.IPPath,
		"rule", "delete", "from", runtime.sourceCIDR,
		"table", strconv.Itoa(runtime.routingTable),
		"priority", strconv.Itoa(runtime.routingPriority),
	)
	_ = w.executor.Run(w.cfg.IPPath, "route", "flush", "table", strconv.Itoa(runtime.routingTable))
}

func (w *WireGuard) applyEntryForwarding(runtime *gostRuntime) error {
	if w.cfg.IPTablesPath == "" {
		return nil
	}
	forwardRuleAdded, err := ensureIPTablesRule(w.executor, w.cfg.IPTablesPath, entryForwardRuleArgs(runtime)...)
	runtime.entryForwardRuleAdded = forwardRuleAdded
	if err != nil {
		return err
	}
	reverseForwardRuleAdded, err := ensureIPTablesRule(w.executor, w.cfg.IPTablesPath, entryReverseForwardRuleArgs(runtime)...)
	runtime.entryReverseForwardRuleAdded = reverseForwardRuleAdded
	return err
}

func (w *WireGuard) cleanupEntryForwarding(runtime *gostRuntime) {
	if runtime == nil || w.cfg.IPTablesPath == "" {
		return
	}
	if runtime.entryReverseForwardRuleAdded {
		reverseArgs := entryReverseForwardRuleArgs(runtime)
		reverseArgs[0] = "-D"
		_ = w.executor.Run(w.cfg.IPTablesPath, reverseArgs...)
	}
	if runtime.entryForwardRuleAdded {
		forwardArgs := entryForwardRuleArgs(runtime)
		forwardArgs[0] = "-D"
		_ = w.executor.Run(w.cfg.IPTablesPath, forwardArgs...)
	}
}

func (w *WireGuard) applyExitFirewall(runtime *gostRuntime) error {
	if w.cfg.IPTablesPath == "" {
		return nil
	}
	if runtime.exitNAT {
		natArgs := []string{"-t", "nat", "-A", "POSTROUTING", "-s", runtime.sourceCIDR}
		if runtime.outboundIface != "" {
			natArgs = append(natArgs, "-o", runtime.outboundIface)
		}
		natArgs = append(natArgs, "-j", "MASQUERADE")
		natRuleAdded, err := ensureIPTablesRule(w.executor, w.cfg.IPTablesPath, natArgs...)
		if err != nil {
			return err
		}
		runtime.natRuleAdded = natRuleAdded
	}
	forwardRuleAdded, err := ensureIPTablesRule(w.executor, w.cfg.IPTablesPath, exitForwardRuleArgs(runtime)...)
	runtime.forwardRuleAdded = forwardRuleAdded
	if err != nil {
		return err
	}
	reverseForwardRuleAdded, err := ensureIPTablesRule(w.executor, w.cfg.IPTablesPath, exitReverseForwardRuleArgs(runtime)...)
	runtime.reverseForwardRuleAdded = reverseForwardRuleAdded
	return err
}

func (w *WireGuard) cleanupExitFirewall(runtime *gostRuntime) {
	if runtime == nil || w.cfg.IPTablesPath == "" {
		return
	}
	if !runtime.natRuleAdded && !runtime.forwardRuleAdded && !runtime.reverseForwardRuleAdded {
		return
	}
	if runtime.reverseForwardRuleAdded {
		reverseArgs := exitReverseForwardRuleArgs(runtime)
		reverseArgs[0] = "-D"
		_ = w.executor.Run(w.cfg.IPTablesPath, reverseArgs...)
	}
	if runtime.forwardRuleAdded {
		forwardArgs := exitForwardRuleArgs(runtime)
		forwardArgs[0] = "-D"
		_ = w.executor.Run(w.cfg.IPTablesPath, forwardArgs...)
	}
	if runtime.natRuleAdded {
		natArgs := []string{"-t", "nat", "-D", "POSTROUTING", "-s", runtime.sourceCIDR}
		if runtime.outboundIface != "" {
			natArgs = append(natArgs, "-o", runtime.outboundIface)
		}
		natArgs = append(natArgs, "-j", "MASQUERADE")
		_ = w.executor.Run(w.cfg.IPTablesPath, natArgs...)
	}
}

func exitForwardRuleArgs(runtime *gostRuntime) []string {
	if runtime.outboundIface == "" {
		return []string{"-A", "FORWARD", "-i", runtime.tunName, "-j", "ACCEPT"}
	}
	return []string{"-A", "FORWARD", "-i", runtime.tunName, "-o", runtime.outboundIface, "-j", "ACCEPT"}
}

func entryForwardRuleArgs(runtime *gostRuntime) []string {
	return []string{
		"-A", "FORWARD",
		"-i", runtime.wireGuardIface,
		"-o", runtime.tunName,
		"-s", runtime.sourceCIDR,
		"-j", "ACCEPT",
	}
}

func entryReverseForwardRuleArgs(runtime *gostRuntime) []string {
	return []string{
		"-A", "FORWARD",
		"-i", runtime.tunName,
		"-o", runtime.wireGuardIface,
		"-d", runtime.sourceCIDR,
		"-m", "conntrack",
		"--ctstate", "ESTABLISHED,RELATED",
		"-j", "ACCEPT",
	}
}

func exitReverseForwardRuleArgs(runtime *gostRuntime) []string {
	args := []string{"-A", "FORWARD"}
	if runtime.outboundIface != "" {
		args = append(args, "-i", runtime.outboundIface)
	}
	args = append(args,
		"-o", runtime.tunName,
		"-d", runtime.sourceCIDR,
		"-m", "conntrack",
		"--ctstate", "ESTABLISHED,RELATED",
		"-j", "ACCEPT",
	)
	return args
}

func ensureIPTablesRule(executor commandExecutor, path string, args ...string) (bool, error) {
	checkArgs := make([]string, len(args))
	copy(checkArgs, args)
	for i, arg := range checkArgs {
		if arg == "-A" {
			checkArgs[i] = "-C"
			break
		}
	}
	if err := executor.Run(path, checkArgs...); err == nil {
		return false, nil
	}
	var ruleErr error
	for attempt := 0; attempt < 30; attempt++ {
		ruleErr = executor.Run(path, args...)
		if ruleErr == nil {
			return true, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false, ruleErr
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
	if wireGuardRelayRole(n) == "exit" {
		return validateWireGuardExitNode(n)
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
		if wireGuardRelayBackend(n) == "gost" && !cidr.Addr().Is4() {
			return errors.New("wireguard GOST relay runtime currently supports IPv4 peer CIDRs only")
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
	backend := wireGuardRelayBackend(n)
	if backend != "" && backend != "gost" {
		return fmt.Errorf("wireguard relay backend is not supported: %q", n.Relay.Backend)
	}
	if backend == "gost" {
		if err := validateWireGuardGostRuntimeSettings(n); err != nil {
			return err
		}
		if err := validateNetworkPolicyConfig(n); err != nil {
			return err
		}
		return validateWireGuardWSSRelay(n, "entry")
	}
	return nil
}

func validateWireGuardExitNode(n *panel.WireGuardNode) error {
	if n == nil {
		return errors.New("wireguard exit config is missing")
	}
	cidr, err := netip.ParsePrefix(strings.TrimSpace(n.CIDR))
	if err != nil || cidr.Bits() == 0 || !cidr.Addr().Is4() || cidr.Bits() > 30 {
		return fmt.Errorf("wireguard exit cidr is invalid: %q", n.CIDR)
	}
	if n.MTU != 0 && (n.MTU < 576 || n.MTU > 1500) {
		return fmt.Errorf("wireguard mtu is invalid: %d", n.MTU)
	}
	if wireGuardRelayBackend(n) != "gost" {
		return fmt.Errorf("wireguard exit relay backend is not supported: %q", n.Relay.Backend)
	}
	if n.Relay.ServerPort < 1 || n.Relay.ServerPort > 65535 {
		return fmt.Errorf("wireguard exit relay.server_port is invalid: %d", n.Relay.ServerPort)
	}
	if n.Relay.TunPort < 0 || n.Relay.TunPort > 65535 {
		return fmt.Errorf("wireguard exit relay.tun_port is invalid: %d", n.Relay.TunPort)
	}
	if relayTunAddress(n, "exit") == "" {
		return errors.New("wireguard exit requires relay.exit_tun_address or relay.tun_address")
	}
	if relayTunIP(n.Relay.EntryTunAddress) == "" {
		return errors.New("wireguard exit requires relay.entry_tun_address")
	}
	if err := validateWireGuardGostRuntimeSettings(n); err != nil {
		return err
	}
	return validateWireGuardWSSRelay(n, "exit")
}

func validateWireGuardWSSRelay(n *panel.WireGuardNode, role string) error {
	mode, err := wireGuardGostMode(n)
	if err != nil || mode != "relay+wss" {
		return err
	}
	path := wireGuardWSSPath(n)
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n") {
		return fmt.Errorf("wireguard relay.wss_path is invalid: %q", path)
	}
	if role == "entry" {
		if strings.TrimSpace(n.Relay.WSSCertFile) != "" || strings.TrimSpace(n.Relay.WSSKeyFile) != "" {
			return errors.New("wireguard WSS entry must not receive exit certificate paths")
		}
		if !n.Relay.WSSSecure {
			return errors.New("wireguard WSS entry requires relay.wss_secure=true")
		}
		serverName := strings.TrimSpace(n.Relay.WSSServerName)
		if serverName == "" || strings.ContainsAny(serverName, " \t\r\n/\\") {
			return errors.New("wireguard WSS entry requires a valid relay.wss_server_name")
		}
		return validateWireGuardRuntimeFile(n.Relay.WSSCAFile, "relay.wss_ca_file", false)
	}
	if strings.TrimSpace(n.Relay.WSSServerName) != "" || strings.TrimSpace(n.Relay.WSSCAFile) != "" {
		return errors.New("wireguard WSS exit must not receive entry verification settings")
	}
	if n.Relay.WSSSecure {
		return errors.New("wireguard WSS exit must not receive the entry secure setting")
	}
	if err := validateWireGuardRuntimeFile(n.Relay.WSSCertFile, "relay.wss_cert_file", true); err != nil {
		return err
	}
	return validateWireGuardRuntimeFile(n.Relay.WSSKeyFile, "relay.wss_key_file", true)
}

func validateWireGuardRuntimeFile(value, name string, required bool) error {
	value = strings.TrimSpace(value)
	if value == "" {
		if required {
			return fmt.Errorf("wireguard WSS requires %s", name)
		}
		return nil
	}
	if len(value) > 1024 || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("wireguard %s is invalid", name)
	}
	return nil
}

func validateWireGuardGostRuntimeSettings(n *panel.WireGuardNode) error {
	if n == nil {
		return errors.New("wireguard GOST runtime config is missing")
	}
	if wireGuardRelayBackend(n) == "gost" {
		for _, value := range []struct {
			name string
			cidr string
		}{
			{name: "relay.tun_address", cidr: n.Relay.TunAddress},
			{name: "relay.entry_tun_address", cidr: n.Relay.EntryTunAddress},
			{name: "relay.exit_tun_address", cidr: n.Relay.ExitTunAddress},
		} {
			if strings.TrimSpace(value.cidr) == "" {
				continue
			}
			ip, _, parseErr := net.ParseCIDR(value.cidr)
			if parseErr != nil || ip.To4() == nil {
				return fmt.Errorf("%s must be an IPv4 CIDR for the GOST relay runtime", value.name)
			}
		}
		for _, value := range n.AllowedIPs {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if ip := net.ParseIP(value); ip != nil {
				if ip.To4() == nil {
					return errors.New("wireguard GOST relay runtime supports IPv4 AllowedIPs only")
				}
				continue
			}
			ip, _, parseErr := net.ParseCIDR(value)
			if parseErr != nil || ip.To4() == nil {
				return errors.New("wireguard GOST relay runtime supports IPv4 AllowedIPs only")
			}
		}
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

func gostTunName(tag string) string {
	sum := sha1.Sum([]byte(tag + ":gost"))
	return "gt" + hex.EncodeToString(sum[:])[:13]
}

func relayRoutingTable(tag string, configured int) int {
	if configured > 0 {
		return configured
	}
	sum := sha1.Sum([]byte(tag + ":table"))
	return 30000 + int(sum[0])<<8 + int(sum[1])
}

func relayRoutingPriority(tag string, configured int) int {
	if configured > 0 {
		return configured
	}
	// Policy rules must run before the kernel's main-table rule at priority
	// 32766. Routing table IDs may be greater than that, so they cannot also be
	// used as rule priorities. Keep the generated priority in a separate,
	// deterministic range that precedes main while leaving room for operator
	// rules with lower numeric priorities.
	sum := sha1.Sum([]byte(tag + ":priority"))
	value := int(sum[0])<<8 | int(sum[1])
	return 10000 + value%20000
}

func wireGuardMTU(n *panel.WireGuardNode) int {
	if n != nil && n.MTU > 0 {
		return n.MTU
	}
	return 1280
}

func wireGuardRelayRole(n *panel.WireGuardNode) string {
	if n == nil {
		return "entry"
	}
	role := strings.ToLower(strings.TrimSpace(n.Relay.Role))
	if role == "exit" {
		return "exit"
	}
	return "entry"
}

func wireGuardRelayBackend(n *panel.WireGuardNode) string {
	if n == nil {
		return ""
	}
	backend := strings.ToLower(strings.TrimSpace(n.Relay.Backend))
	if backend != "" {
		return backend
	}
	if hasWireGuardRelayConfig(n.Relay) {
		return "gost"
	}
	return ""
}

func hasWireGuardRelayConfig(relay panel.WireGuardRelay) bool {
	return strings.TrimSpace(relay.Mode) != "" ||
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

func wireGuardGostMode(n *panel.WireGuardNode) (string, error) {
	if n == nil {
		return "relay+quic", nil
	}
	tunnelType := strings.ToLower(strings.TrimSpace(n.TunnelType))
	mode := strings.ToLower(strings.TrimSpace(n.Relay.Mode))
	if tunnelType == "" && mode != "" {
		if strings.Contains(mode, "wss") {
			tunnelType = "wss"
		} else if strings.Contains(mode, "quic") {
			tunnelType = "quic"
		}
	}
	if n.Relay.WSSCompat {
		tunnelType = "wss"
	}
	switch tunnelType {
	case "", "quic":
		return "relay+quic", nil
	case "wss":
		return "relay+wss", nil
	default:
		return "", fmt.Errorf("wireguard tunnel_type %q is not supported by first relay runtime", n.TunnelType)
	}
}

func wireGuardWSSPath(n *panel.WireGuardNode) string {
	if n == nil {
		return "/ws"
	}
	path := strings.TrimSpace(n.Relay.WSSPath)
	if path == "" {
		return "/ws"
	}
	return path
}

func gostRelayEndpoint(n *panel.WireGuardNode, mode, host string, port int, listener bool) string {
	endpoint := &url.URL{
		Scheme: mode,
		Host:   net.JoinHostPort(strings.TrimSpace(host), strconv.Itoa(port)),
	}
	query := url.Values{}
	if listener {
		query.Set("bind", "true")
	}
	if mode == "relay+wss" {
		query.Set("path", wireGuardWSSPath(n))
		if listener {
			if certFile := strings.TrimSpace(n.Relay.WSSCertFile); certFile != "" {
				query.Set("certFile", certFile)
			}
			if keyFile := strings.TrimSpace(n.Relay.WSSKeyFile); keyFile != "" {
				query.Set("keyFile", keyFile)
			}
		} else {
			if n.Relay.WSSSecure {
				query.Set("secure", "true")
			}
			if serverName := strings.TrimSpace(n.Relay.WSSServerName); serverName != "" {
				query.Set("serverName", serverName)
			}
			if caFile := strings.TrimSpace(n.Relay.WSSCAFile); caFile != "" {
				query.Set("caFile", caFile)
			}
		}
	}
	endpoint.RawQuery = query.Encode()
	return endpoint.String()
}

func relayTunAddress(n *panel.WireGuardNode, role string) string {
	if n == nil {
		return ""
	}
	if role == "exit" {
		if v := strings.TrimSpace(n.Relay.ExitTunAddress); v != "" {
			return v
		}
	} else if v := strings.TrimSpace(n.Relay.EntryTunAddress); v != "" {
		return v
	}
	return strings.TrimSpace(n.Relay.TunAddress)
}

func relayTunIP(address string) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return ""
	}
	if strings.Contains(address, "/") {
		ip, _, err := net.ParseCIDR(address)
		if err == nil && ip != nil {
			return ip.String()
		}
	}
	return address
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
