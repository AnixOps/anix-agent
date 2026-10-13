package wireguard

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
	vCore "github.com/AnixOps/anix-agent/v5/core"
)

type fakeExecutor struct {
	commands     []string
	starts       []string
	outputs      map[string][]byte
	failContains []string
	startProcess func() process
}

func (f *fakeExecutor) Run(name string, args ...string) error {
	cmd := name + " " + strings.Join(args, " ")
	f.commands = append(f.commands, cmd)
	if strings.Contains(cmd, " link show ") {
		return errors.New("missing")
	}
	for _, pattern := range f.failContains {
		if strings.Contains(cmd, pattern) {
			return errors.New("forced failure")
		}
	}
	return nil
}

func (f *fakeExecutor) Output(name string, args ...string) ([]byte, error) {
	if f.outputs == nil {
		return nil, nil
	}
	return f.outputs[name+" "+strings.Join(args, " ")], nil
}

func (f *fakeExecutor) Start(name string, args ...string) (process, error) {
	f.starts = append(f.starts, name+" "+strings.Join(args, " "))
	if f.startProcess != nil {
		return f.startProcess(), nil
	}
	return fakeProcess{}, nil
}

type fakeProcess struct{}

func (fakeProcess) Stop() error { return nil }

type waitableFakeProcess struct {
	done     chan struct{}
	stopOnce sync.Once
	err      error
}

func (p *waitableFakeProcess) Wait() error {
	<-p.done
	return p.err
}

func (p *waitableFakeProcess) Stop() error {
	p.stopOnce.Do(func() { close(p.done) })
	return nil
}

func TestWireGuard_AddNodeAndUsersApplyConfig(t *testing.T) {
	exec := &fakeExecutor{}
	core := &WireGuard{
		cfg: &conf.WireGuardConfig{
			RuntimeDir: t.TempDir(),
			WGPath:     "wg",
			IPPath:     "ip",
			GostPath:   "gost",
		},
		executor: exec,
		nodes:    make(map[string]*nodeState),
	}
	node := testNodeInfo()

	if err := core.AddNode("test-node", node, &conf.Options{}); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	added, err := core.AddUsers(&vCore.AddUsersParams{
		Tag:      "test-node",
		NodeInfo: node,
		Users: []panel.UserInfo{{
			Id:                    1,
			Uuid:                  "user-1",
			WireGuardPeerIP:       "10.66.0.2",
			WireGuardPublicKey:    testWireGuardKey,
			WireGuardPresharedKey: testWireGuardKey,
		}},
	})
	if err != nil {
		t.Fatalf("AddUsers() error = %v", err)
	}
	if added != 1 {
		t.Fatalf("AddUsers() added = %d, want 1", added)
	}

	rendered := renderConfig(core.nodes["test-node"])
	for _, want := range []string{
		"PrivateKey = " + testWireGuardKey,
		"ListenPort = 51820",
		"PublicKey = " + testWireGuardKey,
		"PresharedKey = " + testWireGuardKey,
		"AllowedIPs = 10.66.0.2/32",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered config missing %q:\n%s", want, rendered)
		}
	}
	joined := strings.Join(exec.commands, "\n")
	for _, want := range []string{
		"ip link add",
		"ip address add 10.66.0.1/24",
		"wg setconf",
		"ip link set up",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("commands missing %q:\n%s", want, joined)
		}
	}
}

func TestWireGuardRuntimeHealthDefaultsHealthy(t *testing.T) {
	core := &WireGuard{
		cfg:      &conf.WireGuardConfig{RuntimeDir: t.TempDir(), WGPath: "wg", IPPath: "ip"},
		executor: &fakeExecutor{},
		nodes:    make(map[string]*nodeState),
	}
	if err := core.AddNode("health-node", testNodeInfo(), &conf.Options{}); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	healthy, message := core.RuntimeHealth("health-node")
	if !healthy || message != "" {
		t.Fatalf("RuntimeHealth() = (%v, %q), want healthy", healthy, message)
	}
}

func TestWireGuard_AddUsersRejectsMissingPeer(t *testing.T) {
	core := &WireGuard{
		cfg:      conf.NewWireGuardConfig(),
		executor: &fakeExecutor{},
		nodes: map[string]*nodeState{
			"test-node": {
				tag:   "test-node",
				iface: "wgtest",
				info:  testNodeInfo(),
				users: make(map[string]panel.UserInfo),
			},
		},
	}

	_, err := core.AddUsers(&vCore.AddUsersParams{
		Tag: "test-node",
		Users: []panel.UserInfo{{
			Uuid:               "user-1",
			WireGuardPublicKey: "peer-public",
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "peer_ip") {
		t.Fatalf("AddUsers() error = %v, want peer_ip error", err)
	}
}

func TestValidateWireGuardNodeRejectsIPv6GostRelayRuntime(t *testing.T) {
	node := testNodeInfo()
	node.WireGuard.Relay.Backend = "gost"
	node.WireGuard.CIDR = "fd00::/120"
	node.WireGuard.ServerAddress = "fd00::1/120"
	if err := validateWireGuardNode(node); err == nil {
		t.Fatal("validateWireGuardNode() accepted an IPv6 GOST relay CIDR")
	}

	node = testNodeInfo()
	node.WireGuard.Relay.Backend = "gost"
	node.WireGuard.AllowedIPs = []string{"::/0"}
	if err := validateWireGuardNode(node); err == nil {
		t.Fatal("validateWireGuardNode() accepted IPv6 AllowedIPs for GOST relay")
	}
}

func TestValidateWireGuardExitDoesNotRequireEntryKeyMaterial(t *testing.T) {
	node := testNodeInfo()
	node.Common.ServerPort = 0
	node.WireGuard.ServerPrivateKey = ""
	node.WireGuard.ServerPublicKey = ""
	node.WireGuard.ServerAddress = ""
	node.WireGuard.Relay = panel.WireGuardRelay{
		Backend:         "gost",
		Role:            "exit",
		ServerPort:      8443,
		TunPort:         8421,
		EntryTunAddress: "172.31.66.2/24",
		ExitTunAddress:  "172.31.66.1/24",
	}

	if err := validateWireGuardNode(node); err != nil {
		t.Fatalf("validateWireGuardNode() exit config error = %v", err)
	}
}

func TestWireGuard_AddUsersAppliesPerPeerTcRateLimit(t *testing.T) {
	exec := &fakeExecutor{}
	core := &WireGuard{
		cfg: &conf.WireGuardConfig{
			RuntimeDir: t.TempDir(),
			WGPath:     "wg",
			IPPath:     "ip",
			TCPath:     "tc",
		},
		executor: exec,
		nodes:    make(map[string]*nodeState),
		traffic:  make(map[string]map[string]trafficPair),
	}
	if err := core.AddNode("rate-node", testNodeInfo(), &conf.Options{LimitConfig: conf.LimitConfig{SpeedLimit: 20}}); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	_, err := core.AddUsers(&vCore.AddUsersParams{
		Tag: "rate-node",
		Users: []panel.UserInfo{{
			Id:                    1,
			Uuid:                  "rate-user",
			WireGuardPeerIP:       "10.66.0.2",
			WireGuardPublicKey:    testWireGuardKey,
			WireGuardPresharedKey: testWireGuardKey,
			SpeedLimit:            625000,
		}},
	})
	if err != nil {
		t.Fatalf("AddUsers() error = %v", err)
	}
	joined := strings.Join(exec.commands, "\n")
	for _, want := range []string{
		"tc qdisc replace dev wg",
		"tc class replace dev wg",
		"rate 5000000bit",
		"tc filter replace dev wg",
		"parent ffff:",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("tc commands missing %q:\n%s", want, joined)
		}
	}

	if err := core.UpdateUserRateLimit("rate-node", "rate-user", 250000); err != nil {
		t.Fatalf("UpdateUserRateLimit() error = %v", err)
	}
	if !strings.Contains(strings.Join(exec.commands, "\n"), "rate 2000000bit") {
		t.Fatalf("updated tc rate missing:\n%s", strings.Join(exec.commands, "\n"))
	}
}

func TestWireGuard_AddUsersRefreshesChangedPeerCredentials(t *testing.T) {
	exec := &fakeExecutor{}
	core := &WireGuard{
		cfg:      &conf.WireGuardConfig{RuntimeDir: t.TempDir(), WGPath: "wg", IPPath: "ip"},
		executor: exec,
		nodes:    make(map[string]*nodeState),
	}
	node := testNodeInfo()
	if err := core.AddNode("changed-node", node, &conf.Options{}); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	first := panel.UserInfo{Id: 1, Uuid: "changed-user", WireGuardPeerIP: "10.66.0.2", WireGuardPublicKey: testWireGuardKey}
	if _, err := core.AddUsers(&vCore.AddUsersParams{Tag: "changed-node", Users: []panel.UserInfo{first}}); err != nil {
		t.Fatalf("first AddUsers() error = %v", err)
	}
	second := first
	second.WireGuardPublicKey = testWireGuardKeyAlt
	if _, err := core.AddUsers(&vCore.AddUsersParams{Tag: "changed-node", Users: []panel.UserInfo{second}}); err != nil {
		t.Fatalf("second AddUsers() error = %v", err)
	}
	if !strings.Contains(renderConfig(core.nodes["changed-node"]), "PublicKey = "+testWireGuardKeyAlt) {
		t.Fatalf("changed peer key was not rendered:\n%s", renderConfig(core.nodes["changed-node"]))
	}
}

func TestWireGuard_GetUserTrafficSliceParsesTransferDeltas(t *testing.T) {
	exec := &fakeExecutor{
		outputs: map[string][]byte{
			"wg show wgtest transfer": []byte("peer-public 1000 2000\n"),
		},
	}
	core := &WireGuard{
		cfg:      conf.NewWireGuardConfig(),
		executor: exec,
		nodes: map[string]*nodeState{
			"test-node": {
				tag:     "test-node",
				iface:   "wgtest",
				info:    testNodeInfo(),
				users:   make(map[string]panel.UserInfo),
				cfgPath: "unused",
			},
		},
		traffic: make(map[string]map[string]trafficPair),
	}
	core.nodes["test-node"].users["user-1"] = panel.UserInfo{
		Id:                 7,
		Uuid:               "user-1",
		WireGuardPublicKey: "peer-public",
	}

	first, err := core.GetUserTrafficSlice("test-node", true)
	if err != nil {
		t.Fatalf("GetUserTrafficSlice() error = %v", err)
	}
	if len(first) != 1 || first[0].UID != 7 || first[0].Upload != 1000 || first[0].Download != 2000 {
		t.Fatalf("first traffic = %#v", first)
	}

	exec.outputs["wg show wgtest transfer"] = []byte("peer-public 1700 2600\n")
	second, err := core.GetUserTrafficSlice("test-node", true)
	if err != nil {
		t.Fatalf("GetUserTrafficSlice() second error = %v", err)
	}
	if len(second) != 1 || second[0].Upload != 700 || second[0].Download != 600 {
		t.Fatalf("second traffic = %#v", second)
	}
}

func TestWireGuard_RollbackUserTrafficSliceRestoresCursor(t *testing.T) {
	exec := &fakeExecutor{
		outputs: map[string][]byte{
			"wg show wgtest transfer": []byte("peer-public 1700 2600\n"),
		},
	}
	core := &WireGuard{
		cfg:      conf.NewWireGuardConfig(),
		executor: exec,
		nodes: map[string]*nodeState{
			"test-node": {
				tag:   "test-node",
				iface: "wgtest",
				info:  testNodeInfo(),
				users: map[string]panel.UserInfo{"user-1": {Id: 7, Uuid: "user-1", WireGuardPublicKey: "peer-public"}},
			},
		},
		traffic: make(map[string]map[string]trafficPair),
	}

	first, err := core.GetUserTrafficSlice("test-node", true)
	if err != nil || len(first) != 1 {
		t.Fatalf("initial traffic = %#v, err = %v", first, err)
	}
	if err := core.RollbackUserTrafficSlice("test-node", first); err != nil {
		t.Fatalf("RollbackUserTrafficSlice() error = %v", err)
	}
	second, err := core.GetUserTrafficSlice("test-node", true)
	if err != nil || len(second) != 1 || second[0].Upload != 1700 || second[0].Download != 2600 {
		t.Fatalf("rolled back traffic = %#v, err = %v", second, err)
	}
}

func TestWireGuard_GetOnlineDeviceParsesRecentHandshake(t *testing.T) {
	now := time.Now().Unix()
	exec := &fakeExecutor{
		outputs: map[string][]byte{
			"wg show wgtest dump": []byte(strings.Join([]string{
				"server-private server-public 51820 off",
				"peer-public psk 203.0.113.10:51280 10.66.0.2/32 " + strconv.FormatInt(now-30, 10) + " 1000 2000 0",
				"old-peer psk 203.0.113.11:51280 10.66.0.3/32 " + strconv.FormatInt(now-600, 10) + " 1000 2000 0",
				"none-peer psk (none) 10.66.0.4/32 " + strconv.FormatInt(now-20, 10) + " 1000 2000 0",
				"unknown-peer psk 203.0.113.12:51280 10.66.0.5/32 " + strconv.FormatInt(now-20, 10) + " 1000 2000 0",
			}, "\n")),
		},
	}
	core := &WireGuard{
		cfg: &conf.WireGuardConfig{
			WGPath:                        "wg",
			OnlineHandshakeTimeoutSeconds: 180,
		},
		executor: exec,
		nodes: map[string]*nodeState{
			"test-node": {
				tag:   "test-node",
				iface: "wgtest",
				info:  testNodeInfo(),
				users: map[string]panel.UserInfo{
					"user-1": {Id: 7, Uuid: "user-1", WireGuardPublicKey: "peer-public"},
					"user-2": {Id: 8, Uuid: "user-2", WireGuardPublicKey: "old-peer"},
					"user-3": {Id: 9, Uuid: "user-3", WireGuardPublicKey: "none-peer"},
				},
			},
		},
	}

	online, err := core.GetOnlineDevice("test-node")
	if err != nil {
		t.Fatalf("GetOnlineDevice() error = %v", err)
	}
	if len(online) != 1 || online[0].UID != 7 || online[0].IP != "203.0.113.10" {
		t.Fatalf("online users = %#v", online)
	}
}

func TestParseDumpOnlineSupportsIPv6Endpoint(t *testing.T) {
	now := int64(1700000000)
	out := []byte("peer-public psk [2001:db8::1]:51280 10.66.0.2/32 1699999990 1000 2000 0\n")
	online := parseDumpOnline(out, map[string]int{"peer-public": 7}, now, 180)
	if len(online) != 1 || online[0].UID != 7 || online[0].IP != "2001:db8::1" {
		t.Fatalf("online users = %#v", online)
	}
}

func TestWireGuard_AddNodeStartsGostEntryAndPolicyRoute(t *testing.T) {
	exec := &fakeExecutor{failContains: []string{"iptables -C FORWARD"}}
	core := &WireGuard{
		cfg: &conf.WireGuardConfig{
			RuntimeDir:   t.TempDir(),
			WGPath:       "wg",
			IPPath:       "ip",
			IPTablesPath: "iptables",
			SysctlPath:   "sysctl",
			GostPath:     "gost",
		},
		executor: exec,
		nodes:    make(map[string]*nodeState),
	}
	node := testNodeInfo()
	node.WireGuard.CIDR = "10.66.0.0/24"
	node.WireGuard.Relay = panel.WireGuardRelay{
		Backend:         "gost",
		Role:            "entry",
		Server:          "exit.example.com",
		ServerPort:      8443,
		TunPort:         8421,
		EntryTunAddress: "172.31.66.2/24",
		TunName:         "gtwgtest",
		RoutingTable:    32010,
		RoutingPriority: 12010,
	}

	if err := core.AddNode("test-node", node, &conf.Options{}); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}

	starts := strings.Join(exec.starts, "\n")
	for _, want := range []string{
		"gost -L tun://:0/:8421?net=172.31.66.2/24&name=gtwgtest&mtu=1280 -F relay+quic://exit.example.com:8443",
	} {
		if !strings.Contains(starts, want) {
			t.Fatalf("starts missing %q:\n%s", want, starts)
		}
	}
	joined := strings.Join(exec.commands, "\n")
	iface := interfaceName("test-node")
	for _, want := range []string{
		"sysctl -w net.ipv4.ip_forward=1",
		"ip route replace default dev gtwgtest table 32010",
		"ip rule add from 10.66.0.0/24 table 32010 priority 12010",
		"iptables -A FORWARD -i " + iface + " -o gtwgtest -s 10.66.0.0/24 -j ACCEPT",
		"iptables -A FORWARD -i gtwgtest -o " + iface + " -d 10.66.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("commands missing %q:\n%s", want, joined)
		}
	}
}

func TestWireGuardNetworkPolicyAppliesArbitrarySourcePaths(t *testing.T) {
	exec := &fakeExecutor{failContains: []string{"iptables -C FORWARD"}}
	core := &WireGuard{
		cfg: &conf.WireGuardConfig{
			RuntimeDir: t.TempDir(), WGPath: "wg", IPPath: "ip",
			IPTablesPath: "iptables", SysctlPath: "sysctl", GostPath: "gost",
		},
		executor: exec,
		nodes:    make(map[string]*nodeState),
	}
	node := testNodeInfo()
	node.WireGuard.TunnelType = "wss"
	node.WireGuard.Relay = panel.WireGuardRelay{
		Backend: "gost", Mode: "relay+wss", Role: "entry", WSSCompat: true,
		WSSSecure: true, WSSServerName: "exit.example.com", WSSPath: "/wireguard",
		Server: "104.251.233.29", ServerPort: 443,
		TunPort: 8421, EntryTunAddress: "172.31.66.2/24", TunName: "gtwgpaths",
		NetworkPolicy: panel.WireGuardNetworkPolicy{
			Version: 1, Strategy: "failover", ActiveTable: 62000, ActivePriority: 7000,
			Paths: []panel.WireGuardNetworkPath{
				{Name: "9929", Interface: "eth0", Source: "10.7.0.112", Gateway: "10.7.0.1", Priority: 20, RoutingTable: 51000, RulePriority: 4100},
				{Name: "cn2", Interface: "eth1", Source: "10.8.0.112", Gateway: "10.8.0.1", Priority: 10, RoutingTable: 51001, RulePriority: 4101},
			},
			HealthCheck: panel.WireGuardHealthCheck{IntervalSeconds: 60, TimeoutSeconds: 1, FailureThreshold: 3, RecoveryThreshold: 2, FailbackDelaySeconds: 300},
		},
	}

	if err := core.AddNode("test-paths", node, &conf.Options{}); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	joined := strings.Join(exec.commands, "\n")
	for _, want := range []string{
		"ip -4 route replace default via 10.8.0.1 dev eth1 src 10.8.0.112 table 51001",
		"ip -4 rule add from 10.8.0.112/32 table 51001 priority 4101",
		"ip -4 route replace default via 10.7.0.1 dev eth0 src 10.7.0.112 table 51000",
		"ip -4 rule add from 10.7.0.112/32 table 51000 priority 4100",
		"ip -4 route replace default via 10.8.0.1 dev eth1 src 10.8.0.112 table 62000",
		"ip -4 rule add to 104.251.233.29/32 table 62000 priority 7000",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("commands missing %q:\n%s", want, joined)
		}
	}
	if err := core.DelNode("test-paths"); err != nil {
		t.Fatalf("DelNode() error = %v", err)
	}
	joined = strings.Join(exec.commands, "\n")
	if !strings.Contains(joined, "ip -4 route flush table 62000") || !strings.Contains(joined, "ip -4 route flush table 51001") {
		t.Fatalf("network policy cleanup missing:\n%s", joined)
	}
}

func TestWireGuard_AddNodeDefaultsConfiguredRelayBackendToGost(t *testing.T) {
	exec := &fakeExecutor{}
	core := &WireGuard{
		cfg: &conf.WireGuardConfig{
			RuntimeDir: t.TempDir(),
			WGPath:     "wg",
			IPPath:     "ip",
			SysctlPath: "sysctl",
			GostPath:   "gost",
		},
		executor: exec,
		nodes:    make(map[string]*nodeState),
	}
	node := testNodeInfo()
	node.WireGuard.Relay = panel.WireGuardRelay{
		Role:            "entry",
		Server:          "exit.example.com",
		ServerPort:      8443,
		TunPort:         8421,
		EntryTunAddress: "172.31.66.2/24",
		TunName:         "gtwgdefault",
	}

	if err := core.AddNode("default-backend-node", node, &conf.Options{}); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	if !strings.Contains(strings.Join(exec.starts, "\n"), "gost -L tun://:0/:8421") {
		t.Fatalf("configured relay did not default to GOST: %s", strings.Join(exec.starts, "\n"))
	}

	unsupported := testNodeInfo()
	unsupported.WireGuard.Relay = node.WireGuard.Relay
	unsupported.WireGuard.Relay.Backend = "unsupported"
	if err := core.AddNode("unsupported-backend-node", unsupported, &conf.Options{}); err == nil {
		t.Fatal("AddNode() accepted an unsupported relay backend")
	}
}

func TestRelayRoutingPriorityDefaultsBeforeMainTableRule(t *testing.T) {
	priority := relayRoutingPriority("wireguard-entry", 0)
	if priority < 10000 || priority >= 30000 {
		t.Fatalf("default routing priority = %d, want range [10000, 30000)", priority)
	}
	if priority >= 32766 {
		t.Fatalf("default routing priority = %d, must precede main-table priority 32766", priority)
	}
	if got := relayRoutingPriority("wireguard-entry", 12010); got != 12010 {
		t.Fatalf("configured routing priority = %d, want 12010", got)
	}
}

func TestWireGuard_AddNodeStartsGostWSSRelay(t *testing.T) {
	exec := &fakeExecutor{}
	core := &WireGuard{
		cfg: &conf.WireGuardConfig{
			RuntimeDir: t.TempDir(),
			WGPath:     "wg",
			IPPath:     "ip",
			SysctlPath: "sysctl",
			GostPath:   "gost",
		},
		executor: exec,
		nodes:    make(map[string]*nodeState),
	}
	node := testNodeInfo()
	node.WireGuard.TunnelType = "wss"
	node.WireGuard.Relay = panel.WireGuardRelay{
		Backend:         "gost",
		Mode:            "relay+wss",
		Role:            "entry",
		WSSCompat:       true,
		WSSPath:         "/wireguard",
		WSSSecure:       true,
		WSSServerName:   "exit.example.com",
		Server:          "exit.example.com",
		ServerPort:      8443,
		TunPort:         8421,
		EntryTunAddress: "172.31.66.2/24",
		TunName:         "gtwgwss",
	}

	if err := core.AddNode("wss-node", node, &conf.Options{}); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}

	starts := strings.Join(exec.starts, "\n")
	if !strings.Contains(starts, "gost -L tun://:0/:8421?net=172.31.66.2/24&name=gtwgwss&mtu=1280 -F relay+wss://exit.example.com:8443?path=%2Fwireguard&secure=true&serverName=exit.example.com") {
		t.Fatalf("WSS relay command missing:\n%s", starts)
	}
}

func TestValidateWireGuardWSSRejectsRoleLeakedCertificateSettings(t *testing.T) {
	entry := testNodeInfo()
	entry.WireGuard.TunnelType = "wss"
	entry.WireGuard.Relay = panel.WireGuardRelay{
		Backend:         "gost",
		Mode:            "relay+wss",
		Role:            "entry",
		WSSSecure:       true,
		WSSServerName:   "exit.example.com",
		WSSCertFile:     "/etc/v2bx/exit-cert.pem",
		WSSKeyFile:      "/etc/v2bx/exit-key.pem",
		Server:          "exit.example.com",
		ServerPort:      8443,
		TunPort:         8421,
		EntryTunAddress: "172.31.66.2/24",
	}
	if err := validateWireGuardNode(entry); err == nil {
		t.Fatal("WSS entry accepted exit certificate paths")
	}

	exit := testNodeInfo()
	exit.Common.ServerPort = 0
	exit.WireGuard.ServerPrivateKey = ""
	exit.WireGuard.ServerPublicKey = ""
	exit.WireGuard.ServerAddress = ""
	exit.WireGuard.TunnelType = "wss"
	exit.WireGuard.Relay = panel.WireGuardRelay{
		Backend:         "gost",
		Mode:            "relay+wss",
		Role:            "exit",
		WSSServerName:   "exit.example.com",
		WSSCertFile:     "/etc/v2bx/exit-cert.pem",
		WSSKeyFile:      "/etc/v2bx/exit-key.pem",
		ServerPort:      8443,
		TunPort:         8421,
		EntryTunAddress: "172.31.66.2/24",
		ExitTunAddress:  "172.31.66.1/24",
	}
	if err := validateWireGuardNode(exit); err == nil {
		t.Fatal("WSS exit accepted entry verification settings")
	}
}

func TestGostRelayEndpointEncodesWSSCertificateSettings(t *testing.T) {
	node := testNodeInfo()
	node.WireGuard.TunnelType = "wss"
	node.WireGuard.Relay = panel.WireGuardRelay{
		Backend:         "gost",
		Mode:            "relay+wss",
		Role:            "exit",
		WSSPath:         "/wire guard",
		WSSCertFile:     "/etc/v2bx/relay cert.pem",
		WSSKeyFile:      "/etc/v2bx/relay key.pem",
		ServerPort:      8443,
		EntryTunAddress: "172.31.66.2/24",
		ExitTunAddress:  "172.31.66.1/24",
	}

	endpoint := gostRelayEndpoint(node.WireGuard, "relay+wss", "", 8443, true)
	for _, want := range []string{
		"relay+wss://:8443?",
		"bind=true",
		"path=%2Fwire+guard",
		"certFile=%2Fetc%2Fv2bx%2Frelay+cert.pem",
		"keyFile=%2Fetc%2Fv2bx%2Frelay+key.pem",
	} {
		if !strings.Contains(endpoint, want) {
			t.Fatalf("WSS endpoint missing %q: %s", want, endpoint)
		}
	}
}

func TestWireGuardGostExitMarksUnhealthyAndRestarts(t *testing.T) {
	first := &waitableFakeProcess{done: make(chan struct{})}
	second := &waitableFakeProcess{done: make(chan struct{})}
	var processMu sync.Mutex
	processes := []*waitableFakeProcess{first, second}
	started := 0
	exec := &fakeExecutor{
		startProcess: func() process {
			processMu.Lock()
			defer processMu.Unlock()
			if started >= len(processes) {
				return second
			}
			proc := processes[started]
			started++
			return proc
		},
	}
	core := &WireGuard{
		cfg: &conf.WireGuardConfig{
			RuntimeDir:              t.TempDir(),
			WGPath:                  "wg",
			IPPath:                  "ip",
			IPTablesPath:            "iptables",
			SysctlPath:              "sysctl",
			GostPath:                "gost",
			GostRestartDelaySeconds: 1,
		},
		executor: exec,
		nodes:    make(map[string]*nodeState),
	}
	node := testNodeInfo()
	node.WireGuard.Relay = panel.WireGuardRelay{
		Backend:         "gost",
		Role:            "entry",
		Server:          "exit.example.com",
		ServerPort:      8443,
		TunPort:         8421,
		EntryTunAddress: "172.31.66.2/24",
		TunName:         "gtwgrestart",
	}
	if err := core.AddNode("restart-node", node, &conf.Options{}); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	defer func() { _ = core.Close() }()

	close(first.done)
	deadline := time.Now().Add(5 * time.Second)
	sawUnhealthy := false
	for time.Now().Before(deadline) {
		healthy, message := core.RuntimeHealth("restart-node")
		if !healthy && message != "" {
			sawUnhealthy = true
		}
		processMu.Lock()
		currentStarted := started
		processMu.Unlock()
		if healthy && currentStarted >= 2 {
			if !sawUnhealthy {
				t.Fatal("GOST exit did not publish an unhealthy runtime state")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	healthy, message := core.RuntimeHealth("restart-node")
	processMu.Lock()
	currentStarted := started
	processMu.Unlock()
	t.Fatalf("GOST process did not recover: healthy=%v message=%q started=%d", healthy, message, currentStarted)
}

func TestWireGuardUserRefreshKeepsUnchangedGostRelay(t *testing.T) {
	exec := &fakeExecutor{}
	core := &WireGuard{
		cfg: &conf.WireGuardConfig{
			RuntimeDir: t.TempDir(),
			WGPath:     "wg",
			IPPath:     "ip",
			SysctlPath: "sysctl",
			GostPath:   "gost",
		},
		executor: exec,
		nodes:    make(map[string]*nodeState),
	}
	node := testNodeInfo()
	node.WireGuard.Relay = panel.WireGuardRelay{
		Backend:         "gost",
		Role:            "entry",
		Server:          "exit.example.com",
		ServerPort:      8443,
		TunPort:         8421,
		EntryTunAddress: "172.31.66.2/24",
		TunName:         "gtwgstable",
	}
	if err := core.AddNode("stable-node", node, &conf.Options{}); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	if _, err := core.AddUsers(&vCore.AddUsersParams{
		Tag: "stable-node",
		Users: []panel.UserInfo{{
			Id:                    1,
			Uuid:                  "stable-user",
			WireGuardPeerIP:       "10.66.0.2",
			WireGuardPublicKey:    testWireGuardKey,
			WireGuardPresharedKey: testWireGuardKey,
		}},
	}); err != nil {
		t.Fatalf("AddUsers() error = %v", err)
	}
	if len(exec.starts) != 1 {
		t.Fatalf("GOST relay restarted during unchanged user refresh: starts=%d", len(exec.starts))
	}
}

func TestWireGuard_AddNodeStartsGostExitAndNAT(t *testing.T) {
	exec := &fakeExecutor{
		failContains: []string{"iptables -t nat -C", "iptables -C FORWARD"},
	}
	core := &WireGuard{
		cfg: &conf.WireGuardConfig{
			RuntimeDir:   t.TempDir(),
			WGPath:       "wg",
			IPPath:       "ip",
			IPTablesPath: "iptables",
			SysctlPath:   "sysctl",
			GostPath:     "gost",
		},
		executor: exec,
		nodes:    make(map[string]*nodeState),
	}
	node := testNodeInfo()
	node.WireGuard.CIDR = "10.66.0.0/24"
	node.WireGuard.Relay = panel.WireGuardRelay{
		Backend:         "gost",
		Role:            "exit",
		ServerPort:      8443,
		TunPort:         8421,
		EntryTunAddress: "172.31.66.2/24",
		ExitTunAddress:  "172.31.66.1/24",
		TunName:         "gtwgexit",
		ExitNAT:         true,
		OutboundIface:   "eth0",
	}

	if err := core.AddNode("exit-node", node, &conf.Options{}); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}

	starts := strings.Join(exec.starts, "\n")
	for _, want := range []string{
		"gost -L tun://:8421?net=172.31.66.1/24&name=gtwgexit&mtu=1280&route=10.66.0.0/24&gw=172.31.66.2 -L relay+quic://:8443?bind=true",
	} {
		if !strings.Contains(starts, want) {
			t.Fatalf("starts missing %q:\n%s", want, starts)
		}
	}
	joined := strings.Join(exec.commands, "\n")
	for _, forbidden := range []string{"ip link add", "wg setconf"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("exit role must not create a local WireGuard interface; found %q:\n%s", forbidden, joined)
		}
	}
	for _, want := range []string{
		"iptables -t nat -A POSTROUTING -s 10.66.0.0/24 -o eth0 -j MASQUERADE",
		"iptables -A FORWARD -i gtwgexit -o eth0 -j ACCEPT",
		"iptables -A FORWARD -i eth0 -o gtwgexit -d 10.66.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("commands missing %q:\n%s", want, joined)
		}
	}
	traffic, err := core.GetUserTrafficSlice("exit-node", true)
	if err != nil || traffic != nil {
		t.Fatalf("exit role traffic = %#v, err = %v; want no peer traffic", traffic, err)
	}
	if err := core.DelNode("exit-node"); err != nil {
		t.Fatalf("DelNode() error = %v", err)
	}
	joined = strings.Join(exec.commands, "\n")
	for _, want := range []string{
		"iptables -D FORWARD -i eth0 -o gtwgexit -d 10.66.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"iptables -D FORWARD -i gtwgexit -o eth0 -j ACCEPT",
		"iptables -t nat -D POSTROUTING -s 10.66.0.0/24 -o eth0 -j MASQUERADE",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("cleanup missing %q:\n%s", want, joined)
		}
	}
}

func TestWireGuard_ExitWithoutNATDoesNotCleanupEntryRouting(t *testing.T) {
	exec := &fakeExecutor{failContains: []string{"iptables -C FORWARD"}}
	core := &WireGuard{
		cfg: &conf.WireGuardConfig{
			RuntimeDir:   t.TempDir(),
			WGPath:       "wg",
			IPPath:       "ip",
			IPTablesPath: "iptables",
			SysctlPath:   "sysctl",
			GostPath:     "gost",
		},
		executor: exec,
		nodes:    make(map[string]*nodeState),
	}
	node := testNodeInfo()
	node.Common.ServerPort = 0
	node.WireGuard.ServerPrivateKey = ""
	node.WireGuard.ServerPublicKey = ""
	node.WireGuard.ServerAddress = ""
	node.WireGuard.Relay = panel.WireGuardRelay{
		Backend:         "gost",
		Role:            "exit",
		ServerPort:      8443,
		TunPort:         8421,
		EntryTunAddress: "172.31.66.2/24",
		ExitTunAddress:  "172.31.66.1/24",
		TunName:         "gtwgexitnonat",
		ExitNAT:         false,
	}

	if err := core.AddNode("exit-no-nat", node, &conf.Options{}); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	if err := core.DelNode("exit-no-nat"); err != nil {
		t.Fatalf("DelNode() error = %v", err)
	}
	joined := strings.Join(exec.commands, "\n")
	if !strings.Contains(joined, "iptables -A FORWARD -i gtwgexitnonat -j ACCEPT") {
		t.Fatalf("non-NAT exit did not install its forward rule:\n%s", joined)
	}
	if strings.Contains(joined, "MASQUERADE") {
		t.Fatalf("non-NAT exit installed MASQUERADE:\n%s", joined)
	}
	for _, forbidden := range []string{"ip rule delete", "ip route flush table"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("non-NAT exit touched entry routing via %q:\n%s", forbidden, joined)
		}
	}
}

func testNodeInfo() *panel.NodeInfo {
	common := panel.CommonNode{
		Host:       "entry.example.com",
		ServerPort: 51820,
		ServerName: "entry.example.com",
	}
	wg := &panel.WireGuardNode{
		CommonNode:       common,
		CIDR:             "10.66.0.0/24",
		ServerAddress:    "10.66.0.1/24",
		ServerPrivateKey: testWireGuardKey,
		ServerPublicKey:  derivedTestWireGuardPublicKey(),
		MTU:              1280,
		TunnelType:       "quic",
	}
	return &panel.NodeInfo{
		Id:        1,
		Type:      "wireguard",
		Security:  panel.None,
		Common:    &common,
		WireGuard: wg,
	}
}

const testWireGuardKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
const testWireGuardKeyAlt = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="

func derivedTestWireGuardPublicKey() string {
	decoded, _ := base64.StdEncoding.DecodeString(testWireGuardKey)
	private, _ := ecdh.X25519().NewPrivateKey(decoded)
	return base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())
}
