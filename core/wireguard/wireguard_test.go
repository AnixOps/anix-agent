package wireguard

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
	vCore "github.com/AnixOps/anix-agent/v5/core"
)

type fakeExecutor struct {
	commands     []string
	outputs      map[string][]byte
	failContains []string
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

func TestWireGuard_AddNodeAndUsersApplyConfig(t *testing.T) {
	exec := &fakeExecutor{}
	core := &WireGuard{
		cfg: &conf.WireGuardConfig{
			RuntimeDir: t.TempDir(),
			WGPath:     "wg",
			IPPath:     "ip",
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

// The relay ran on gost and was removed with it: a node that still carries
// relay settings is refused.
func TestValidateWireGuardNodeRefusesTheRemovedRelay(t *testing.T) {
	for _, relay := range []panel.WireGuardRelay{
		{Backend: "gost"},
		{Role: "exit", ServerPort: 8443},
		{Server: "exit.example.com", ServerPort: 8443, TunPort: 8421},
	} {
		node := testNodeInfo()
		node.WireGuard.Relay = relay
		if err := validateWireGuardNode(node); err == nil || !strings.Contains(err.Error(), "relay was removed") {
			t.Fatalf("relay %+v: error = %v", relay, err)
		}
	}
	if err := validateWireGuardNode(testNodeInfo()); err != nil {
		t.Fatalf("plain node: %v", err)
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
