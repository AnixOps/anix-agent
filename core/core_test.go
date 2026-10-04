package core

import (
	"testing"

	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/conf"
	"github.com/stretchr/testify/require"
)

// fakeCore serves protocols and records the nodes added to it.
type fakeCore struct {
	kind      string
	protocols []string
	nodes     []string
}

func (f *fakeCore) Start() error { return nil }
func (f *fakeCore) Close() error { return nil }
func (f *fakeCore) AddNode(tag string, _ *panel.NodeInfo, _ *conf.Options) error {
	f.nodes = append(f.nodes, tag)
	return nil
}
func (f *fakeCore) DelNode(string) error                  { return nil }
func (f *fakeCore) AddUsers(*AddUsersParams) (int, error) { return 0, nil }
func (f *fakeCore) GetUserTrafficSlice(string, bool) ([]panel.UserTraffic, error) {
	return nil, nil
}
func (f *fakeCore) DelUsers([]panel.UserInfo, string, *panel.NodeInfo) error { return nil }
func (f *fakeCore) Protocols() []string                                      { return f.protocols }
func (f *fakeCore) Type() string                                             { return f.kind }

// withCores replaces the registered cores for a test.
func withCores(t *testing.T, made map[string]*fakeCore) {
	t.Helper()
	previous := cores
	cores = map[string]func(*conf.CoreConfig) (Core, error){}
	for name, core := range made {
		core := core
		cores[name] = func(*conf.CoreConfig) (Core, error) { return core, nil }
	}
	t.Cleanup(func() { cores = previous })
}

func TestSelectorPicksTheFirstConfiguredCoreForAProtocol(t *testing.T) {
	xray := &fakeCore{kind: "xray", protocols: []string{"vless", "vmess"}}
	sing := &fakeCore{kind: "sing", protocols: []string{"vless", "hysteria2"}}
	withCores(t, map[string]*fakeCore{"xray": xray, "sing": sing})
	for range 20 {
		xray.nodes, sing.nodes = nil, nil
		selector, err := NewSelector([]conf.CoreConfig{{Type: "sing"}, {Type: "xray"}})
		require.NoError(t, err)
		require.NoError(t, selector.AddNode("a", &panel.NodeInfo{Type: "vless"}, &conf.Options{RawOptions: []byte(`{}`)}))
		require.NoError(t, selector.AddNode("b", &panel.NodeInfo{Type: "vmess"}, &conf.Options{RawOptions: []byte(`{}`)}))
		require.Equal(t, []string{"a"}, sing.nodes, "vless runs on the first configured core")
		require.Equal(t, []string{"b"}, xray.nodes)
	}
}

func TestNewForConfigRunsEveryCompiledInCoreWithoutConfiguredCores(t *testing.T) {
	xray := &fakeCore{kind: "xray", protocols: []string{"vless"}}
	sing := &fakeCore{kind: "sing", protocols: []string{"vless", "hysteria2"}}
	wireguard := &fakeCore{kind: "wireguard", protocols: []string{"wireguard"}}
	withCores(t, map[string]*fakeCore{"wireguard": wireguard, "sing": sing, "xray": xray})

	defaults, err := DefaultCoreConfigs()
	require.NoError(t, err)
	var order []string
	for _, config := range defaults {
		order = append(order, config.Type)
	}
	require.Equal(t, []string{"xray", "sing", "wireguard"}, order)

	built, err := NewForConfig(nil, 1)
	require.NoError(t, err)
	selector, ok := built.(*Selector)
	require.True(t, ok, "always a Selector: nodes name no core")
	for tag, protocol := range map[string]string{"v": "vless", "h": "hysteria2", "w": "wireguard"} {
		require.NoError(t, selector.AddNode(tag, &panel.NodeInfo{Type: protocol}, &conf.Options{RawOptions: []byte(`{}`)}))
	}
	require.Equal(t, []string{"v"}, xray.nodes)
	require.Equal(t, []string{"h"}, sing.nodes)
	require.Equal(t, []string{"w"}, wireguard.nodes)

	// A forward node only (no proxy node) runs no core at all, and a
	// configuration with cores keeps them.
	_, err = NewForConfig(nil, 0)
	require.Error(t, err)
	built, err = NewForConfig([]conf.CoreConfig{{Type: "sing"}}, 1)
	require.NoError(t, err)
	require.Same(t, sing, built)
}

func TestDefaultCoreConfigsCarryTheCoreDefaults(t *testing.T) {
	withCores(t, map[string]*fakeCore{"xray": {}, "sing": {}, "hysteria2": {}, "wireguard": {}})
	defaults, err := DefaultCoreConfigs()
	require.NoError(t, err)
	require.Len(t, defaults, 4)
	require.NotNil(t, defaults[0].XrayConfig)
	require.NotNil(t, defaults[1].SingConfig)
	require.NotNil(t, defaults[2].Hysteria2Config)
	require.NotNil(t, defaults[3].WireGuardConfig)
}
