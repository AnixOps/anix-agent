package xray

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
	"github.com/stretchr/testify/require"
	"github.com/xtls/xray-core/features/routing"
	coreConf "github.com/xtls/xray-core/infra/conf"
	"golang.org/x/net/proxy"
)

const egressMethod = "2022-blake3-aes-128-gcm"

func egressKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 16)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(key)
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// startEgressCore starts an Xray core with a direct default outbound and a
// SOCKS inbound on 127.0.0.1 standing in for a node's protocol inbound.
func startEgressCore(t *testing.T) (*Xray, int) {
	t.Helper()
	config := &conf.CoreConfig{Type: "xray", XrayConfig: conf.NewXrayConfig()}
	config.XrayConfig.LogConfig.Level = "error"
	made, err := New(config)
	require.NoError(t, err)
	core := made.(*Xray)
	require.NoError(t, core.Start())
	t.Cleanup(func() { _ = core.Close() })

	var direct coreConf.OutboundDetourConfig
	require.NoError(t, json.Unmarshal([]byte(`{"tag":"direct","protocol":"freedom","settings":{}}`), &direct))
	built, err := direct.Build()
	require.NoError(t, err)
	require.NoError(t, core.addOutbound(built))

	socksPort := freePort(t)
	var socks coreConf.InboundDetourConfig
	require.NoError(t, json.Unmarshal([]byte(fmt.Sprintf(
		`{"tag":"test-socks","protocol":"socks","listen":"127.0.0.1","port":%d,"settings":{"auth":"noauth"}}`, socksPort)), &socks))
	inbound, err := socks.Build()
	require.NoError(t, err)
	require.NoError(t, core.addInbound(inbound))
	return core, socksPort
}

func getThroughSocks(t *testing.T, socksPort int, target string) (string, error) {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, proxy.Direct)
	require.NoError(t, err)
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{Dial: dialer.Dial},
	}
	response, err := client.Get(target)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	return string(body), err
}

func TestApplyEgressSendsTheRouteDomainsThroughTheRelay(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "reached")
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)
	_, backendPort, err := net.SplitHostPort(backendURL.Host)
	require.NoError(t, err)
	target := "http://localhost:" + backendPort + "/"

	core, socksPort := startEgressCore(t)
	key := egressKey(t)
	relayPort := freePort(t)
	config := &panel.EgressConfig{
		Relays: []panel.EgressRelay{{ID: 7, Port: relayPort, Method: egressMethod, Password: key}},
		Routes: []panel.EgressRoute{{ID: 7, Domains: []string{"localhost"},
			Server: panel.EgressServer{Protocol: panel.EgressProtocolShadowsocks, Host: "127.0.0.1", Port: relayPort, Method: egressMethod, Password: key}}},
	}
	require.NoError(t, core.ApplyEgress(config))
	require.NotNil(t, core.ohm.GetHandler(egressOutboundTag(7)))
	body, err := getThroughSocks(t, socksPort, target)
	require.NoError(t, err)
	require.Equal(t, "reached", body)

	// A route whose key the relay refuses: the domain now fails, which
	// shows it went through the relay rather than the direct outbound.
	config.Routes[0].Server.Password = egressKey(t)
	require.NoError(t, core.ApplyEgress(config))
	_, err = getThroughSocks(t, socksPort, target)
	require.Error(t, err)

	// Without the route the domain leaves directly again.
	require.NoError(t, core.ApplyEgress(&panel.EgressConfig{Relays: config.Relays}))
	require.Nil(t, core.ohm.GetHandler(egressOutboundTag(7)))
	body, err = getThroughSocks(t, socksPort, target)
	require.NoError(t, err)
	require.Equal(t, "reached", body)

	// An empty configuration removes the relay too.
	require.NoError(t, core.ApplyEgress(nil))
	_, err = core.ihm.GetHandler(t.Context(), egressRelayTag(7))
	require.Error(t, err)
	router := core.Server.GetFeature(routing.RouterType()).(routing.Router)
	require.NotNil(t, router)
}

func TestApplyEgressRefusesAnInvalidConfiguration(t *testing.T) {
	core, _ := startEgressCore(t)
	err := core.ApplyEgress(&panel.EgressConfig{Routes: []panel.EgressRoute{{ID: 1,
		Server: panel.EgressServer{Host: "127.0.0.1", Port: 1, Method: egressMethod, Password: "x"}}}})
	require.ErrorContains(t, err, "no domains")
}

func TestApplyEgressRefusesAnUnknownRelayProtocol(t *testing.T) {
	core, _ := startEgressCore(t)
	err := core.ApplyEgress(&panel.EgressConfig{Relays: []panel.EgressRelay{{ID: 1, Protocol: "vless", Port: freePort(t), Method: egressMethod, Password: egressKey(t)}}})
	require.ErrorContains(t, err, `no relay protocol "vless"`)
}

func TestEgressDomains(t *testing.T) {
	require.Equal(t, []string{"domain:openai.com", "full:api.x.ai", "domain:claude.ai", "keyword:gemini"},
		egressDomains([]string{" OpenAI.com", "full:api.x.ai", ".claude.ai", "", "keyword:gemini"}))
}
