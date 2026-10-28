package anixcore

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
	vCore "github.com/AnixOps/anix-agent/v5/core"
)

// fakeAPI records management API calls and answers like anixcore.
type fakeAPI struct {
	mu       sync.Mutex
	inbounds map[string]map[string]any
	users    map[string]map[string]apiUser
	calls    []string
	egress   []map[string]any
	network  []map[string]any
}

func newFakeAPI(t *testing.T) (*fakeAPI, *httptest.Server) {
	api := &fakeAPI{inbounds: map[string]map[string]any{}, users: map[string]map[string]apiUser{}}
	server := httptest.NewServer(http.HandlerFunc(api.serve))
	t.Cleanup(server.Close)
	return api, server
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer secret" {
		w.WriteHeader(401)
		_, _ = io.WriteString(w, `{"error":"unauthorized"}`)
		return
	}
	f.calls = append(f.calls, r.Method+" "+r.URL.RequestURI())
	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	body, _ := io.ReadAll(r.Body)
	reply := func(status int, value any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(value)
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/v1/status":
		reply(200, map[string]any{"version": "test"})
	case r.Method == "PUT" && r.URL.Path == "/v1/egress":
		var egress map[string]any
		_ = json.Unmarshal(body, &egress)
		f.egress = append(f.egress, egress)
		reply(200, map[string]any{"routes": []int{}, "relays": []any{}})
	case r.Method == "PUT" && r.URL.Path == "/v1/network":
		var plan map[string]any
		_ = json.Unmarshal(body, &plan)
		f.network = append(f.network, plan)
		reply(200, fakeNetworkStatus(plan))
	case r.Method == "GET" && r.URL.Path == "/v1/network":
		var plan map[string]any
		if len(f.network) > 0 {
			plan = f.network[len(f.network)-1]
		}
		reply(200, fakeNetworkStatus(plan))
	case r.Method == "POST" && r.URL.Path == "/v1/inbounds":
		var inbound map[string]any
		_ = json.Unmarshal(body, &inbound)
		tag := inbound["tag"].(string)
		if _, ok := f.inbounds[tag]; ok {
			reply(409, map[string]any{"error": "exists"})
			return
		}
		f.inbounds[tag] = inbound
		f.users[tag] = map[string]apiUser{}
		var withUsers struct {
			Users []apiUser `json:"users"`
		}
		_ = json.Unmarshal(body, &withUsers)
		for _, user := range withUsers.Users {
			f.users[tag][user.Name] = user
		}
		reply(201, map[string]any{"tag": tag})
	case len(segments) >= 3 && segments[1] == "inbounds":
		tag := segments[2]
		if _, ok := f.inbounds[tag]; !ok {
			reply(404, map[string]any{"error": "no such inbound"})
			return
		}
		rest := strings.Join(segments[3:], "/")
		switch {
		case r.Method == "DELETE" && rest == "":
			delete(f.inbounds, tag)
			reply(200, map[string]any{})
		case r.Method == "POST" && rest == "users":
			var add struct {
				Users []apiUser `json:"users"`
			}
			_ = json.Unmarshal(body, &add)
			for _, user := range add.Users {
				f.users[tag][user.Name] = user
			}
			reply(200, map[string]any{"users": len(add.Users)})
		case r.Method == "POST" && rest == "users/remove":
			var remove struct {
				Names []string `json:"names"`
			}
			_ = json.Unmarshal(body, &remove)
			for _, name := range remove.Names {
				delete(f.users[tag], name)
			}
			reply(200, map[string]any{"removed": len(remove.Names)})
		case r.Method == "GET" && rest == "traffic":
			reply(200, map[string]any{"traffic": []map[string]any{
				{"name": "7", "up": 100, "down": 200},
				{"name": "8", "up": 0, "down": 0},
				{"name": "not-a-panel-user", "up": 5, "down": 5},
				{"name": "2147483648", "up": 5, "down": 5},
			}})
		case r.Method == "GET" && rest == "online":
			reply(200, map[string]any{"online": []map[string]any{
				{"name": "7", "ip": "203.0.113.9", "connections": 2},
			}})
		default:
			reply(404, map[string]any{"error": "no such endpoint"})
		}
	default:
		reply(404, map[string]any{"error": "no such endpoint"})
	}
}

func externalCore(t *testing.T, server *httptest.Server) *Core {
	t.Helper()
	core, err := New(&conf.CoreConfig{Type: coreType, AnixcoreConfig: &conf.AnixcoreConfig{
		ApiAddress:          strings.TrimPrefix(server.URL, "http://"),
		ApiToken:            "secret",
		StartTimeoutSeconds: 5,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Start(); err != nil {
		t.Fatal(err)
	}
	return core.(*Core)
}

func shadowsocksNode() *panel.NodeInfo {
	return &panel.NodeInfo{
		Type:   "shadowsocks",
		Common: &panel.CommonNode{ServerPort: 8388},
		Shadowsocks: &panel.ShadowsocksNode{
			Cipher:    "2022-blake3-aes-128-gcm",
			ServerKey: "AAECAwQFBgcICQoLDA0ODw==",
		},
	}
}

func TestShadowsocksNodesStartWithTheirFirstUsers(t *testing.T) {
	api, server := newFakeAPI(t)
	core := externalCore(t, server)
	defer core.Close()

	info := shadowsocksNode()
	if err := core.AddNode("ss", info, &conf.Options{}); err != nil {
		t.Fatal(err)
	}
	if len(api.inbounds) != 0 {
		t.Fatalf("a shadowsocks inbound without users was created: %v", api.inbounds)
	}
	if traffic, err := core.GetUserTrafficSlice("ss", true); err != nil || traffic != nil {
		t.Fatalf("traffic before the inbound exists = %v, %v", traffic, err)
	}
	user := panel.UserInfo{Id: 7, Uuid: "0123456789abcdef0123456789abcdef"}
	added, err := core.AddUsers(&vCore.AddUsersParams{Tag: "ss", Users: []panel.UserInfo{user}, NodeInfo: info})
	if err != nil || added != 1 {
		t.Fatalf("AddUsers = %d, %v", added, err)
	}
	inbound := api.inbounds["ss"]
	if inbound["type"] != "shadowsocks" || inbound["method"] != "2022-blake3-aes-128-gcm" ||
		inbound["password"] != "AAECAwQFBgcICQoLDA0ODw==" || inbound["listen"] != "0.0.0.0" {
		t.Fatalf("inbound = %v", inbound)
	}
	// The user key is the first 16 bytes of the UUID, as the sing-box core
	// derives it.
	if got := api.users["ss"]["7"].Password; got != "MDEyMzQ1Njc4OWFiY2RlZg==" {
		t.Fatalf("user key = %q", got)
	}

	more := panel.UserInfo{Id: 8, Uuid: "fedcba9876543210fedcba9876543210"}
	if _, err := core.AddUsers(&vCore.AddUsersParams{Tag: "ss", Users: []panel.UserInfo{more}, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}
	if len(api.users["ss"]) != 2 {
		t.Fatalf("users = %v", api.users["ss"])
	}

	traffic, err := core.GetUserTrafficSlice("ss", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(traffic) != 1 || traffic[0] != (panel.UserTraffic{UID: 7, Upload: 100, Download: 200}) {
		t.Fatalf("traffic = %v", traffic)
	}
	online, err := core.GetOnlineDevice("ss")
	if err != nil || len(online) != 1 || online[0] != (panel.OnlineUser{UID: 7, IP: "203.0.113.9"}) {
		t.Fatalf("online = %v, %v", online, err)
	}

	if err := core.DelUsers([]panel.UserInfo{user}, "ss", info); err != nil {
		t.Fatal(err)
	}
	if _, ok := api.users["ss"]["7"]; ok {
		t.Fatal("user 7 was not removed")
	}
	if err := core.DelNode("ss"); err != nil {
		t.Fatal(err)
	}
	if len(api.inbounds) != 0 {
		t.Fatalf("inbound not removed: %v", api.inbounds)
	}
	if !strings.Contains(strings.Join(api.calls, "\n"), "traffic?reset=true") {
		t.Fatalf("traffic was not read with reset: %v", api.calls)
	}
}

func TestReplayRestoresNodesAndUsers(t *testing.T) {
	api, server := newFakeAPI(t)
	core := externalCore(t, server)
	defer core.Close()

	info := &panel.NodeInfo{
		Type:   "trojan",
		Common: &panel.CommonNode{ServerPort: 443},
		Trojan: &panel.TrojanNode{Network: "tcp"},
	}
	options := &conf.Options{ListenIP: "::", CertConfig: &conf.CertConfig{
		CertMode: "file", CertFile: "/etc/cert.pem", KeyFile: "/etc/key.pem",
	}}
	if err := core.AddNode("trojan", info, options); err != nil {
		t.Fatal(err)
	}
	user := panel.UserInfo{Id: 3, Uuid: "c9a1e7b0-5b0e-4a4b-9a54-2f3f1c1b0d11"}
	if _, err := core.AddUsers(&vCore.AddUsersParams{Tag: "trojan", Users: []panel.UserInfo{user}, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}

	// A restarted anixcore starts empty.
	api.mu.Lock()
	api.inbounds = map[string]map[string]any{}
	api.users = map[string]map[string]apiUser{}
	api.mu.Unlock()
	if err := core.replay(); err != nil {
		t.Fatal(err)
	}
	if got := api.users["trojan"]["3"].Password; got != user.Uuid {
		t.Fatalf("restored user = %v", api.users["trojan"])
	}
	tls := api.inbounds["trojan"]["tls"].(map[string]any)
	if tls["certificate_path"] != "/etc/cert.pem" || api.inbounds["trojan"]["listen"] != "::" {
		t.Fatalf("restored inbound = %v", api.inbounds["trojan"])
	}
}

func TestStartNeedsBothApiAddressAndToken(t *testing.T) {
	core, _ := New(&conf.CoreConfig{Type: coreType, AnixcoreConfig: &conf.AnixcoreConfig{ApiAddress: "127.0.0.1:1"}})
	if err := core.Start(); err == nil {
		t.Fatal("Start without a token should fail")
	}
}

func TestCoreConfigParsesTheAnixcoreSection(t *testing.T) {
	var config conf.CoreConfig
	if err := json.Unmarshal([]byte(`{"Type":"anixcore","BinaryPath":"/usr/local/bin/anixcore"}`), &config); err != nil {
		t.Fatal(err)
	}
	if config.AnixcoreConfig == nil || config.AnixcoreConfig.BinaryPath != "/usr/local/bin/anixcore" ||
		config.AnixcoreConfig.RuntimeDir == "" || config.AnixcoreConfig.StartTimeoutSeconds != 10 {
		t.Fatalf("config = %+v", config.AnixcoreConfig)
	}
}

func TestEgressIsSentAndReplayed(t *testing.T) {
	api, server := newFakeAPI(t)
	core := externalCore(t, server)
	defer core.Close()

	config := &panel.EgressConfig{
		Routes: []panel.EgressRoute{{ID: 3, Domains: []string{"openai.com", "full:claude.ai"}, Server: panel.EgressServer{
			Host: "203.0.113.5", Port: 9443, Method: "2022-blake3-aes-128-gcm", Password: "AAECAwQFBgcICQoLDA0ODw==",
		}}},
		Relays: []panel.EgressRelay{{ID: 4, Port: 9444, Method: "2022-blake3-aes-128-gcm", Password: "AAECAwQFBgcICQoLDA0ODw=="}},
	}
	if err := core.ApplyEgress(config); err != nil {
		t.Fatal(err)
	}
	if len(api.egress) != 1 {
		t.Fatalf("egress calls = %v", api.egress)
	}
	route := api.egress[0]["routes"].([]any)[0].(map[string]any)
	server0 := route["server"].(map[string]any)
	if route["id"] != float64(3) || server0["host"] != "203.0.113.5" || server0["port"] != float64(9443) {
		t.Fatalf("sent route = %v", route)
	}
	relay := api.egress[0]["relays"].([]any)[0].(map[string]any)
	if relay["id"] != float64(4) || relay["port"] != float64(9444) {
		t.Fatalf("sent relay = %v", relay)
	}

	// A restarted anixcore gets the routes again.
	if err := core.replay(); err != nil {
		t.Fatal(err)
	}
	if len(api.egress) != 2 || len(api.egress[1]["routes"].([]any)) != 1 {
		t.Fatalf("replayed egress = %v", api.egress)
	}

	// No configuration removes everything, with empty lists, and is not
	// replayed.
	if err := core.ApplyEgress(nil); err != nil {
		t.Fatal(err)
	}
	if routes, ok := api.egress[2]["routes"].([]any); !ok || len(routes) != 0 {
		t.Fatalf("cleared egress = %v", api.egress[2])
	}
	if err := core.replay(); err != nil {
		t.Fatal(err)
	}
	if len(api.egress) != 3 {
		t.Fatalf("an empty configuration was replayed: %v", api.egress)
	}

	vless := &panel.EgressConfig{Relays: []panel.EgressRelay{{ID: 5, Protocol: "vless", Port: 1, Method: "m", Password: "k"}}}
	if err := core.ApplyEgress(vless); err == nil || !strings.Contains(err.Error(), "vless") {
		t.Fatalf("an unknown relay protocol = %v", err)
	}
	if len(api.egress) != 3 {
		t.Fatal("a refused configuration reached anixcore")
	}
}

func TestEgressNeedsAnAnixcoreWithTheEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/status" {
			_, _ = io.WriteString(w, `{}`)
			return
		}
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"error":"no such endpoint"}`)
	}))
	defer server.Close()
	core := externalCore(t, server)
	defer core.Close()
	config := &panel.EgressConfig{Relays: []panel.EgressRelay{{ID: 1, Port: 9000, Method: "m", Password: "k"}}}
	if err := core.ApplyEgress(config); err == nil || !strings.Contains(err.Error(), "update it") {
		t.Fatalf("ApplyEgress on an old anixcore = %v", err)
	}
}
