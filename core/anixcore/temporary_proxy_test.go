package anixcore

import (
	"strings"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
)

func temporaryProxyAPI(t *testing.T) (*fakeAPI, *Core) {
	t.Helper()
	api, server := newFakeAPI(t)
	api.features = []string{inboundExpiryFeature}
	api.types = []string{"shadowsocks", socksType}
	core := externalCore(t, server)
	t.Cleanup(func() { _ = core.Close() })
	return api, core
}

func setClock(t *testing.T, at time.Time) {
	t.Helper()
	previous := temporaryProxyNow
	temporaryProxyNow = func() time.Time { return at }
	t.Cleanup(func() { temporaryProxyNow = previous })
}

func testProxy(id uint64, port int, expires time.Time) panel.TemporaryProxy {
	return panel.TemporaryProxy{
		ID: id, Listen: "10.126.126.1", Port: port, Username: "tmp-u",
		Password: "0123456789abcdef", ExpiresAtUnixMs: expires.UnixMilli(),
	}
}

func TestTemporaryProxiesRunAsExpiringSocksInbounds(t *testing.T) {
	api, core := temporaryProxyAPI(t)
	start := time.UnixMilli(1_764_000_000_000)
	setClock(t, start)
	end := start.Add(15 * time.Minute)
	if err := core.ApplyTemporaryProxies([]panel.TemporaryProxy{testProxy(7, 1080, end)}); err != nil {
		t.Fatal(err)
	}
	inbound := api.inbounds["tmp-socks-7"]
	if inbound == nil {
		t.Fatalf("inbounds = %v", api.inbounds)
	}
	if inbound["type"] != "socks" || inbound["listen"] != "10.126.126.1" || inbound["listen_port"] != float64(1080) ||
		inbound["expires_at_ms"] != float64(end.UnixMilli()) {
		t.Fatalf("inbound = %v", inbound)
	}
	if user := api.users["tmp-socks-7"]["7"]; user.Password != "0123456789abcdef" {
		t.Fatalf("users = %+v", api.users["tmp-socks-7"])
	}
	users := inbound["users"].([]any)
	if users[0].(map[string]any)["username"] != "tmp-u" {
		t.Fatalf("users = %v", users)
	}

	// The same set again changes nothing.
	calls := len(api.calls)
	if err := core.ApplyTemporaryProxies([]panel.TemporaryProxy{testProxy(7, 1080, end)}); err != nil {
		t.Fatal(err)
	}
	if len(api.calls) != calls {
		t.Fatalf("calls = %v", api.calls[calls:])
	}

	// A changed proxy is removed and added again; a new one is added.
	longer := end.Add(15 * time.Minute)
	if err := core.ApplyTemporaryProxies([]panel.TemporaryProxy{testProxy(7, 1080, longer), testProxy(8, 1081, end)}); err != nil {
		t.Fatal(err)
	}
	if api.inbounds["tmp-socks-7"]["expires_at_ms"] != float64(longer.UnixMilli()) || api.inbounds["tmp-socks-8"] == nil {
		t.Fatalf("inbounds = %v", api.inbounds)
	}

	// A restarted anixcore gets the proxies that have not expired.
	setClock(t, end.Add(time.Minute))
	api.inbounds = map[string]map[string]any{}
	if err := core.replay(); err != nil {
		t.Fatal(err)
	}
	if api.inbounds["tmp-socks-7"] == nil || api.inbounds["tmp-socks-8"] != nil {
		t.Fatalf("replayed inbounds = %v", api.inbounds)
	}

	// Gone from the configuration: removed. anixcore may have dropped it
	// already (404), which is fine, and it is not replayed.
	delete(api.inbounds, "tmp-socks-7")
	if err := core.ApplyTemporaryProxies(nil); err != nil {
		t.Fatal(err)
	}
	if err := core.replay(); err != nil {
		t.Fatal(err)
	}
	if len(api.inbounds) != 0 {
		t.Fatalf("inbounds = %v", api.inbounds)
	}
}

func TestExpiredOrInvalidTemporaryProxiesAreNotSent(t *testing.T) {
	api, core := temporaryProxyAPI(t)
	now := time.UnixMilli(1_764_000_000_000)
	setClock(t, now)
	if err := core.ApplyTemporaryProxies([]panel.TemporaryProxy{testProxy(1, 1080, now)}); err != nil {
		t.Fatal(err)
	}
	if len(api.inbounds) != 0 {
		t.Fatalf("an expired proxy was sent: %v", api.inbounds)
	}
	tooLong := testProxy(2, 1080, now.Add(8*24*time.Hour))
	if err := core.ApplyTemporaryProxies([]panel.TemporaryProxy{tooLong}); err == nil || !strings.Contains(err.Error(), "seven days") {
		t.Fatalf("a proxy for eight days = %v", err)
	}
	public := testProxy(3, 1080, now.Add(time.Hour))
	public.Listen = "0.0.0.0"
	if err := core.ApplyTemporaryProxies([]panel.TemporaryProxy{public}); err == nil {
		t.Fatal("a wildcard listen address was accepted")
	}
	if len(api.inbounds) != 0 {
		t.Fatalf("inbounds = %v", api.inbounds)
	}
}

func TestTemporaryProxiesNeedAKernelWithSocks(t *testing.T) {
	api, server := newFakeAPI(t)
	api.features = []string{inboundExpiryFeature}
	core := externalCore(t, server)
	defer core.Close()
	now := time.UnixMilli(1_764_000_000_000)
	setClock(t, now)
	err := core.ApplyTemporaryProxies([]panel.TemporaryProxy{testProxy(1, 1080, now.Add(time.Hour))})
	if err == nil || !strings.Contains(err.Error(), "update it") {
		t.Fatalf("err = %v", err)
	}
	// Nothing to run is fine on any kernel.
	if err := core.ApplyTemporaryProxies(nil); err != nil {
		t.Fatal(err)
	}
}
