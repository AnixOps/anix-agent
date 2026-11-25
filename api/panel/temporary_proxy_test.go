package panel

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParseTemporaryProxies(t *testing.T) {
	none, err := ParseTemporaryProxies([]byte(`{"kind":"proxy"}`))
	if err != nil || len(none) != 0 {
		t.Fatalf("no member: %v %v", none, err)
	}
	parsed, err := ParseTemporaryProxies([]byte(`{"temporary_proxies":[
		{"id":7,"listen":"10.126.126.1","port":1080,"username":"tmp-7","password":"0123456789abcdef","expires_at_unix_ms":1764045000000}]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := TemporaryProxy{ID: 7, Listen: "10.126.126.1", Port: 1080, Username: "tmp-7", Password: "0123456789abcdef", ExpiresAtUnixMs: 1764045000000}
	if len(parsed) != 1 || parsed[0] != want {
		t.Fatalf("parsed %+v", parsed)
	}
}

func TestValidateTemporaryProxies(t *testing.T) {
	ok := TemporaryProxy{ID: 1, Listen: "100.64.0.5", Port: 1080, Username: "u", Password: strings.Repeat("p", 16), ExpiresAtUnixMs: 1}
	if err := ValidateTemporaryProxies([]TemporaryProxy{ok}); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(p *TemporaryProxy){
		"no id":          func(p *TemporaryProxy) { p.ID = 0 },
		"not an address": func(p *TemporaryProxy) { p.Listen = "mesh.local" },
		"wildcard v4":    func(p *TemporaryProxy) { p.Listen = "0.0.0.0" },
		"wildcard v6":    func(p *TemporaryProxy) { p.Listen = "::" },
		"public":         func(p *TemporaryProxy) { p.Listen = "8.8.8.8" },
		"public v6":      func(p *TemporaryProxy) { p.Listen = "2001:db8::1" },
		"zone":           func(p *TemporaryProxy) { p.Listen = "fe80::1%eth0" },
		"port":           func(p *TemporaryProxy) { p.Port = 0 },
		"big port":       func(p *TemporaryProxy) { p.Port = 65536 },
		"no username":    func(p *TemporaryProxy) { p.Username = "" },
		"long username":  func(p *TemporaryProxy) { p.Username = strings.Repeat("u", 256) },
		"short password": func(p *TemporaryProxy) { p.Password = "short" },
		"no expiry":      func(p *TemporaryProxy) { p.ExpiresAtUnixMs = 0 },
	}
	for name, change := range cases {
		proxy := ok
		change(&proxy)
		if err := ValidateTemporaryProxies([]TemporaryProxy{proxy}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	second := ok
	if err := ValidateTemporaryProxies([]TemporaryProxy{ok, second}); err == nil {
		t.Error("repeated id accepted")
	}
	second.ID = 2
	if err := ValidateTemporaryProxies([]TemporaryProxy{ok, second}); err == nil {
		t.Error("repeated address and port accepted")
	}
	second.Port = 1081
	if err := ValidateTemporaryProxies([]TemporaryProxy{ok, second}); err != nil {
		t.Errorf("two ports: %v", err)
	}
}

func TestIsInternalAddress(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.0.0.1", "172.31.0.1", "192.168.0.1", "100.100.0.1", "169.254.0.1", "::1", "fd12::1", "fe80::1", "::ffff:10.0.0.1"} {
		if !IsInternalAddress(netip.MustParseAddr(s)) {
			t.Errorf("%s is internal", s)
		}
	}
	for _, s := range []string{"0.0.0.0", "::", "1.1.1.1", "100.128.0.1", "172.32.0.1", "2001:db8::1", "::ffff:8.8.8.8"} {
		if IsInternalAddress(netip.MustParseAddr(s)) {
			t.Errorf("%s is not internal", s)
		}
	}
}

func TestTemporaryProxyExpired(t *testing.T) {
	now := time.UnixMilli(1000)
	if (TemporaryProxy{ExpiresAtUnixMs: 1001}).Expired(now) {
		t.Error("expired early")
	}
	if !(TemporaryProxy{ExpiresAtUnixMs: 1000}).Expired(now) {
		t.Error("not expired at its time")
	}
}
