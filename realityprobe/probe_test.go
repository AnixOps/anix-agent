package realityprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"
)

// site starts an HTTPS test server (certificate for example.com) and a
// Prober that resolves example.com to it.
func site(t *testing.T, h2 bool, maxVersion uint16, handler http.HandlerFunc) (*Prober, int) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = h2
	server.TLS = &tls.Config{MaxVersion: maxVersion}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	n, _ := strconv.Atoi(port)
	prober := &Prober{
		RootCAs:      roots,
		AllowPrivate: true,
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
	}
	return prober, n
}

func ok(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

func TestProbePasses(t *testing.T) {
	prober, port := site(t, true, 0, ok)
	result, verdict, summary, err := prober.Check(context.Background(), Action, map[string]any{"server_name": "Example.COM.", "port": float64(port)})
	if err != nil {
		t.Fatal(err)
	}
	r := result.(*Result)
	if verdict != VerdictOK || r.Verdict != VerdictOK || len(r.Failures) != 0 {
		t.Fatalf("verdict %s, %+v", verdict, r)
	}
	if r.ServerName != "example.com" || r.TLSVersion != "TLS 1.3" || r.ALPN != "h2" || r.HTTPStatus != 200 || r.CertChainBytes == 0 || r.CertNotAfter == nil {
		t.Fatalf("result %+v", r)
	}
	if r.Curve != tls.X25519MLKEM768.String() && r.Curve != tls.X25519.String() {
		t.Fatalf("curve %s", r.Curve)
	}
	if !slices.Contains(r.CertNames, "example.com") {
		t.Fatalf("names %v", r.CertNames)
	}
	if summary == "" {
		t.Fatal("no summary")
	}
}

func TestProbeHardRequirements(t *testing.T) {
	t.Run("http/1.1 only", func(t *testing.T) {
		prober, port := site(t, false, 0, ok)
		r := prober.Probe(context.Background(), "example.com", port)
		if r.Verdict != VerdictFailed || !slices.Contains(r.Failures, FailH2) || r.HTTPStatus != 0 {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("TLS 1.2", func(t *testing.T) {
		prober, port := site(t, true, tls.VersionTLS12, ok)
		r := prober.Probe(context.Background(), "example.com", port)
		if !slices.Contains(r.Failures, FailTLS13) {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("redirect elsewhere", func(t *testing.T) {
		prober, port := site(t, true, 0, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://login.other.net/", http.StatusFound)
		})
		r := prober.Probe(context.Background(), "example.com", port)
		if !slices.Contains(r.Failures, FailRedirect) || r.RedirectHost != "login.other.net" {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("redirect to www", func(t *testing.T) {
		prober, port := site(t, true, 0, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://www.example.com/", http.StatusMovedPermanently)
		})
		r := prober.Probe(context.Background(), "example.com", port)
		if r.Verdict != VerdictOK || r.RedirectHost != "www.example.com" {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("certificate for another name", func(t *testing.T) {
		prober, port := site(t, true, 0, ok)
		r := prober.Probe(context.Background(), "wrong.test", port)
		if !slices.Equal(r.Failures, []string{FailCertificate}) || r.Verdict != VerdictFailed {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("cdn", func(t *testing.T) {
		prober, port := site(t, true, 0, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Server", "cloudflare")
			w.Header().Set("Cf-Ray", "1-AMS")
		})
		r := prober.Probe(context.Background(), "example.com", port)
		if r.Verdict != VerdictOK || r.CDN != "cloudflare" {
			t.Fatalf("%+v", r)
		}
	})
}

func TestProbeRefusesPrivateAddresses(t *testing.T) {
	prober := &Prober{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("100.64.1.1")}, nil
	}}
	r := prober.Probe(context.Background(), "intranet.example.com", 443)
	if r.Verdict != VerdictFailed || !slices.Equal(r.Failures, []string{FailPrivateAddress}) || r.Address != "" {
		t.Fatalf("%+v", r)
	}
}

func TestProbeConnectFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	prober := &Prober{AllowPrivate: true, Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r := prober.Probe(ctx, "example.com", port)
	if !slices.Equal(r.Failures, []string{FailConnect}) {
		t.Fatalf("%+v", r)
	}
}

func TestParseParams(t *testing.T) {
	for name, params := range map[string]map[string]any{
		"missing":     {},
		"address":     {"server_name": "1.2.3.4"},
		"v6 address":  {"server_name": "::1"},
		"no dot":      {"server_name": "localhost"},
		"bad label":   {"server_name": "-a.example.com"},
		"with port":   {"server_name": "example.com:443"},
		"port range":  {"server_name": "example.com", "port": float64(70000)},
		"port float":  {"server_name": "example.com", "port": 443.5},
		"timeout str": {"server_name": "example.com", "timeout_ms": "5"},
	} {
		if _, _, _, err := ParseParams(params); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	host, port, timeout, err := ParseParams(map[string]any{"server_name": "www.Example.com", "timeout_ms": float64(50)})
	if err != nil || host != "www.example.com" || port != 443 || timeout != minTimeout {
		t.Fatalf("%s %d %s %v", host, port, timeout, err)
	}
}

func TestPublicAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1111": true, "10.1.2.3": false, "192.168.1.1": false, "127.0.0.1": false,
		"169.254.1.1": false, "100.64.0.1": false, "0.0.0.0": false, "fd00::1": false, "::ffff:10.0.0.1": false, "224.0.0.1": false,
	} {
		if got := PublicAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: %v", addr, got)
		}
	}
}
