// Package realityprobe runs the reality.probe check of the agent.diagnostic
// operation (anix-control sdk/api/agent/v1/PROTOCOL.md, "Reality target
// probe"): from the node's own network it tells whether a site can serve as
// a REALITY target (dest and SNI) for the node's inbounds.
//
// A probe names a host, never an address: the Agent resolves it with the
// node's resolver and refuses an answer that is not a public address, so
// Control cannot make the node dial into its own network. It dials one
// address, completes one TLS handshake and sends one GET /.
//
// A target passes when it answers TLS 1.3 with ALPN h2 and an X25519 key
// exchange (X25519 or X25519MLKEM768), its certificate verifies for the
// name, and GET / does not redirect to another host. The rest of the
// result (latency, OCSP stapling, chain size, CDN) is for Control's
// ranking. The probe is the Agent's own Go code, not a call into a proxy
// core, so it stays the same whichever core the node runs.
package realityprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Action is the check's action and Capability the capability an Agent that
// runs it lists.
const (
	Action     = "reality.probe"
	Capability = "reality.probe"
)

const (
	defaultTimeout = 5 * time.Second
	minTimeout     = 100 * time.Millisecond
	maxTimeout     = 10 * time.Second
	// maxCertNames bounds the certificate's names in a result.
	maxCertNames = 20
	// userAgent is the GET's: a current desktop browser's.
	userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)

// The hard requirements a target fails, as Result.Failures lists them.
const (
	FailResolve        = "resolve"
	FailPrivateAddress = "private_address"
	FailConnect        = "connect"
	FailHandshake      = "tls_handshake"
	FailTLS13          = "tls13"
	FailH2             = "h2"
	FailX25519         = "x25519"
	FailCertificate    = "certificate"
	FailHTTP           = "http"
	FailRedirect       = "redirect"
)

// The verdicts of the diagnostic answer.
const (
	VerdictOK     = "ok"
	VerdictFailed = "failed"
)

// Result is a probe's answer, the diagnostic state's result.
type Result struct {
	ServerName string `json:"server_name"`
	Port       int    `json:"port"`
	// Address is the address dialled.
	Address  string   `json:"address,omitempty"`
	Verdict  string   `json:"verdict"`
	Failures []string `json:"failures,omitempty"`
	// Error says what went wrong at the first failure.
	Error          string     `json:"error,omitempty"`
	ConnectMS      int64      `json:"connect_ms,omitempty"`
	HandshakeMS    int64      `json:"handshake_ms,omitempty"`
	TLSVersion     string     `json:"tls_version,omitempty"`
	ALPN           string     `json:"alpn,omitempty"`
	Curve          string     `json:"curve,omitempty"`
	CertNames      []string   `json:"cert_names,omitempty"`
	CertIssuer     string     `json:"cert_issuer,omitempty"`
	CertNotAfter   *time.Time `json:"cert_not_after,omitempty"`
	CertChainBytes int        `json:"cert_chain_bytes,omitempty"`
	OCSPStapled    bool       `json:"ocsp_stapled,omitempty"`
	HTTPStatus     int        `json:"http_status,omitempty"`
	RedirectHost   string     `json:"redirect_host,omitempty"`
	ServerHeader   string     `json:"server_header,omitempty"`
	// CDN names the CDN the response headers show the site behind.
	CDN string `json:"cdn,omitempty"`
}

func (r *Result) fail(code string, err error) {
	r.Failures = append(r.Failures, code)
	if r.Error == "" && err != nil {
		r.Error = err.Error()
	}
}

// Prober runs reality.probe; the zero value probes with the system's
// resolver and roots.
type Prober struct {
	// Lookup resolves a host; nil uses net.DefaultResolver.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// RootCAs verifies certificates; nil uses the system roots.
	RootCAs *x509.CertPool
	// AllowPrivate lets a probe dial a non-public address (tests).
	AllowPrivate bool
}

// IsCheck reports whether action is reality.probe.
func (p *Prober) IsCheck(action string) bool { return action == Action }

// Check runs one probe (diagnostic.Checker). It fails only on malformed
// parameters; a target that does not pass is a "failed" verdict.
func (p *Prober) Check(ctx context.Context, action string, params map[string]any) (any, string, string, error) {
	if action != Action {
		return nil, "", "", fmt.Errorf("%q is not %s", action, Action)
	}
	host, port, timeout, err := ParseParams(params)
	if err != nil {
		return nil, "", "", err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result := p.Probe(ctx, host, port)
	return result, result.Verdict, Summary(result), nil
}

// ParseParams reads server_name (a host name, not an address), port (443
// when absent) and timeout_ms (5000 when absent, clamped to 100 to 10000).
func ParseParams(params map[string]any) (host string, port int, timeout time.Duration, err error) {
	host, _ = params["server_name"].(string)
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if !validHostName(host) {
		return "", 0, 0, errors.New("server_name must be a host name")
	}
	port = 443
	if raw, ok := params["port"]; ok {
		n, ok := wholeNumber(raw)
		if !ok || n < 1 || n > 65535 {
			return "", 0, 0, errors.New("port must be an integer from 1 to 65535")
		}
		port = int(n)
	}
	timeout = defaultTimeout
	if raw, ok := params["timeout_ms"]; ok {
		n, ok := wholeNumber(raw)
		if !ok {
			return "", 0, 0, errors.New("timeout_ms must be an integer")
		}
		timeout = min(max(time.Duration(n)*time.Millisecond, minTimeout), maxTimeout)
	}
	return host, port, timeout, nil
}

// validHostName accepts a DNS name with at least one dot and no address.
func validHostName(host string) bool {
	if len(host) == 0 || len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func wholeNumber(raw any) (int64, bool) {
	switch v := raw.(type) {
	case int:
		return int64(v), true
	case int64:
		return v, true
	case float64:
		if v != float64(int64(v)) {
			return 0, false
		}
		return int64(v), true
	}
	return 0, false
}

// Probe probes host:port until ctx ends.
func (p *Prober) Probe(ctx context.Context, host string, port int) *Result {
	result := &Result{ServerName: host, Port: port}
	defer func() {
		result.Verdict = VerdictOK
		if len(result.Failures) > 0 {
			result.Verdict = VerdictFailed
		}
	}()

	addr, err := p.resolve(ctx, host)
	if err != nil {
		code := FailResolve
		if errors.Is(err, errNotPublic) {
			code = FailPrivateAddress
		}
		result.fail(code, err)
		return result
	}
	address := net.JoinHostPort(addr.String(), strconv.Itoa(port))
	result.Address = address

	started := time.Now()
	var dialer net.Dialer
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		result.fail(FailConnect, err)
		return result
	}
	result.ConnectMS = time.Since(started).Milliseconds()

	conn := tls.Client(raw, &tls.Config{
		ServerName: host,
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
		// The chain is verified below, so that a target with a bad
		// certificate still answers what it negotiated.
		InsecureSkipVerify: true, // #nosec G402 -- verified against RootCAs after the handshake.
	})
	defer conn.Close()
	started = time.Now()
	if err := conn.HandshakeContext(ctx); err != nil {
		result.fail(FailHandshake, err)
		return result
	}
	result.HandshakeMS = time.Since(started).Milliseconds()

	state := conn.ConnectionState()
	result.TLSVersion = tls.VersionName(state.Version)
	result.ALPN = state.NegotiatedProtocol
	result.Curve = state.CurveID.String()
	result.OCSPStapled = len(state.OCSPResponse) > 0
	if state.Version != tls.VersionTLS13 {
		result.fail(FailTLS13, fmt.Errorf("negotiated %s, not TLS 1.3", result.TLSVersion))
	}
	if state.NegotiatedProtocol != "h2" {
		result.fail(FailH2, fmt.Errorf("ALPN %q, not h2", state.NegotiatedProtocol))
	}
	if state.CurveID != tls.X25519 && state.CurveID != tls.X25519MLKEM768 {
		result.fail(FailX25519, fmt.Errorf("key exchange %s, not X25519", result.Curve))
	}
	p.certificate(result, state)

	if state.NegotiatedProtocol == "h2" {
		p.get(ctx, result, conn)
	}
	return result
}

var errNotPublic = errors.New("the name resolves to no public address")

// resolve answers the host's first public address, IPv4 first.
func (p *Prober) resolve(ctx context.Context, host string) (netip.Addr, error) {
	var addrs []netip.Addr
	var err error
	if p.Lookup != nil {
		addrs, err = p.Lookup(ctx, host)
	} else {
		addrs, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	if err != nil {
		return netip.Addr{}, err
	}
	var v6 netip.Addr
	for _, addr := range addrs {
		addr = addr.Unmap()
		if !p.AllowPrivate && !PublicAddr(addr) {
			continue
		}
		if addr.Is4() {
			return addr, nil
		}
		if !v6.IsValid() {
			v6 = addr
		}
	}
	if v6.IsValid() {
		return v6, nil
	}
	if len(addrs) == 0 {
		return netip.Addr{}, errors.New("the name has no address")
	}
	return netip.Addr{}, fmt.Errorf("%w (%s)", errNotPublic, addrs[0])
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// PublicAddr reports whether addr is a global unicast address outside the
// private, shared and reserved ranges.
func PublicAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, prefix := range nonPublic {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// certificate records the chain and verifies it for the result's name.
func (p *Prober) certificate(result *Result, state tls.ConnectionState) {
	if len(state.PeerCertificates) == 0 {
		result.fail(FailCertificate, errors.New("no certificate"))
		return
	}
	leaf := state.PeerCertificates[0]
	for _, cert := range state.PeerCertificates {
		result.CertChainBytes += len(cert.Raw)
	}
	result.CertNames = leaf.DNSNames
	if len(result.CertNames) > maxCertNames {
		result.CertNames = result.CertNames[:maxCertNames]
	}
	result.CertIssuer = leaf.Issuer.CommonName
	if len(leaf.Issuer.Organization) > 0 {
		result.CertIssuer = leaf.Issuer.Organization[0]
	}
	notAfter := leaf.NotAfter.UTC()
	result.CertNotAfter = &notAfter

	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: result.ServerName, Roots: p.RootCAs, Intermediates: intermediates}); err != nil {
		result.fail(FailCertificate, err)
	}
}

// get sends GET / over the probe's connection and records the answer.
func (p *Prober) get(ctx context.Context, result *Result, conn *tls.Conn) {
	used := false
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			if used {
				return nil, errors.New("the probe has one connection")
			}
			used = true
			return conn, nil
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	target := url.URL{Scheme: "https", Host: result.ServerName, Path: "/"}
	if result.Port != 443 {
		target.Host = net.JoinHostPort(result.ServerName, strconv.Itoa(result.Port))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		result.fail(FailHTTP, err)
		return
	}
	request.Header.Set("User-Agent", userAgent)
	request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	response, err := client.Do(request)
	if err != nil {
		result.fail(FailHTTP, err)
		return
	}
	defer response.Body.Close()
	_, _ = io.CopyN(io.Discard, response.Body, 64<<10)

	result.HTTPStatus = response.StatusCode
	result.ServerHeader = response.Header.Get("Server")
	result.CDN = detectCDN(response.Header)
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		location, err := request.URL.Parse(response.Header.Get("Location"))
		if err == nil && location.Hostname() != "" {
			result.RedirectHost = strings.ToLower(location.Hostname())
			if !SameSite(result.ServerName, result.RedirectHost) {
				result.fail(FailRedirect, fmt.Errorf("GET / redirects to %s", result.RedirectHost))
			}
		}
	}
}

// SameSite reports whether two host names differ at most by a leading
// "www.".
func SameSite(a, b string) bool {
	return strings.TrimPrefix(a, "www.") == strings.TrimPrefix(b, "www.")
}

// detectCDN names the CDN a response's headers show.
func detectCDN(header http.Header) string {
	server := strings.ToLower(header.Get("Server"))
	switch {
	case header.Get("Cf-Ray") != "" || server == "cloudflare":
		return "cloudflare"
	case header.Get("X-Amz-Cf-Id") != "" || strings.Contains(server, "cloudfront"):
		return "cloudfront"
	case strings.Contains(strings.ToLower(header.Get("Via")), "varnish") && header.Get("X-Served-By") != "" || strings.Contains(server, "fastly"):
		return "fastly"
	case strings.HasPrefix(server, "akamai"):
		return "akamai"
	}
	return ""
}

// Summary is a one-line account of a result.
func Summary(result *Result) string {
	target := net.JoinHostPort(result.ServerName, strconv.Itoa(result.Port))
	if result.Verdict == VerdictOK {
		return fmt.Sprintf("%s ok: %s, %s, %s, handshake %d ms", target, result.TLSVersion, result.ALPN, result.Curve, result.HandshakeMS)
	}
	summary := fmt.Sprintf("%s failed: %s", target, strings.Join(result.Failures, ", "))
	if result.Error != "" {
		summary += " (" + result.Error + ")"
	}
	return summary
}
