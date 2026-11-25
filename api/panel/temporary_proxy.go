package panel

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"
)

// TemporaryProxyMinPassword is the shortest password of a temporary proxy;
// the core refuses shorter ones.
const TemporaryProxyMinPassword = 16

// TemporaryProxyMaxLifetime is the longest a temporary proxy may run from
// now; the core refuses one that ends later.
const TemporaryProxyMaxLifetime = 7 * 24 * time.Hour

// TemporaryProxy is one entry of the member "temporary_proxies" of a
// configuration document: a SOCKS5 proxy the node serves on an internal
// address (a mesh virtual address or a LAN address) until ExpiresAtUnixMs,
// for devices of that network to send traffic out through this node. It
// requires the username and password, never listens on a public or
// wildcard address, and ends by itself at its expiry even when Control is
// unreachable.
type TemporaryProxy struct {
	ID              uint64 `json:"id"`
	Listen          string `json:"listen"`
	Port            int    `json:"port"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	ExpiresAtUnixMs int64  `json:"expires_at_unix_ms"`
}

// Expired tells whether the proxy has ended at now.
func (p TemporaryProxy) Expired(now time.Time) bool {
	return now.UnixMilli() >= p.ExpiresAtUnixMs
}

// ParseTemporaryProxies reads the member "temporary_proxies" of a
// configuration document; a document without it has none. Expired entries
// are kept: the core skips them.
func ParseTemporaryProxies(document []byte) ([]TemporaryProxy, error) {
	var holder struct {
		Proxies []TemporaryProxy `json:"temporary_proxies"`
	}
	if err := json.Unmarshal(document, &holder); err != nil {
		return nil, fmt.Errorf("decode the temporary_proxies member: %w", err)
	}
	if err := ValidateTemporaryProxies(holder.Proxies); err != nil {
		return nil, err
	}
	return holder.Proxies, nil
}

// ValidateTemporaryProxies checks every entry: unique ids, an internal
// listen address, a valid port used once per address, a 1-255 byte
// username, a 16-255 byte password and an expiry.
func ValidateTemporaryProxies(proxies []TemporaryProxy) error {
	ids := map[uint64]bool{}
	endpoints := map[netip.AddrPort]bool{}
	for _, proxy := range proxies {
		if proxy.ID == 0 || ids[proxy.ID] {
			return fmt.Errorf("temporary proxy %d: the id is missing or repeated", proxy.ID)
		}
		ids[proxy.ID] = true
		addr, err := netip.ParseAddr(proxy.Listen)
		if err != nil || addr.Zone() != "" {
			return fmt.Errorf("temporary proxy %d: listen %q is not an IP address", proxy.ID, proxy.Listen)
		}
		if !IsInternalAddress(addr) {
			return fmt.Errorf("temporary proxy %d: listen %s is not an internal address", proxy.ID, addr)
		}
		if proxy.Port < 1 || proxy.Port > 65535 {
			return fmt.Errorf("temporary proxy %d: invalid port %d", proxy.ID, proxy.Port)
		}
		endpoint := netip.AddrPortFrom(addr.Unmap(), uint16(proxy.Port))
		if endpoints[endpoint] {
			return fmt.Errorf("temporary proxy %d: %s is used twice", proxy.ID, endpoint)
		}
		endpoints[endpoint] = true
		if len(proxy.Username) == 0 || len(proxy.Username) > 255 {
			return fmt.Errorf("temporary proxy %d: the username must be 1-255 bytes", proxy.ID)
		}
		if len(proxy.Password) < TemporaryProxyMinPassword || len(proxy.Password) > 255 {
			return fmt.Errorf("temporary proxy %d: the password must be 16-255 bytes", proxy.ID)
		}
		if proxy.ExpiresAtUnixMs <= 0 {
			return fmt.Errorf("temporary proxy %d: no expiry", proxy.ID)
		}
	}
	return nil
}

var internalPrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("::1/128"),
}

// IsInternalAddress tells whether addr is loopback, private (RFC 1918),
// shared (100.64.0.0/10), link-local or IPv6 unique local; the addresses
// the core lets a temporary proxy listen on and answer.
func IsInternalAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, prefix := range internalPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
