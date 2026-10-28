// Package anxline is the host side of ANX-Line links (anx docs/ANX-LINE-SPEC
// §4.2, §5, §9 TBD-L11 and TBD-L14): the Agent installs the nftables rules
// that drop the kernel's RST segments for fake-TCP carriers (C3), and watches
// each MPTCP path of a multipath link every 200 ms, taking a dead path out of
// the kernel's MPTCP endpoints (`ip mptcp endpoint delete` or `change …
// backup`) so the connection moves to the other paths in about a second
// instead of the kernel's 5 s.
//
// Both are data: the rules are templates from the link configuration, the
// probe targets, intervals and thresholds are the link's. anx-server itself
// never touches the firewall or the MPTCP endpoints.
package anxline

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Defaults (spec §9 TBD-L14: one probe every 200 ms, a switch in 1–1.5 s;
// the kernel resumes about 1 s after RM_ADDR, so a path is declared dead
// after two missed probes).
const (
	DefaultTable        = "anixops_anx_line"
	DefaultNFT          = "nft"
	DefaultIP           = "ip"
	DefaultIntervalMs   = 200
	DefaultTimeoutMs    = 200
	DefaultFailAfter    = 2
	DefaultRecoverAfter = 5
)

// Fake-TCP roles: the server owns the fake-TCP port, the client sends to it.
const (
	RoleServer = "server"
	RoleClient = "client"
)

// Actions on a dead MPTCP path.
const (
	// ActionDelete removes the endpoint (`ip mptcp endpoint delete`): a
	// signal endpoint sends RM_ADDR, the kernel closes the subflows on it.
	// This is what the lab measured (about 1 s to resume).
	ActionDelete = "delete"
	// ActionBackup marks the endpoint backup (`ip mptcp endpoint change …
	// backup`, MP_PRIO): the subflow stays but carries data only when no
	// other subflow is left.
	ActionBackup = "backup"
)

// Probe kinds. A TCP probe connects from the path's address to Target; a
// refused connection (RST) proves the path works as well as an accepted one.
const (
	ProbeTCP  = "tcp"
	ProbeICMP = "icmp"
)

// Default RST rule templates (spec §4.2). {port}, {local} and {peer} are
// replaced by the link's values; the rules go into an output filter chain.
var (
	DefaultServerRules      = []string{"ip saddr {local} tcp sport {port} tcp flags & rst == rst drop"}
	DefaultServerRulesNoSrc = []string{"tcp sport {port} tcp flags & rst == rst drop"}
	DefaultClientRules      = []string{"ip daddr {peer} tcp dport {port} tcp flags & rst == rst drop"}
)

// Config is the Agent configuration's AnxLine section.
type Config struct {
	Enable bool `json:"Enable"`
	// NFT and IP are the nft and ip binaries ("nft", "ip" when empty).
	NFT string `json:"NFT"`
	IP  string `json:"IP"`
	// Table is the nftables table (family ip) the Agent owns entirely
	// (DefaultTable when empty).
	Table string `json:"Table"`
	Links []Link `json:"Links"`
}

// Link is one ANX-Line link on this host, by the link_id of AddLinks (or
// the egress node's side of it).
type Link struct {
	ID        string     `json:"ID"`
	FakeTCP   *FakeTCP   `json:"FakeTCP"`
	Multipath *Multipath `json:"Multipath"`
}

// FakeTCP is a C3 carrier end (spec §4.2): the RST segments the kernel sends
// for the fake-TCP port are dropped on the way out, so stateful middleboxes
// keep the flow.
type FakeTCP struct {
	Role string `json:"Role"`
	// Port is the fake-TCP port: the server's --faketcp-listen port.
	Port int `json:"Port"`
	// Local is the server's own address the RSTs leave from (optional:
	// without it the rule matches the port only).
	Local string `json:"Local"`
	// Peer is the server's address, required on the client.
	Peer string `json:"Peer"`
	// Rules are nft rule templates replacing the defaults.
	Rules []string `json:"Rules"`
}

// Multipath watches the MPTCP paths (endpoints) of a multipath link.
type Multipath struct {
	IntervalMs   int    `json:"IntervalMs"`
	TimeoutMs    int    `json:"TimeoutMs"`
	FailAfter    int    `json:"FailAfter"`
	RecoverAfter int    `json:"RecoverAfter"`
	Action       string `json:"Action"`
	Paths        []Path `json:"Paths"`
}

// Path is one MPTCP endpoint and how to probe it.
type Path struct {
	// Endpoint is the `ip mptcp endpoint` id (1–255).
	Endpoint int    `json:"Endpoint"`
	Addr     string `json:"Addr"`
	Dev      string `json:"Dev"`
	// Flags are the endpoint flags used when the Agent adds it (subflow,
	// signal, backup, fullmesh; "subflow" when empty).
	Flags []string `json:"Flags"`
	Probe Probe    `json:"Probe"`
}

// Probe says how a path is probed.
type Probe struct {
	Kind   string `json:"Kind"`
	Target string `json:"Target"`
}

// Enabled reports whether the AnxLine section is on.
func (c *Config) Enabled() bool { return c != nil && c.Enable }

func (c *Config) table() string { return valueOr(c.Table, DefaultTable) }
func (c *Config) nft() string   { return valueOr(c.NFT, DefaultNFT) }
func (c *Config) ip() string    { return valueOr(c.IP, DefaultIP) }

func (m *Multipath) interval() time.Duration {
	return time.Duration(positiveOr(m.IntervalMs, DefaultIntervalMs)) * time.Millisecond
}
func (m *Multipath) timeout() time.Duration {
	return time.Duration(positiveOr(m.TimeoutMs, DefaultTimeoutMs)) * time.Millisecond
}
func (m *Multipath) failAfter() int    { return positiveOr(m.FailAfter, DefaultFailAfter) }
func (m *Multipath) recoverAfter() int { return positiveOr(m.RecoverAfter, DefaultRecoverAfter) }
func (m *Multipath) action() string    { return valueOr(m.Action, ActionDelete) }

func (p *Path) flags() []string {
	if len(p.Flags) == 0 {
		return []string{"subflow"}
	}
	return p.Flags
}

var (
	tableName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
	devName   = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,15}$`)
	// A rendered rule may only hold nft words, addresses and operators: no
	// ';', braces, quotes, comments or newlines that could leave the chain.
	ruleText = regexp.MustCompile(`^[A-Za-z0-9 .:/_&=!<>,-]+$`)
)

var endpointFlags = map[string]bool{"subflow": true, "signal": true, "backup": true, "fullmesh": true}

// Validate checks the section; a disabled section is not checked.
func (c *Config) Validate() error {
	if !c.Enabled() {
		return nil
	}
	if !tableName.MatchString(c.table()) {
		return fmt.Errorf("AnxLine.Table %q: letters, digits and _ only", c.Table)
	}
	ids := map[string]bool{}
	endpoints := map[int]string{}
	for i := range c.Links {
		link := &c.Links[i]
		if strings.TrimSpace(link.ID) == "" {
			return fmt.Errorf("AnxLine.Links[%d]: ID is required", i)
		}
		if ids[link.ID] {
			return fmt.Errorf("AnxLine link %q: duplicate ID", link.ID)
		}
		ids[link.ID] = true
		if link.FakeTCP == nil && link.Multipath == nil {
			return fmt.Errorf("AnxLine link %q: neither FakeTCP nor Multipath", link.ID)
		}
		if link.FakeTCP != nil {
			if _, err := link.FakeTCP.rules(); err != nil {
				return fmt.Errorf("AnxLine link %q: %w", link.ID, err)
			}
		}
		if link.Multipath != nil {
			if err := link.Multipath.validate(); err != nil {
				return fmt.Errorf("AnxLine link %q: %w", link.ID, err)
			}
			for _, path := range link.Multipath.Paths {
				if other, ok := endpoints[path.Endpoint]; ok {
					return fmt.Errorf("AnxLine link %q: MPTCP endpoint %d is also on link %q", link.ID, path.Endpoint, other)
				}
				endpoints[path.Endpoint] = link.ID
			}
		}
	}
	return nil
}

// rules renders the link's RST rules.
func (f *FakeTCP) rules() ([]string, error) {
	if f.Port < 1 || f.Port > 65535 {
		return nil, fmt.Errorf("FakeTCP.Port %d out of range", f.Port)
	}
	values := map[string]string{"{port}": strconv.Itoa(f.Port)}
	if f.Local != "" {
		addr, err := netip.ParseAddr(f.Local)
		if err != nil || !addr.Is4() {
			return nil, fmt.Errorf("FakeTCP.Local %q: an IPv4 address is required (fake TCP is IPv4 only)", f.Local)
		}
		values["{local}"] = addr.String()
	}
	if f.Peer != "" {
		addr, err := netip.ParseAddr(f.Peer)
		if err != nil || !addr.Is4() {
			return nil, fmt.Errorf("FakeTCP.Peer %q: an IPv4 address is required (fake TCP is IPv4 only)", f.Peer)
		}
		values["{peer}"] = addr.String()
	}
	templates := f.Rules
	switch f.Role {
	case RoleServer:
		if len(templates) == 0 {
			templates = DefaultServerRules
			if f.Local == "" {
				templates = DefaultServerRulesNoSrc
			}
		}
	case RoleClient:
		if f.Peer == "" {
			return nil, errors.New("FakeTCP.Peer is required on the client")
		}
		if len(templates) == 0 {
			templates = DefaultClientRules
		}
	default:
		return nil, fmt.Errorf("FakeTCP.Role %q: %q or %q", f.Role, RoleServer, RoleClient)
	}
	out := make([]string, 0, len(templates))
	for _, template := range templates {
		rule := template
		for key, value := range values {
			rule = strings.ReplaceAll(rule, key, value)
		}
		if strings.ContainsAny(rule, "{}") {
			return nil, fmt.Errorf("FakeTCP rule %q: unknown or unset placeholder", template)
		}
		rule = strings.Join(strings.Fields(rule), " ")
		if !ruleText.MatchString(rule) {
			return nil, fmt.Errorf("FakeTCP rule %q: only nft words, addresses and operators are allowed", template)
		}
		out = append(out, rule)
	}
	return out, nil
}

func (m *Multipath) validate() error {
	if m.IntervalMs < 0 || m.TimeoutMs < 0 || m.FailAfter < 0 || m.RecoverAfter < 0 {
		return errors.New("Multipath: negative interval, timeout or threshold")
	}
	if m.timeout() > m.interval() {
		return errors.New("Multipath.TimeoutMs must not exceed IntervalMs")
	}
	if m.interval() < 50*time.Millisecond {
		return errors.New("Multipath.IntervalMs must be at least 50")
	}
	switch m.action() {
	case ActionDelete, ActionBackup:
	default:
		return fmt.Errorf("Multipath.Action %q: %q or %q", m.Action, ActionDelete, ActionBackup)
	}
	if len(m.Paths) < 2 {
		return errors.New("Multipath needs at least two paths")
	}
	seen := map[int]bool{}
	for i := range m.Paths {
		path := &m.Paths[i]
		if path.Endpoint < 1 || path.Endpoint > 255 {
			return fmt.Errorf("Multipath.Paths[%d].Endpoint %d: 1 to 255", i, path.Endpoint)
		}
		if seen[path.Endpoint] {
			return fmt.Errorf("Multipath: endpoint %d listed twice", path.Endpoint)
		}
		seen[path.Endpoint] = true
		addr, err := netip.ParseAddr(path.Addr)
		if err != nil {
			return fmt.Errorf("Multipath.Paths[%d].Addr %q: %v", i, path.Addr, err)
		}
		if path.Dev != "" && !devName.MatchString(path.Dev) {
			return fmt.Errorf("Multipath.Paths[%d].Dev %q: not an interface name", i, path.Dev)
		}
		for _, flag := range path.Flags {
			if !endpointFlags[flag] {
				return fmt.Errorf("Multipath.Paths[%d]: unknown endpoint flag %q", i, flag)
			}
		}
		if err := path.Probe.validate(addr); err != nil {
			return fmt.Errorf("Multipath.Paths[%d]: %w", i, err)
		}
	}
	return nil
}

func (p *Probe) validate(source netip.Addr) error {
	switch p.Kind {
	case ProbeTCP:
		host, port, err := net.SplitHostPort(p.Target)
		if err != nil {
			return fmt.Errorf("Probe.Target %q: host:port is required for a tcp probe", p.Target)
		}
		target, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("Probe.Target %q: an IP address is required", p.Target)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("Probe.Target %q: port out of range", p.Target)
		}
		if target.Is4() != source.Is4() {
			return fmt.Errorf("Probe.Target %q: not the address family of the path", p.Target)
		}
	case ProbeICMP:
		target, err := netip.ParseAddr(p.Target)
		if err != nil {
			return fmt.Errorf("Probe.Target %q: an IP address is required for an icmp probe", p.Target)
		}
		if target.Is4() != source.Is4() {
			return fmt.Errorf("Probe.Target %q: not the address family of the path", p.Target)
		}
	default:
		return fmt.Errorf("Probe.Kind %q: %q or %q", p.Kind, ProbeTCP, ProbeICMP)
	}
	return nil
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func positiveOr(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}
