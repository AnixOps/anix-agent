package panel

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Security is how a node's inbound is secured.
const (
	None    = 0
	Tls     = 1
	Reality = 2
)

// NodeInfo is a node's configuration as Control answers it: the fields
// every protocol has and exactly one protocol's settings.
type NodeInfo struct {
	Id           int
	Type         string // the protocol
	Security     int
	PushInterval time.Duration
	PullInterval time.Duration
	// Rules are the node's block rules.
	Rules  Rules
	Common *CommonNode

	VLessVMess  *VLessVMessNode
	Shadowsocks *ShadowsocksNode
	Trojan      *TrojanNode
	Tuic        *TuicNode
	AnyTls      *AnyTlsNode
	Hysteria2   *Hysteria2Node
	WireGuard   *WireGuardNode
	Iwan        *IwanNode
	Anx         *AnxNode
	Snell       *SnellNode
}

// Rules are block rules: destination patterns (regular expressions) and
// sniffed protocols.
type Rules struct {
	Regexp   []string
	Protocol []string
}

// CommonNode is what every protocol's answer carries.
type CommonNode struct {
	Host       string `json:"host"`
	ServerPort int    `json:"server_port"`
	ServerName string `json:"server_name"`
	// Routes and BaseConfig are read into NodeInfo and then cleared.
	Routes     []Route     `json:"routes"`
	BaseConfig *BaseConfig `json:"base_config"`
}

// Route is a routing entry; the Agent applies "block" routes. Match is a
// comma-separated string or a list of strings.
type Route struct {
	Id     int    `json:"id"`
	Match  any    `json:"match"`
	Action string `json:"action"`
}

// BaseConfig carries the report and poll intervals in seconds, as a number
// or a string.
type BaseConfig struct {
	PushInterval any `json:"push_interval"`
	PullInterval any `json:"pull_interval"`
}

// VLessVMessNode is a vless or vmess node. Tls is the node's Security.
type VLessVMessNode struct {
	CommonNode
	Tls             int             `json:"tls"`
	TlsSettings     TlsSettings     `json:"tls_settings"`
	Network         string          `json:"network"`
	NetworkSettings json.RawMessage `json:"network_settings"`
	Flow            string          `json:"flow"` // vless only
}

// TlsSettings are a vless node's Reality settings.
type TlsSettings struct {
	ServerName string `json:"server_name"`
	Dest       string `json:"dest"`
	ServerPort string `json:"server_port"`
	ShortId    string `json:"short_id"`
	PrivateKey string `json:"private_key"`
}

type ShadowsocksNode struct {
	CommonNode
	Cipher    string `json:"cipher"`
	ServerKey string `json:"server_key"`
}

type TrojanNode struct {
	CommonNode
	Network         string          `json:"network"`
	NetworkSettings json.RawMessage `json:"network_settings"`
}

type TuicNode struct {
	CommonNode
	CongestionControl string `json:"congestion_control"`
}

type AnyTlsNode struct {
	CommonNode
	PaddingScheme []string `json:"padding_scheme,omitempty"`
}

type Hysteria2Node struct {
	CommonNode
	ObfsType     string `json:"obfs"`
	ObfsPassword string `json:"obfs-password"`
}

type WireGuardNode struct {
	CommonNode
	CIDR             string         `json:"cidr"`
	ServerAddress    string         `json:"server_address"`
	ServerPrivateKey string         `json:"server_private_key"`
	ServerPublicKey  string         `json:"server_public_key"`
	MTU              int            `json:"mtu"`
	DNS              []string       `json:"dns"`
	AllowedIPs       []string       `json:"allowed_ips"`
	TunnelType       string         `json:"tunnel_type"`
	Relay            WireGuardRelay `json:"relay"`
}

// IwanNode is a Panabit iWAN inbound (docs/protocols/iwan.md §12 of
// networkcore_anixops). iWAN has no confidentiality or integrity.
type IwanNode struct {
	CommonNode
	// IPv4 network the users' tunnel addresses come from, e.g. 10.66.0.0/16.
	Pool string `json:"pool"`
	MTU  int    `json:"mtu"`
	// `ip` or `ip:port` the gateway relays DNS to.
	DNSUpstream string `json:"dns_upstream"`
	// Nil keeps the kernel default (allowed).
	AllowEncrypt        *bool `json:"allow_encrypt"`
	AllowClientToClient bool  `json:"allow_client_to_client"`
	// Fixed tunnel addresses by panel user id.
	FixedAddresses map[string]string `json:"fixed_addresses"`
}

// SnellNode is a Snell inbound (networkcore_anixops crates/inbound-snell):
// one PSK for the node, and each panel user logs in with its UUID as the
// user key.
type SnellNode struct {
	CommonNode
	PSK     string `json:"psk"`
	Version int    `json:"version"`
	// Obfs is "http" (versions 1 to 4) or empty.
	Obfs string `json:"obfs"`
	// Mode is a version 6 mode; empty keeps the kernel default.
	Mode string `json:"mode"`
}

// AnxNode is an ANX-A inbound (anx-node's `anx` inbound, A2 jacket): the
// server names it answers to, the cover site everything else is forwarded
// to, and the ALPN. The server key pair is the Agent's anx-server key.
type AnxNode struct {
	CommonNode
	ServerNames []string `json:"server_names"`
	Dest        string   `json:"dest"`
	ALPN        []string `json:"alpn"`
	// AllowNoSNI also accepts ClientHellos without SNI (the A2 no-SNI mode,
	// clients dialing the IP).
	AllowNoSNI bool `json:"allow_no_sni"`
	// ShapePlain hands out the plain shape profile instead of VisionLike.
	ShapePlain bool `json:"shape_plain"`
	// MaxStreams caps the streams of one session; 0 = anx-node's default.
	MaxStreams int `json:"max_streams"`
	// WGListenPort is the UDP port of the wg jacket (WireGuard-shaped UDP,
	// for users dialing a domestic entry); 0 = off.
	WGListenPort int `json:"wg_listen_port"`
	// BareListenPort is the TCP port of the bare jacket (random-looking TCP,
	// for users dialing a domestic entry only); 0 = off.
	BareListenPort int `json:"bare_listen_port"`
	// DestStack picks the TLS stack preset (openssl, boringssl, go, rustls)
	// for failed handshakes when dest is unreachable; empty = anx-node's
	// default.
	DestStack string `json:"dest_stack"`
	// DestBehavior overrides the preset key by key (anx BOUNDARY.md
	// dest_behavior); with a dest it should carry session_tickets and
	// flight_records as measured by anx-lab dest-probe.
	DestBehavior map[string]any `json:"dest_behavior"`
	// DestBehaviors holds per-dest overrides on top of DestBehavior, keyed
	// by an entry of the dest list ("host:port"); usually the site keys
	// session_tickets and flight_records of each backup dest.
	DestBehaviors map[string]map[string]any `json:"dest_behaviors"`
	// LicenseCA lists the license CAs (64-hex Ed25519 public keys, at most
	// two while rotating) whose device licenses the node accepts (anx spec
	// §2.4.1); empty = licensing off. Control sends it only while ANX
	// licensing is on.
	LicenseCA []string `json:"license_ca"`
	// RequireLicense makes the node refuse sessions without a license;
	// needs LicenseCA and no wg jacket.
	RequireLicense bool `json:"require_license"`
	// LicenseRevoked lists the devices (16-hex device_id) the panel
	// revoked while their license may still be valid: the node refuses
	// them. Control sends it only while it is not empty.
	LicenseRevoked []string `json:"license_revoked"`
}

type WireGuardRelay struct {
	Backend         string                 `json:"backend"`
	Mode            string                 `json:"mode"`
	Role            string                 `json:"role"`
	WSSCompat       bool                   `json:"wss_compat"`
	ExitNAT         bool                   `json:"exit_nat"`
	EntryStats      bool                   `json:"entry_stats"`
	Server          string                 `json:"server"`
	ServerPort      int                    `json:"server_port"`
	TunName         string                 `json:"tun_name"`
	TunPort         int                    `json:"tun_port"`
	TunAddress      string                 `json:"tun_address"`
	EntryTunAddress string                 `json:"entry_tun_address"`
	ExitTunAddress  string                 `json:"exit_tun_address"`
	OutboundIface   string                 `json:"outbound_iface"`
	RoutingTable    int                    `json:"routing_table"`
	RoutingPriority int                    `json:"routing_priority"`
	WSSPath         string                 `json:"wss_path"`
	WSSSecure       bool                   `json:"wss_secure"`
	WSSServerName   string                 `json:"wss_server_name"`
	WSSCAFile       string                 `json:"wss_ca_file"`
	WSSCertFile     string                 `json:"wss_cert_file"`
	WSSKeyFile      string                 `json:"wss_key_file"`
	NetworkPolicy   WireGuardNetworkPolicy `json:"network_policy"`
}

type WireGuardNetworkPolicy struct {
	Version        int                    `json:"version"`
	Strategy       string                 `json:"strategy"`
	Paths          []WireGuardNetworkPath `json:"paths"`
	HealthCheck    WireGuardHealthCheck   `json:"health_check"`
	ActiveTable    int                    `json:"active_table"`
	ActivePriority int                    `json:"active_priority"`
}

type WireGuardNetworkPath struct {
	Name         string `json:"name"`
	Interface    string `json:"interface"`
	Source       string `json:"source"`
	Gateway      string `json:"gateway"`
	Priority     int    `json:"priority"`
	RoutingTable int    `json:"routing_table"`
	RulePriority int    `json:"rule_priority"`
}

type WireGuardHealthCheck struct {
	IntervalSeconds      int `json:"interval_seconds"`
	TimeoutSeconds       int `json:"timeout_seconds"`
	FailureThreshold     int `json:"failure_threshold"`
	RecoveryThreshold    int `json:"recovery_threshold"`
	FailbackDelaySeconds int `json:"failback_delay_seconds"`
}

// protocols decodes each protocol's answer into its NodeInfo field and
// returns the common part and the node's security.
var protocols = map[string]func(body []byte, n *NodeInfo) (*CommonNode, int, error){
	"vless":       decodeInto(func(n *NodeInfo, p *VLessVMessNode) int { n.VLessVMess = p; return p.Tls }),
	"vmess":       decodeInto(func(n *NodeInfo, p *VLessVMessNode) int { n.VLessVMess = p; return p.Tls }),
	"shadowsocks": decodeInto(func(n *NodeInfo, p *ShadowsocksNode) int { n.Shadowsocks = p; return None }),
	"trojan":      decodeInto(func(n *NodeInfo, p *TrojanNode) int { n.Trojan = p; return Tls }),
	"tuic":        decodeInto(func(n *NodeInfo, p *TuicNode) int { n.Tuic = p; return Tls }),
	"anytls":      decodeInto(func(n *NodeInfo, p *AnyTlsNode) int { n.AnyTls = p; return Tls }),
	"hysteria2":   decodeInto(func(n *NodeInfo, p *Hysteria2Node) int { n.Hysteria2 = p; return Tls }),
	"wireguard":   decodeInto(func(n *NodeInfo, p *WireGuardNode) int { n.WireGuard = p; return None }),
	"iwan":        decodeInto(func(n *NodeInfo, p *IwanNode) int { n.Iwan = p; return None }),
	"anx":         decodeInto(func(n *NodeInfo, p *AnxNode) int { n.Anx = p; return None }),
	"snell":       decodeInto(func(n *NodeInfo, p *SnellNode) int { n.Snell = p; return None }),
}

// protocolNode is a protocol's settings, which embed CommonNode.
type protocolNode interface {
	common() *CommonNode
}

func (c *CommonNode) common() *CommonNode { return c }

func decodeInto[T any, P interface {
	*T
	protocolNode
}](set func(*NodeInfo, P) int) func([]byte, *NodeInfo) (*CommonNode, int, error) {
	return func(body []byte, n *NodeInfo) (*CommonNode, int, error) {
		p := P(new(T))
		if err := json.Unmarshal(body, p); err != nil {
			return nil, 0, err
		}
		return p.common(), set(n, p), nil
	}
}

// ParseNodeInfo parses a node configuration answer: one entry of a
// configuration snapshot's runtime answers, delivered on the Agent control
// stream. The answer names the protocol in "type" and the node's category
// in "node_type"; either stands in for the other when it is missing, and
// "v2ray" means vmess. nodeCategory is the node_type.
func ParseNodeInfo(body []byte, nodeID int) (node *NodeInfo, nodeCategory string, err error) {
	var kind struct {
		Type     string `json:"type"`
		NodeType string `json:"node_type"`
	}
	if err := json.Unmarshal(body, &kind); err != nil {
		return nil, "", fmt.Errorf("decode node type: %w", err)
	}
	protocol, category := normalizeType(kind.Type), normalizeType(kind.NodeType)
	if protocol == "" {
		protocol = category
	}
	if category == "" {
		category = protocol
	}
	if category == "" {
		// The answer holds the node's secrets: never echo it.
		return nil, "", fmt.Errorf("node type not found in the node configuration (%d bytes)", len(body))
	}
	decode, ok := protocols[protocol]
	if !ok {
		return nil, "", fmt.Errorf("unsupported node type: %s", protocol)
	}
	node = &NodeInfo{Id: nodeID, Type: protocol}
	common, security, err := decode(body, node)
	if err != nil {
		return nil, "", fmt.Errorf("decode %s node: %w", protocol, err)
	}
	node.Security = security
	if node.Rules, err = blockRules(common.Routes); err != nil {
		return nil, "", err
	}
	if b := common.BaseConfig; b != nil {
		node.PushInterval, node.PullInterval = seconds(b.PushInterval), seconds(b.PullInterval)
	}
	common.Routes, common.BaseConfig = nil, nil
	node.Common = common
	return node, category, nil
}

func normalizeType(t string) string {
	t = strings.ToLower(t)
	if t == "v2ray" {
		return "vmess"
	}
	return t
}

// blockRules collects the "block" routes: "protocol:<name>" entries are
// protocols, any other entry (optionally "regexp:<expression>") a
// destination pattern.
func blockRules(routes []Route) (Rules, error) {
	var rules Rules
	for _, route := range routes {
		var matches []string
		switch m := route.Match.(type) {
		case string:
			matches = strings.Split(m, ",")
		case []any:
			for _, v := range m {
				s, ok := v.(string)
				if !ok {
					return Rules{}, fmt.Errorf("route %d: match entries must be strings", route.Id)
				}
				matches = append(matches, s)
			}
		default:
			return Rules{}, fmt.Errorf("route %d: match must be a string or a list of strings", route.Id)
		}
		if route.Action != "block" {
			continue
		}
		for _, m := range matches {
			if name, ok := strings.CutPrefix(m, "protocol:"); ok {
				rules.Protocol = append(rules.Protocol, name)
			} else {
				rules.Regexp = append(rules.Regexp, strings.TrimPrefix(m, "regexp:"))
			}
		}
	}
	return rules, nil
}

// seconds reads an interval in seconds given as a JSON number or string.
func seconds(v any) time.Duration {
	switch v := v.(type) {
	case float64:
		return time.Duration(v * float64(time.Second))
	case string:
		n, _ := strconv.Atoi(v)
		return time.Duration(n) * time.Second
	}
	return 0
}
