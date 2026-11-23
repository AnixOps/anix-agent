package panel

// Protocol node types added by AnixOps. Each embeds CommonNode.

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

// AnxNode is an ANX-A inbound (anx-node's `anx` inbound): its server names,
// dest and ALPN. The server key pair is the Agent's anx-server key.
type AnxNode struct {
	CommonNode
	ServerNames []string `json:"server_names"`
	Dest        string   `json:"dest"`
	ALPN        []string `json:"alpn"`
	// AllowNoSNI also accepts connections without SNI.
	AllowNoSNI bool `json:"allow_no_sni"`
	// ShapePlain is anx-node's shape_plain option.
	ShapePlain bool `json:"shape_plain"`
	// MaxStreams caps the streams of one session; 0 = anx-node's default.
	MaxStreams int `json:"max_streams"`
	// WGListenPort is anx-node's wg_listen_port (UDP); 0 = off.
	WGListenPort int `json:"wg_listen_port"`
	// BareListenPort is anx-node's bare_listen_port (TCP); 0 = off.
	BareListenPort int `json:"bare_listen_port"`
	// DestStack is anx-node's dest_stack preset; empty = anx-node's
	// default.
	DestStack string `json:"dest_stack"`
	// DestBehavior is anx-node's dest_behavior, passed through as Control
	// sends it.
	DestBehavior map[string]any `json:"dest_behavior"`
	// DestBehaviors holds per-dest overrides on top of DestBehavior, keyed
	// by an entry of the dest list ("host:port").
	DestBehaviors map[string]map[string]any `json:"dest_behaviors"`
	// LicenseCA lists the license CAs (64-hex Ed25519 public keys, at most
	// two while rotating) whose device licenses the node accepts; empty =
	// licensing off. Control sends it only while ANX
	// licensing is on.
	LicenseCA []string `json:"license_ca"`
	// RequireLicense makes the node refuse sessions without a license;
	// needs LicenseCA and no WGListenPort.
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
