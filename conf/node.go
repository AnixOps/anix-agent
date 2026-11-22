package conf

import "encoding/json"

// NodeConfig is one entry of "Nodes": the connection to Control and the
// node's local options, both read from the same flat object.
type NodeConfig struct {
	ApiConfig ApiConfig `json:"-"`
	Options   Options   `json:"-"`
}

type ApiConfig struct {
	// APIHost is Control's base URL; it names the node's core tag and, when
	// GRPCHost is empty, the control stream's host (port 50051).
	APIHost        string `json:"ApiHost"`
	GRPCHost       string `json:"GRPCHost"` // optional explicit grpc target host:port
	GRPCUseTLS     bool   `json:"GRPCUseTLS"`
	GRPCServerName string `json:"GRPCServerName"`
	GRPCKeepalive  int    `json:"GRPCKeepalive"` // seconds
	// AgentControlAllowInsecure must be explicitly enabled before the control
	// stream may run in plaintext to a non-loopback target.
	AgentControlAllowInsecure bool `json:"AgentControlAllowInsecure"`
	// AgentIdentity is the stream's mTLS identity: enrollment, the key and
	// certificate directory, an optional one-time enrollment credential.
	AgentIdentity AgentIdentityConfig `json:"AgentIdentity"`
	// AgentStream is the stream's data plane: the node's configuration
	// from Control's snapshots, and where the delivered state is kept.
	AgentStream AgentStreamConfig `json:"AgentStream"`
	// PluginSupervisorEnabled activates the local official-plugin Supervisor for
	// this Agent process.
	MaintenanceEnvironment  string `json:"MaintenanceEnvironment"`
	PluginSupervisorEnabled bool   `json:"PluginSupervisorEnabled"`
	PluginRoot              string `json:"PluginRoot"`
	PluginSocketDir         string `json:"PluginSocketDir"`
	PluginOfficialPublicKey string `json:"PluginOfficialPublicKey"`
	// AgentNode names the node the Agent speaks for, as Control's
	// identities do: "proxy-<id>" or "forward-<id>" (the O1 installer
	// writes it). A forward node's entry runs the forward component on its
	// own stream (ForwardConfig); NodeID, when set, must match.
	AgentNode string `json:"AgentNode"`
	NodeID    int    `json:"NodeID"`
	NodeType  string `json:"NodeType"`
}

// Options are a node's local settings.
type Options struct {
	// Name, when set, is the node's core tag instead of one built from
	// Control's host and the node.
	Name string `json:"Name"`
	// Core is the core that runs the node: anixcore, wireguard, or empty
	// for the default.
	Core     string `json:"Core"`
	CoreName string `json:"CoreName"`
	ListenIP string `json:"ListenIP"`
	// DeviceOnlineMinTraffic (KB) is the traffic in a report window below
	// which a user's online IP is not counted as a device.
	DeviceOnlineMinTraffic int64       `json:"DeviceOnlineMinTraffic"`
	ReportMinTraffic       int64       `json:"ReportMinTraffic"`
	LimitConfig            LimitConfig `json:"LimitConfig"`
	CertConfig             *CertConfig `json:"CertConfig"`
	// RawOptions is the node's whole object, for the core to read its own
	// settings from.
	RawOptions json.RawMessage `json:"-"`
}

// LimitConfig is the node's speed limit (Mbps, 0 for none) and the dynamic
// speed limit: a user whose traffic in Periodic seconds reaches Traffic is
// held to SpeedLimit Mbps for ExpireTime minutes.
type LimitConfig struct {
	SpeedLimit              int                      `json:"SpeedLimit"`
	EnableDynamicSpeedLimit bool                     `json:"EnableDynamicSpeedLimit"`
	DynamicSpeedLimitConfig *DynamicSpeedLimitConfig `json:"DynamicSpeedLimitConfig"`
}

type DynamicSpeedLimitConfig struct {
	Periodic   int   `json:"Periodic"`
	Traffic    int64 `json:"Traffic"`
	SpeedLimit int   `json:"SpeedLimit"`
	ExpireTime int   `json:"ExpireTime"`
}

// CertConfig is where a TLS node's certificate comes from. CertMode is
// none, file (CertFile and KeyFile), self (a self-signed certificate for
// CertDomain), http or dns (ACME for CertDomain; dns uses Provider with
// the credentials in DNSEnv).
type CertConfig struct {
	CertMode   string            `json:"CertMode"`
	CertDomain string            `json:"CertDomain"`
	CertFile   string            `json:"CertFile"`
	KeyFile    string            `json:"KeyFile"`
	Provider   string            `json:"Provider"`
	Email      string            `json:"Email"`
	DNSEnv     map[string]string `json:"DNSEnv"`
}

func NewCertConfig() *CertConfig {
	return &CertConfig{CertMode: "none"}
}

func (n *NodeConfig) UnmarshalJSON(data []byte) error {
	n.ApiConfig = ApiConfig{APIHost: "http://127.0.0.1", GRPCKeepalive: 30}
	n.Options = Options{ListenIP: "0.0.0.0", CertConfig: NewCertConfig()}
	if err := json.Unmarshal(data, &n.ApiConfig); err != nil {
		return err
	}
	return json.Unmarshal(data, &n.Options)
}

func (o *Options) UnmarshalJSON(data []byte) error {
	type plain Options
	if err := json.Unmarshal(data, (*plain)(o)); err != nil {
		return err
	}
	o.RawOptions = append(json.RawMessage(nil), data...)
	switch o.Core {
	case "anixcore", "wireguard":
	case "xray", "sing", "hysteria2":
		// The third-party cores are gone: a node that still names one runs
		// on anixcore.
		o.Core = "anixcore"
	default:
		o.Core = ""
	}
	return nil
}
