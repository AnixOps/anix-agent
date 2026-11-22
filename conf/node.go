package conf

import "encoding/json"

// NodeConfig is one entry of Nodes: a flat object decoded into both
// ApiConfig and Options.
type NodeConfig struct {
	ApiConfig ApiConfig `json:"-"`
	Options   Options   `json:"-"`
}

func (n *NodeConfig) UnmarshalJSON(data []byte) error {
	n.ApiConfig = ApiConfig{APIHost: "http://127.0.0.1", GRPCKeepalive: 30}
	n.Options = Options{ListenIP: "0.0.0.0", CertConfig: NewCertConfig()}
	if err := json.Unmarshal(data, &n.ApiConfig); err != nil {
		return err
	}
	return json.Unmarshal(data, &n.Options)
}

// ApiConfig is a node's connection to Control.
type ApiConfig struct {
	// APIHost is Control's URL. It names the node's tag and is the stream
	// host when GRPCHost is empty.
	APIHost        string `json:"ApiHost"`
	GRPCHost       string `json:"GRPCHost"`
	GRPCUseTLS     bool   `json:"GRPCUseTLS"`
	GRPCServerName string `json:"GRPCServerName"`
	// GRPCKeepalive is the stream's keepalive in seconds.
	GRPCKeepalive int `json:"GRPCKeepalive"`
	// AgentControlAllowInsecure must be set explicitly for a plaintext
	// stream to a host that is not loopback.
	AgentControlAllowInsecure bool                `json:"AgentControlAllowInsecure"`
	AgentIdentity             AgentIdentityConfig `json:"AgentIdentity"`
	AgentStream               AgentStreamConfig   `json:"AgentStream"`
	MaintenanceEnvironment    string              `json:"MaintenanceEnvironment"`
	PluginSupervisorEnabled   bool                `json:"PluginSupervisorEnabled"`
	PluginRoot                string              `json:"PluginRoot"`
	PluginSocketDir           string              `json:"PluginSocketDir"`
	PluginOfficialPublicKey   string              `json:"PluginOfficialPublicKey"`
	// AgentNode is the node's name in Control: proxy-<id> or forward-<id>.
	AgentNode string `json:"AgentNode"`
	NodeID    int    `json:"NodeID"`
	NodeType  string `json:"NodeType"`
}

// Options is a node's local settings.
type Options struct {
	Name     string `json:"Name"`
	Core     string `json:"Core"`
	CoreName string `json:"CoreName"`
	ListenIP string `json:"ListenIP"`
	// DeviceOnlineMinTraffic is in KB.
	DeviceOnlineMinTraffic int64       `json:"DeviceOnlineMinTraffic"`
	ReportMinTraffic       int64       `json:"ReportMinTraffic"`
	LimitConfig            LimitConfig `json:"LimitConfig"`
	CertConfig             *CertConfig `json:"CertConfig"`
	// RawOptions is the object the options were decoded from; the core
	// selector decodes it again for the core it picks.
	RawOptions json.RawMessage `json:"-"`
}

type options Options

func (o *Options) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, (*options)(o)); err != nil {
		return err
	}
	o.RawOptions = append(json.RawMessage(nil), data...)
	switch o.Core {
	case "anixcore", "wireguard":
	case "xray", "sing", "hysteria2":
		o.Core = "anixcore"
	default:
		o.Core = ""
	}
	return nil
}
