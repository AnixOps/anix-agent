package conf

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"encoding/json"

	"github.com/AnixOps/anix-agent/v5/common/json5"
)

type NodeConfig struct {
	ApiConfig ApiConfig `json:"-"`
	Options   Options   `json:"-"`
}

type rawNodeConfig struct {
	Include string          `json:"Include"`
	ApiRaw  json.RawMessage `json:"ApiConfig"`
	OptRaw  json.RawMessage `json:"Options"`
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
	AgentNode    string `json:"AgentNode"`
	NodeID       int    `json:"NodeID"`
	NodeType     string `json:"NodeType"`
	RuleListPath string `json:"RuleListPath"`
}

func (n *NodeConfig) UnmarshalJSON(data []byte) (err error) {
	rn := rawNodeConfig{}
	err = json.Unmarshal(data, &rn)
	if err != nil {
		return err
	}
	if len(rn.Include) != 0 {
		file, _ := strings.CutPrefix(rn.Include, ":")
		switch file {
		case "http", "https":
			rsp, err := http.Get(file)
			if err != nil {
				return err
			}
			defer rsp.Body.Close()
			data, err = io.ReadAll(json5.NewTrimNodeReader(rsp.Body))
			if err != nil {
				return fmt.Errorf("open include file error: %s", err)
			}
		default:
			f, err := os.Open(rn.Include)
			if err != nil {
				return fmt.Errorf("open include file error: %s", err)
			}
			defer f.Close()
			data, err = io.ReadAll(json5.NewTrimNodeReader(f))
			if err != nil {
				return fmt.Errorf("open include file error: %s", err)
			}
		}
		err = json.Unmarshal(data, &rn)
		if err != nil {
			return fmt.Errorf("unmarshal include file error: %s", err)
		}
	}

	n.ApiConfig = ApiConfig{
		APIHost:       "http://127.0.0.1",
		GRPCKeepalive: 30,
	}
	if len(rn.ApiRaw) > 0 {
		err = json.Unmarshal(rn.ApiRaw, &n.ApiConfig)
		if err != nil {
			return
		}
	} else {
		err = json.Unmarshal(data, &n.ApiConfig)
		if err != nil {
			return
		}
	}

	n.Options = Options{
		ListenIP:   "0.0.0.0",
		SendIP:     "0.0.0.0",
		CertConfig: NewCertConfig(),
	}
	if len(rn.OptRaw) > 0 {
		err = json.Unmarshal(rn.OptRaw, &n.Options)
		if err != nil {
			return
		}
	} else {
		err = json.Unmarshal(data, &n.Options)
		if err != nil {
			return
		}
	}
	return
}

type Options struct {
	Name                   string          `json:"Name"`
	Core                   string          `json:"Core"`
	CoreName               string          `json:"CoreName"`
	ListenIP               string          `json:"ListenIP"`
	SendIP                 string          `json:"SendIP"`
	DeviceOnlineMinTraffic int64           `json:"DeviceOnlineMinTraffic"`
	ReportMinTraffic       int64           `json:"ReportMinTraffic"`
	LimitConfig            LimitConfig     `json:"LimitConfig"`
	RawOptions             json.RawMessage `json:"RawOptions"`
	CertConfig             *CertConfig     `json:"CertConfig"`
}

func (o *Options) UnmarshalJSON(data []byte) error {
	type opt Options
	err := json.Unmarshal(data, (*opt)(o))
	if err != nil {
		return err
	}
	switch o.Core {
	// The third-party cores are gone: a node that still names one runs on
	// anixcore.
	case "xray", "sing", "hysteria2", "anixcore":
		o.Core = "anixcore"
		o.RawOptions = data
		return nil
	case "wireguard":
		// WireGuard has no nested per-node options, but keeping the explicit
		// core selection is required when a process hosts multiple core types.
		o.RawOptions = data
		return nil
	default:
		o.Core = ""
		o.RawOptions = data
	}
	return nil
}
