package conf

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"encoding/json"

	"github.com/AnixOps/anix-agent/v4/common/json5"
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
	APIHost        string `json:"ApiHost"`
	APISendIP      string `json:"ApiSendIP"`
	Transport      string `json:"Transport"` // http | grpc
	GRPCHost       string `json:"GRPCHost"`  // optional explicit grpc target host:port
	GRPCUseTLS     bool   `json:"GRPCUseTLS"`
	GRPCServerName string `json:"GRPCServerName"`
	GRPCKeepalive  int    `json:"GRPCKeepalive"` // seconds
	// AgentControlEnabled opts this node into the v3 primary control stream.
	// The zero value stays off so legacy configs do not start reconnecting unexpectedly.
	AgentControlEnabled bool `json:"AgentControlEnabled"`
	// AgentControlAllowInsecure must be explicitly enabled before the control
	// stream will send node credentials over plaintext to a non-loopback target.
	AgentControlAllowInsecure bool `json:"AgentControlAllowInsecure"`
	// PluginSupervisorEnabled activates the local official-plugin Supervisor for
	// this Agent process. It is off by default for legacy compatibility.
	MaintenanceEnvironment  string `json:"MaintenanceEnvironment"`
	PluginSupervisorEnabled bool   `json:"PluginSupervisorEnabled"`
	PluginRoot              string `json:"PluginRoot"`
	PluginSocketDir         string `json:"PluginSocketDir"`
	PluginOfficialPublicKey string `json:"PluginOfficialPublicKey"`
	NodeID                  int    `json:"NodeID"`
	NodeType                string `json:"NodeType"`
	Key                     string `json:"ApiKey"`
	Timeout                 int    `json:"Timeout"`
	RuleListPath            string `json:"RuleListPath"`

	// 鑷姩鍙戠幇鐩稿叧閰嶇疆
	AuthKey           string `json:"AuthKey"`           // 鎺堟潈瀵嗛挜 (棣栨娉ㄥ唽浣跨敤)
	NodeName          string `json:"NodeName"`          // 鑺傜偣鍚嶇О
	NodeHost          string `json:"NodeHost"`          // 鑺傜偣鍦板潃 (鍙€夛紝榛樿浣跨敤瀹㈡埛绔疘P)
	NodePort          int    `json:"NodePort"`          // API绔彛 (榛樿443)
	CredentialFile    string `json:"CredentialFile"`    // 鍑瘉瀛樺偍璺緞
	HeartbeatInterval int    `json:"HeartbeatInterval"` // 蹇冭烦闂撮殧 (绉掞紝榛樿60)
	AutoRegister      bool   `json:"AutoRegister"`      // 鏄惁鍚敤鑷姩娉ㄥ唽

	// 瀹夊叏澧炲己閰嶇疆
	EnableSign        bool `json:"EnableSign"`        // 鏄惁鍚敤璇锋眰绛惧悕 (榛樿true)
	EncryptCredential bool `json:"EncryptCredential"` // 鏄惁鍔犲瘑瀛樺偍鍑瘉 (榛樿true)

	// 璋冭瘯閰嶇疆
	EnableDebug    bool   `json:"EnableDebug"`    // 鏄惁鍚敤 API 璋冭瘯
	DebugOutputDir string `json:"DebugOutputDir"` // 璋冭瘯杈撳嚭鐩綍 (榛樿 test_data/api_debug)

	// 杩愯鏃跺弬鏁?(涓嶄粠閰嶇疆鏂囦欢璇诲彇)
	ForceReRegister bool `json:"-"` // 寮哄埗閲嶆柊娉ㄥ唽 (鍛戒护琛屽弬鏁?
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
		Transport:     "http",
		GRPCKeepalive: 30,
		Timeout:       30,
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
	XrayOptions            *XrayOptions    `json:"XrayOptions"`
	SingOptions            *SingOptions    `json:"SingOptions"`
	Hysteria2ConfigPath    string          `json:"Hysteria2ConfigPath"`
	CertConfig             *CertConfig     `json:"CertConfig"`
	SyncConfig             *SyncConfig     `json:"SyncConfig"`
}

// SyncConfig 鍚屾閰嶇疆
type SyncConfig struct {
	// WebSocket 閰嶇疆
	EnableWebSocket     bool     `json:"EnableWebSocket"`
	WSEndpoint          string   `json:"WSEndpoint"`
	WSEndpointFallbacks []string `json:"WSEndpointFallbacks,omitempty"`
	ReconnectInterval   int      `json:"ReconnectInterval"` // 绉?
	MaxReconnectTries   int      `json:"MaxReconnectTries"` // 0 = 鏃犻檺閲嶈瘯

	// 蹇冭烦閰嶇疆
	PingInterval int `json:"PingInterval"` // 绉?
	PongTimeout  int `json:"PongTimeout"`  // 绉?
	// 娑堟伅閰嶇疆
	AckTimeout int `json:"AckTimeout"` // 绉?
	BufferSize int `json:"BufferSize"`
	AckRetries int `json:"AckRetries"`

	// 闄嶇骇閰嶇疆
	EnableFallback   bool `json:"EnableFallback"`
	FallbackInterval int  `json:"FallbackInterval"` // 绉?
}

// NewSyncConfig 鍒涘缓榛樿鍚屾閰嶇疆
func NewSyncConfig() *SyncConfig {
	return &SyncConfig{
		EnableWebSocket: false, // 榛樿涓嶅惎鐢紝绛夊悗绔敮鎸佸悗鍚敤
		WSEndpoint:      "/api/v2/agent/ws",
		WSEndpointFallbacks: []string{
			"/api/v2/node/ws",
		},
		ReconnectInterval: 5,
		MaxReconnectTries: 0,
		PingInterval:      30,
		PongTimeout:       10,
		AckTimeout:        5,
		BufferSize:        100,
		AckRetries:        2,
		EnableFallback:    true,
		FallbackInterval:  60,
	}
}

func (o *Options) UnmarshalJSON(data []byte) error {
	type opt Options
	err := json.Unmarshal(data, (*opt)(o))
	if err != nil {
		return err
	}
	switch o.Core {
	case "xray":
		o.XrayOptions = NewXrayOptions()
		return json.Unmarshal(data, o.XrayOptions)
	case "sing":
		o.SingOptions = NewSingOptions()
		return json.Unmarshal(data, o.SingOptions)
	case "hysteria2":
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
