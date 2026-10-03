package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"encoding/json"

	log "github.com/sirupsen/logrus"
)

// Security type
const (
	None    = 0
	Tls     = 1
	Reality = 2
)

type NodeInfo struct {
	Id           int
	Type         string
	Security     int
	PushInterval time.Duration
	PullInterval time.Duration
	RawDNS       RawDNS
	Rules        Rules

	// origin
	VAllss      *VAllssNode
	Shadowsocks *ShadowsocksNode
	Trojan      *TrojanNode
	Tuic        *TuicNode
	AnyTls      *AnyTlsNode
	Hysteria    *HysteriaNode
	Hysteria2   *Hysteria2Node
	WireGuard   *WireGuardNode
	Common      *CommonNode
}

type CommonNode struct {
	Host       string      `json:"host"`
	ServerPort int         `json:"server_port"`
	ServerName string      `json:"server_name"`
	Routes     []Route     `json:"routes"`
	BaseConfig *BaseConfig `json:"base_config"`
}

type Route struct {
	Id          int         `json:"id"`
	Match       interface{} `json:"match"`
	Action      string      `json:"action"`
	ActionValue string      `json:"action_value"`
}
type BaseConfig struct {
	PushInterval any `json:"push_interval"`
	PullInterval any `json:"pull_interval"`
}

// VAllssNode is vmess and vless node info
type VAllssNode struct {
	CommonNode
	Tls                 int             `json:"tls"`
	TlsSettings         TlsSettings     `json:"tls_settings"`
	TlsSettingsBack     *TlsSettings    `json:"tlsSettings"`
	Network             string          `json:"network"`
	NetworkSettings     json.RawMessage `json:"network_settings"`
	NetworkSettingsBack json.RawMessage `json:"networkSettings"`
	Encryption          string          `json:"encryption"`
	EncryptionSettings  EncSettings     `json:"encryption_settings"`
	ServerName          string          `json:"server_name"`

	// vless only
	Flow          string        `json:"flow"`
	RealityConfig RealityConfig `json:"-"`
}

type TlsSettings struct {
	ServerName  string `json:"server_name"`
	Dest        string `json:"dest"`
	ServerPort  string `json:"server_port"`
	ShortId     string `json:"short_id"`
	PrivateKey  string `json:"private_key"`
	Mldsa65Seed string `json:"mldsa65Seed"`
	Xver        uint64 `json:"xver,string"`
}

type EncSettings struct {
	Mode          string `json:"mode"`
	Ticket        string `json:"ticket"`
	ServerPadding string `json:"server_padding"`
	PrivateKey    string `json:"private_key"`
}

type RealityConfig struct {
	Xver         uint64 `json:"Xver"`
	MinClientVer string `json:"MinClientVer"`
	MaxClientVer string `json:"MaxClientVer"`
	MaxTimeDiff  string `json:"MaxTimeDiff"`
}

type ShadowsocksNode struct {
	CommonNode
	Cipher    string `json:"cipher"`
	ServerKey string `json:"server_key"`
}

type TrojanNode struct {
	CommonNode
	Network         string          `json:"network"`
	NetworkSettings json.RawMessage `json:"networkSettings"`
}

type TuicNode struct {
	CommonNode
	CongestionControl string `json:"congestion_control"`
	ZeroRTTHandshake  bool   `json:"zero_rtt_handshake"`
}

type AnyTlsNode struct {
	CommonNode
	PaddingScheme []string `json:"padding_scheme,omitempty"`
}

type HysteriaNode struct {
	CommonNode
	UpMbps   int    `json:"up_mbps"`
	DownMbps int    `json:"down_mbps"`
	Obfs     string `json:"obfs"`
}

type Hysteria2Node struct {
	CommonNode
	Ignore_Client_Bandwidth bool   `json:"ignore_client_bandwidth"`
	UpMbps                  int    `json:"up_mbps"`
	DownMbps                int    `json:"down_mbps"`
	ObfsType                string `json:"obfs"`
	ObfsPassword            string `json:"obfs-password"`
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

type RawDNS struct {
	DNSMap  map[string]map[string]interface{}
	DNSJson []byte
}

type Rules struct {
	Regexp   []string
	Protocol []string
}

func (c *Client) GetNodeInfo() (node *NodeInfo, err error) {
	const path = "/api/v2/server/UniProxy/config"
	r, err := c.client.
		R().
		SetHeader("If-None-Match", c.nodeEtag).
		ForceContentType("application/json").
		Get(path)

	if r.StatusCode() == 304 {
		return nil, nil
	}
	hash := sha256.Sum256(r.Body())
	newBodyHash := hex.EncodeToString(hash[:])
	if c.responseBodyHash == newBodyHash {
		return nil, nil
	}
	c.responseBodyHash = newBodyHash
	c.nodeEtag = r.Header().Get("ETag")
	if err = c.checkResponse(r, path, err); err != nil {
		return nil, err
	}

	if r != nil {
		defer func() {
			if r.RawBody() != nil {
				r.RawBody().Close()
			}
		}()
	} else {
		return nil, fmt.Errorf("received nil response")
	}

	// 调试: 保存原始响应
	if c.Debugger != nil && c.Debugger.IsEnabled() {
		if err := c.Debugger.DumpNodeConfig(r.Body(), c.NodeId); err != nil {
			log.WithError(err).Warn("Failed to dump node config")
		}
	}

	// 调试：打印原始响应内容
	log.WithField("response", string(r.Body())).Debug("Raw node config response")

	node, nodeCategory, err := ParseNodeInfo(r.Body(), c.NodeId)
	if err != nil {
		return nil, err
	}

	// 更新客户端状态
	c.NodeType = nodeCategory
	c.ProtocolType = node.Type

	// 更新全局查询参数，确保后续请求带上 node_type
	c.client.SetQueryParam("node_type", c.NodeType)

	// 调试: 保存解析后的节点信息
	if c.Debugger != nil && c.Debugger.IsEnabled() {
		if err := c.Debugger.DumpParsedNodeInfo(node, c.NodeId); err != nil {
			log.WithError(err).Warn("Failed to dump parsed node info")
		}
	}

	return node, nil
}

// ParseNodeInfo parses a UniProxy node configuration answer: the body of
// GET /api/v2/server/UniProxy/config, or one entry of a configuration
// snapshot's legacy_pull (the same document, delivered on the Agent
// control stream). nodeCategory is the node_type the answer names.
func ParseNodeInfo(body []byte, nodeID int) (node *NodeInfo, nodeCategory string, err error) {
	// 先解析基础信息获取节点类型
	var baseInfo struct {
		Type     string `json:"type"`
		NodeType string `json:"node_type"` // 支持 node_type 字段
	}

	if err = json.Unmarshal(body, &baseInfo); err != nil {
		return nil, "", fmt.Errorf("decode node type error: %s", err)
	}

	log.WithFields(log.Fields{
		"type":      baseInfo.Type,
		"node_type": baseInfo.NodeType,
	}).Debug("Parsed node type fields")

	// 彻底分离 node_type 和 type
	// node_type 是节点分类 (node, vmess, vless 等)
	// type 是具体协议 (vmess, vless, trojan 等)
	nodeCategory = strings.ToLower(baseInfo.NodeType)
	protocolType := strings.ToLower(baseInfo.Type)

	// 兼容逻辑：如果其中一个为空，尝试互相补充
	if nodeCategory == "" && protocolType != "" {
		nodeCategory = protocolType
	} else if protocolType == "" && nodeCategory != "" {
		protocolType = nodeCategory
	}

	if nodeCategory == "" {
		// The answer holds the node's secrets: never echo it.
		return nil, "", fmt.Errorf("node type not found in the node configuration (%d bytes)", len(body))
	}

	// 规范化
	if protocolType == "v2ray" {
		protocolType = "vmess"
	}
	if nodeCategory == "v2ray" {
		nodeCategory = "vmess"
	}

	node = &NodeInfo{
		Id:   nodeID,
		Type: protocolType,
		RawDNS: RawDNS{
			DNSMap:  make(map[string]map[string]interface{}),
			DNSJson: []byte(""),
		},
	}
	// parse protocol params
	var cm *CommonNode
	switch protocolType {
	case "vmess", "vless":
		rsp := &VAllssNode{}
		err = json.Unmarshal(body, rsp)
		if err != nil {
			return nil, "", fmt.Errorf("decode v2ray params error: %s", err)
		}
		if len(rsp.NetworkSettingsBack) > 0 {
			rsp.NetworkSettings = rsp.NetworkSettingsBack
			rsp.NetworkSettingsBack = nil
		}
		if rsp.TlsSettingsBack != nil {
			rsp.TlsSettings = *rsp.TlsSettingsBack
			rsp.TlsSettingsBack = nil
		}
		cm = &rsp.CommonNode
		node.VAllss = rsp
		node.Security = node.VAllss.Tls
	case "shadowsocks":
		rsp := &ShadowsocksNode{}
		err = json.Unmarshal(body, rsp)
		if err != nil {
			return nil, "", fmt.Errorf("decode shadowsocks params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Shadowsocks = rsp
		node.Security = None
	case "trojan":
		rsp := &TrojanNode{}
		err = json.Unmarshal(body, rsp)
		if err != nil {
			return nil, "", fmt.Errorf("decode trojan params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Trojan = rsp
		node.Security = Tls
	case "tuic":
		rsp := &TuicNode{}
		err = json.Unmarshal(body, rsp)
		if err != nil {
			return nil, "", fmt.Errorf("decode tuic params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Tuic = rsp
		node.Security = Tls
	case "anytls":
		rsp := &AnyTlsNode{}
		err = json.Unmarshal(body, rsp)
		if err != nil {
			return nil, "", fmt.Errorf("decode anytls params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.AnyTls = rsp
		node.Security = Tls
	case "hysteria":
		rsp := &HysteriaNode{}
		err = json.Unmarshal(body, rsp)
		if err != nil {
			return nil, "", fmt.Errorf("decode hysteria params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Hysteria = rsp
		node.Security = Tls
	case "hysteria2":
		rsp := &Hysteria2Node{}
		err = json.Unmarshal(body, rsp)
		if err != nil {
			return nil, "", fmt.Errorf("decode hysteria2 params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Hysteria2 = rsp
		node.Security = Tls
	case "wireguard":
		rsp := &WireGuardNode{}
		err = json.Unmarshal(body, rsp)
		if err != nil {
			return nil, "", fmt.Errorf("decode wireguard params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.WireGuard = rsp
		node.Security = None
	}
	if cm == nil {
		return nil, "", fmt.Errorf("unsupported node type: %s", protocolType)
	}

	// parse rules and dns
	for i := range cm.Routes {
		var matchs []string
		switch match := cm.Routes[i].Match.(type) {
		case string:
			matchs = strings.Split(match, ",")
		case []string:
			matchs = match
		case []interface{}:
			matchs = make([]string, 0, len(match))
			for _, value := range match {
				text, ok := value.(string)
				if !ok {
					return nil, "", fmt.Errorf("route %d: match entries must be strings", cm.Routes[i].Id)
				}
				matchs = append(matchs, text)
			}
		default:
			return nil, "", fmt.Errorf("route %d: match must be a string or a list of strings", cm.Routes[i].Id)
		}
		if len(matchs) == 0 {
			continue
		}
		switch cm.Routes[i].Action {
		case "block":
			for _, v := range matchs {
				if strings.HasPrefix(v, "protocol:") {
					// protocol
					node.Rules.Protocol = append(node.Rules.Protocol, strings.TrimPrefix(v, "protocol:"))
				} else {
					// domain
					node.Rules.Regexp = append(node.Rules.Regexp, strings.TrimPrefix(v, "regexp:"))
				}
			}
		case "dns":
			var domains []string
			domains = append(domains, matchs...)
			if matchs[0] != "main" {
				node.RawDNS.DNSMap[strconv.Itoa(i)] = map[string]interface{}{
					"address": cm.Routes[i].ActionValue,
					"domains": domains,
				}
			} else {
				dns := []byte(strings.Join(matchs[1:], ""))
				node.RawDNS.DNSJson = dns
			}
		}
	}

	// set interval
	if cm.BaseConfig != nil {
		node.PushInterval = intervalToTime(cm.BaseConfig.PushInterval)
		node.PullInterval = intervalToTime(cm.BaseConfig.PullInterval)
	}

	node.Common = cm
	// clear
	cm.Routes = nil
	cm.BaseConfig = nil

	return node, nodeCategory, nil
}

func intervalToTime(i interface{}) time.Duration {
	switch reflect.TypeOf(i).Kind() {
	case reflect.Int:
		return time.Duration(i.(int)) * time.Second
	case reflect.String:
		i, _ := strconv.Atoi(i.(string))
		return time.Duration(i) * time.Second
	case reflect.Float64:
		return time.Duration(i.(float64)) * time.Second
	default:
		return time.Duration(reflect.ValueOf(i).Int()) * time.Second
	}
}
