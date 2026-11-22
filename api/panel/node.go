package panel

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Security of a node's inbound.
const (
	None = iota
	Tls
	Reality
)

// NodeInfo is one runtime answer of Control, parsed.
type NodeInfo struct {
	Id           int
	Type         string
	Security     int
	PushInterval time.Duration
	PullInterval time.Duration
	Rules        Rules
	Common       *CommonNode

	// Exactly the one of Type is set.
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

// Rules are the node's block rules.
type Rules struct {
	Regexp   []string
	Protocol []string
}

// CommonNode holds the members every protocol shares.
type CommonNode struct {
	Host       string      `json:"host"`
	ServerPort int         `json:"server_port"`
	ServerName string      `json:"server_name"`
	Routes     []Route     `json:"routes"`
	BaseConfig *BaseConfig `json:"base_config"`
}

// Route is one routing rule; Match is a comma-separated string or a list
// of strings.
type Route struct {
	Id     int    `json:"id"`
	Match  any    `json:"match"`
	Action string `json:"action"`
}

// BaseConfig carries the report intervals in seconds, as number or string.
type BaseConfig struct {
	PushInterval any `json:"push_interval"`
	PullInterval any `json:"pull_interval"`
}

type VLessVMessNode struct {
	CommonNode
	Tls             int             `json:"tls"`
	TlsSettings     TlsSettings     `json:"tls_settings"`
	Network         string          `json:"network"`
	NetworkSettings json.RawMessage `json:"network_settings"`
	Flow            string          `json:"flow"`
}

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

// ParseNodeInfo parses one runtime answer of node nodeID and returns it
// with the answer's node category. Errors never quote the body: it holds
// secrets.
func ParseNodeInfo(body []byte, nodeID int) (*NodeInfo, string, error) {
	var head struct {
		Type     string `json:"type"`
		NodeType string `json:"node_type"`
		CommonNode
	}
	if err := json.Unmarshal(body, &head); err != nil {
		return nil, "", fmt.Errorf("decode the node configuration (%d bytes): %w", len(body), err)
	}
	protocol, category := normalizeType(head.Type), normalizeType(head.NodeType)
	if protocol == "" {
		protocol = category
	}
	if category == "" {
		category = protocol
	}
	if protocol == "" {
		return nil, "", fmt.Errorf("node type not found in the node configuration (%d bytes)", len(body))
	}

	info := &NodeInfo{Id: nodeID, Type: protocol}
	rules, err := blockRules(head.Routes)
	if err != nil {
		return nil, "", err
	}
	info.Rules = rules
	if base := head.BaseConfig; base != nil {
		info.PushInterval = seconds(base.PushInterval)
		info.PullInterval = seconds(base.PullInterval)
	}
	common := head.CommonNode
	common.Routes, common.BaseConfig = nil, nil
	info.Common = &common

	switch protocol {
	case "vless", "vmess":
		info.VLessVMess, err = decodeNode[VLessVMessNode](body, common)
		if err == nil {
			info.Security = info.VLessVMess.Tls
		}
	case "shadowsocks":
		info.Shadowsocks, err = decodeNode[ShadowsocksNode](body, common)
	case "trojan":
		info.Security = Tls
		info.Trojan, err = decodeNode[TrojanNode](body, common)
	case "tuic":
		info.Security = Tls
		info.Tuic, err = decodeNode[TuicNode](body, common)
	case "anytls":
		info.Security = Tls
		info.AnyTls, err = decodeNode[AnyTlsNode](body, common)
	case "hysteria2":
		info.Security = Tls
		info.Hysteria2, err = decodeNode[Hysteria2Node](body, common)
	case "wireguard":
		info.WireGuard, err = decodeNode[WireGuardNode](body, common)
	case "iwan":
		info.Iwan, err = decodeNode[IwanNode](body, common)
	case "anx":
		info.Anx, err = decodeNode[AnxNode](body, common)
	case "snell":
		info.Snell, err = decodeNode[SnellNode](body, common)
	default:
		return nil, "", fmt.Errorf("unsupported node type: %s", protocol)
	}
	if err != nil {
		return nil, "", fmt.Errorf("decode the %s node configuration: %w", protocol, err)
	}
	return info, category, nil
}

func normalizeType(name string) string {
	name = strings.ToLower(name)
	if name == "v2ray" {
		return "vmess"
	}
	return name
}

// commonNode lets decodeNode reach the embedded CommonNode.
func (c *CommonNode) commonNode() *CommonNode { return c }

// decodeNode decodes a protocol node and replaces its common members with
// common, whose routes and base_config are already cleared.
func decodeNode[T any, P interface {
	*T
	commonNode() *CommonNode
}](body []byte, common CommonNode) (P, error) {
	node := P(new(T))
	if err := json.Unmarshal(body, node); err != nil {
		return nil, err
	}
	*node.commonNode() = common
	return node, nil
}

// blockRules collects the entries of the routes with action block.
func blockRules(routes []Route) (Rules, error) {
	var rules Rules
	for _, route := range routes {
		entries, err := matchEntries(route.Match)
		if err != nil {
			return Rules{}, fmt.Errorf("route %d: %w", route.Id, err)
		}
		if route.Action != "block" {
			continue
		}
		for _, entry := range entries {
			if name, ok := strings.CutPrefix(entry, "protocol:"); ok {
				rules.Protocol = append(rules.Protocol, name)
			} else {
				rules.Regexp = append(rules.Regexp, strings.TrimPrefix(entry, "regexp:"))
			}
		}
	}
	return rules, nil
}

func matchEntries(match any) ([]string, error) {
	var entries []string
	switch match := match.(type) {
	case string:
		entries = strings.Split(match, ",")
	case []any:
		for _, item := range match {
			entry, ok := item.(string)
			if !ok {
				return nil, errors.New("match holds a non-string entry")
			}
			entries = append(entries, entry)
		}
	default:
		return nil, fmt.Errorf("match is %T, not a string or a list of strings", match)
	}
	kept := entries[:0]
	for _, entry := range entries {
		if entry = strings.TrimSpace(entry); entry != "" {
			kept = append(kept, entry)
		}
	}
	return kept, nil
}

// seconds reads an interval given as JSON number or numeric string; anything
// else is 0.
func seconds(value any) time.Duration {
	var n float64
	switch value := value.(type) {
	case float64:
		n = value
	case string:
		n, _ = strconv.ParseFloat(strings.TrimSpace(value), 64)
	}
	return time.Duration(n * float64(time.Second))
}
