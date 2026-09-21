package panel

import (
	"encoding/json"
)

// ========== 同步消息类型定义 ==========

// SyncMessageType 同步消息类型
type SyncMessageType string

const (
	// 服务端 -> 节点
	MsgTypeConfigUpdate SyncMessageType = "config_update" // 配置更新
	MsgTypeUserUpdate   SyncMessageType = "user_update"   // 用户变更
	MsgTypeUserBan      SyncMessageType = "user_ban"      // 用户封禁 (紧急)
	MsgTypeRuleUpdate   SyncMessageType = "rule_update"   // 规则更新
	MsgTypeCertUpdate   SyncMessageType = "cert_update"   // 证书更新
	MsgTypePing         SyncMessageType = "ping"          // 心跳检测
	MsgTypeForceReload  SyncMessageType = "force_reload"  // 强制重载

	// 节点 -> 服务端
	MsgTypeMaintenanceEvents SyncMessageType = "maintenance_events"
	MsgTypeMaintenanceAck    SyncMessageType = "maintenance_ack"
	MsgTypeHeartbeat         SyncMessageType = "heartbeat"      // 心跳响应
	MsgTypeAck               SyncMessageType = "ack"            // 消息确认
	MsgTypeTrafficReport     SyncMessageType = "traffic_report" // 流量上报
	MsgTypeAlertReport       SyncMessageType = "alert"          // 告警上报
	MsgTypePong              SyncMessageType = "pong"           // Pong 响应
)

// ========== 同步消息结构 ==========

// SyncMessage 同步消息
type SyncMessage struct {
	ID         string          `json:"id"`                    // 消息唯一ID
	Type       SyncMessageType `json:"type"`                  // 消息类型
	Timestamp  int64           `json:"timestamp"`             // 时间戳 (Unix)
	NodeID     int             `json:"node_id"`               // 节点ID
	Payload    json.RawMessage `json:"payload"`               // 消息负载
	Priority   int             `json:"priority,omitempty"`    // 优先级 (0=普通, 1=高, 2=紧急)
	RequireAck bool            `json:"require_ack,omitempty"` // 是否需要确认
}

// ========== 配置更新相关 ==========

// ConfigUpdatePayload 配置更新负载
type ConfigUpdatePayload struct {
	Version    int64          `json:"version"`             // 配置版本号
	ChangeType string         `json:"change_type"`         // full | partial
	NodeInfo   *NodeInfo      `json:"node_info,omitempty"` // 完整配置 (full 时使用)
	Changes    []ConfigChange `json:"changes,omitempty"`   // 变更列表 (partial 时使用)
}

// ConfigChange 配置变更项
type ConfigChange struct {
	Field    string      `json:"field"`               // 变更字段路径 (如 "server_port", "tls_settings.server_name")
	OldValue interface{} `json:"old_value,omitempty"` // 旧值
	NewValue interface{} `json:"new_value"`           // 新值
	Action   string      `json:"action,omitempty"`    // set | delete
}

// ========== 用户更新相关 ==========

// UserUpdatePayload 用户更新负载
type UserUpdatePayload struct {
	Action string     `json:"action"`           // add | remove | update | ban
	Users  []UserInfo `json:"users"`            // 涉及的用户
	Reason string     `json:"reason,omitempty"` // 原因 (封禁时使用)
}

// UserBanPayload 用户封禁负载 (紧急消息专用)
type UserBanPayload struct {
	UserIDs   []int    `json:"user_ids"`            // 用户ID列表
	UUIDs     []string `json:"uuids"`               // UUID列表
	Reason    string   `json:"reason,omitempty"`    // 封禁原因
	ExpireAt  int64    `json:"expire_at,omitempty"` // 过期时间 (0=永久)
	Immediate bool     `json:"immediate"`           // 是否立即生效
}

// ========== 规则更新相关 ==========

// RuleUpdatePayload 规则更新负载
type RuleUpdatePayload struct {
	Action string `json:"action"` // replace | append | remove
	Rules  Rules  `json:"rules"`  // 规则内容
}

// ========== 证书更新相关 ==========

// CertUpdatePayload 证书更新负载
type CertUpdatePayload struct {
	Domain     string `json:"domain"`      // 域名
	CertPEM    string `json:"cert_pem"`    // 证书内容 (PEM)
	KeyPEM     string `json:"key_pem"`     // 私钥内容 (PEM)
	ExpireAt   int64  `json:"expire_at"`   // 过期时间
	AutoReload bool   `json:"auto_reload"` // 是否自动重载
}

// ========== 心跳相关 ==========

// HeartbeatPayload 心跳负载
type HeartbeatPayload struct {
	CPUUsage      float64 `json:"cpu_usage"`
	MemoryUsage   float64 `json:"memory_usage"`
	DiskUsage     float64 `json:"disk_usage"`
	Uptime        int64   `json:"uptime"`
	OnlineUsers   int     `json:"online_users"`
	Connections   int     `json:"connections"`
	Upload        int64   `json:"upload"`
	Download      int64   `json:"download"`
	Version       string  `json:"version"`
	ConfigVersion int64   `json:"config_version,omitempty"`
}

// PingPayload Ping 负载
type PingPayload struct {
	ServerTime int64 `json:"server_time"` // 服务端时间
}

// PongPayload Pong 负载
type PongPayload struct {
	ServerTime int64 `json:"server_time"` // 回显服务端时间
	ClientTime int64 `json:"client_time"` // 客户端时间
	Latency    int64 `json:"latency"`     // 延迟 (ms)
}

// ========== 确认消息相关 ==========

// AckPayload 确认消息负载
type AckPayload struct {
	MessageID string `json:"msg_id"`          // 原消息ID
	Success   bool   `json:"success"`         // 是否成功
	Error     string `json:"error,omitempty"` // 错误信息
	Timestamp int64  `json:"timestamp"`       // 处理时间
}

// ========== 流量上报相关 ==========

// TrafficReportPayload 流量上报负载
type TrafficReportPayload struct {
	Period    int64         `json:"period"`     // 统计周期 (秒)
	Traffic   []UserTraffic `json:"traffic"`    // 用户流量
	TotalUp   int64         `json:"total_up"`   // 总上传
	TotalDown int64         `json:"total_down"` // 总下载
}

// ========== 告警相关 ==========

// AlertPayload 告警负载
type AlertPayload struct {
	Level     string            `json:"level"`             // info | warning | error | critical
	Type      string            `json:"type"`              // 告警类型
	Message   string            `json:"message"`           // 告警消息
	Details   map[string]string `json:"details,omitempty"` // 详细信息
	Timestamp int64             `json:"timestamp"`         // 发生时间
}

// ========== 强制重载相关 ==========

// ForceReloadPayload 强制重载负载
type ForceReloadPayload struct {
	Reason     string `json:"reason,omitempty"`      // 重载原因
	ClearCache bool   `json:"clear_cache,omitempty"` // 是否清除缓存
}

// ========== 辅助方法 ==========

// NewSyncMessage 创建新的同步消息
func NewSyncMessage(msgType SyncMessageType, nodeID int, payload interface{}) (*SyncMessage, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	return &SyncMessage{
		ID:        generateMessageID(),
		Type:      msgType,
		Timestamp: currentTimestamp(),
		NodeID:    nodeID,
		Payload:   payloadBytes,
	}, nil
}

// ParsePayload 解析消息负载
func (m *SyncMessage) ParsePayload(v interface{}) error {
	return json.Unmarshal(m.Payload, v)
}

// IsHighPriority 是否高优先级消息
func (m *SyncMessage) IsHighPriority() bool {
	return m.Priority > 0
}

// IsUrgent 是否紧急消息
func (m *SyncMessage) IsUrgent() bool {
	return m.Priority >= 2 || m.Type == MsgTypeUserBan || m.Type == MsgTypeForceReload
}
