package node

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	apiclient "github.com/AnixOps/anix-agent/v4/api/client"
	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/common/maintenance"
	"github.com/AnixOps/anix-agent/v4/common/sign"
	vCore "github.com/AnixOps/anix-agent/v4/core"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// SyncState 鍚屾鐘舵€?
type SyncState int32

const (
	SyncStateDisconnected SyncState = iota
	SyncStateConnecting
	SyncStateConnected
	SyncStateFallback
	SyncStateClosed
)

func (s SyncState) String() string {
	switch s {
	case SyncStateDisconnected:
		return "disconnected"
	case SyncStateConnecting:
		return "connecting"
	case SyncStateConnected:
		return "connected"
	case SyncStateFallback:
		return "fallback"
	case SyncStateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// SyncConfig 鍚屾閰嶇疆
type SyncConfig struct {
	MaintenanceOnly bool `json:"-"`
	// WebSocket 閰嶇疆
	EnableWebSocket     bool          `json:"EnableWebSocket"`
	WSEndpoint          string        `json:"WSEndpoint"`
	WSEndpointFallbacks []string      `json:"WSEndpointFallbacks,omitempty"`
	ReconnectInterval   time.Duration `json:"ReconnectInterval"`
	MaxReconnectTries   int           `json:"MaxReconnectTries"` // 0 = 鏃犻檺閲嶈瘯

	// 蹇冭烦閰嶇疆
	PingInterval time.Duration `json:"PingInterval"`
	PongTimeout  time.Duration `json:"PongTimeout"`

	// 娑堟伅閰嶇疆
	AckTimeout time.Duration `json:"AckTimeout"`
	BufferSize int           `json:"BufferSize"`
	AckRetries int           `json:"AckRetries"`

	// 闄嶇骇閰嶇疆
	EnableFallback   bool          `json:"EnableFallback"`
	FallbackInterval time.Duration `json:"FallbackInterval"`
}

// DefaultSyncConfig 榛樿鍚屾閰嶇疆
func DefaultSyncConfig() *SyncConfig {
	return &SyncConfig{
		EnableWebSocket:     true,
		WSEndpoint:          "/api/v2/agent/ws",
		WSEndpointFallbacks: []string{"/api/v2/node/ws"},
		ReconnectInterval:   5 * time.Second,
		MaxReconnectTries:   0,
		PingInterval:        30 * time.Second,
		PongTimeout:         10 * time.Second,
		AckTimeout:          5 * time.Second,
		BufferSize:          100,
		AckRetries:          2,
		EnableFallback:      true,
		FallbackInterval:    60 * time.Second,
	}
}

// SyncManager 鍚屾绠＄悊鍣?
type SyncManager struct {
	client     apiclient.NodeAPI
	controller *Controller
	config     *SyncConfig

	// WebSocket 杩炴帴
	conn   *websocket.Conn
	connMu sync.RWMutex

	// 鐘舵€?
	state        int32 // atomic
	reconnecting int32 // atomic

	// 娑堟伅閫氶亾
	inbound          chan *panel.SyncMessage
	outbound         chan *panel.SyncMessage
	maintenanceMu    sync.Mutex
	maintenanceStore *maintenance.Store
	workersOnce      sync.Once
	writeMu          sync.Mutex

	// 寰呯‘璁ゆ秷鎭?
	pendingAcks sync.Map // map[msgID]*pendingAck

	// 缁熻
	stats *SyncStats

	// 鐢熷懡鍛ㄦ湡
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// SyncStats 鍚屾缁熻
type SyncStats struct {
	MessagesReceived int64
	MessagesSent     int64
	ReconnectCount   int64
	LastConnectedAt  time.Time
	LastMessageAt    time.Time
	CurrentLatency   int64 // ms
}

// pendingAck 寰呯‘璁ゆ秷鎭?
type pendingAck struct {
	msg     *panel.SyncMessage
	sentAt  time.Time
	ackChan chan *panel.AckPayload
	timeout time.Duration
}

// NewSyncManager 鍒涘缓鍚屾绠＄悊鍣?
func NewSyncManager(client apiclient.NodeAPI, controller *Controller, config *SyncConfig) *SyncManager {
	if config == nil {
		config = DefaultSyncConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &SyncManager{
		client:     client,
		controller: controller,
		config:     config,
		inbound:    make(chan *panel.SyncMessage, config.BufferSize),
		outbound:   make(chan *panel.SyncMessage, config.BufferSize),
		stats:      &SyncStats{},
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start 鍚姩鍚屾绠＄悊鍣?
func (sm *SyncManager) Start() error {
	if !sm.config.EnableWebSocket {
		log.Info("WebSocket sync disabled, using polling mode only")
		return nil
	}

	log.WithField("endpoint", sm.config.WSEndpoint).Info("Starting sync manager")

	// 灏濊瘯杩炴帴
	if err := sm.connect(); err != nil {
		log.WithError(err).Warn("Initial WebSocket connection failed")

		if sm.config.EnableFallback {
			log.Info("Falling back to polling mode")
			sm.setState(SyncStateFallback)
			sm.wg.Add(1)
			go sm.runFallbackMode()
		} else {
			sm.startReconnect()
		}
		return nil
	}

	// 鍚姩宸ヤ綔鍗忕▼
	sm.startWorkers()

	return nil
}

// connect 寤虹珛 WebSocket 杩炴帴
func (sm *SyncManager) connect() error {
	if !sm.compareAndSetState(SyncStateDisconnected, SyncStateConnecting) &&
		!sm.compareAndSetState(SyncStateFallback, SyncStateConnecting) {
		return fmt.Errorf("invalid state for connect: %s", sm.getState())
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	var lastErr error
	for _, endpoint := range sm.wsEndpoints() {
		wsURL := sm.buildWSURL(endpoint)
		headers := sm.buildHeaders(endpoint)

		log.WithFields(log.Fields{
			"endpoint": endpoint,
			"url":      wsURL,
		}).Debug("Connecting to WebSocket")

		conn, resp, err := dialer.DialContext(sm.ctx, wsURL, headers)
		if err != nil {
			lastErr = err
			if resp != nil {
				log.WithFields(log.Fields{
					"endpoint": endpoint,
					"status":   resp.StatusCode,
					"error":    err,
				}).Warn("WebSocket dial failed")
			}
			continue
		}

		sm.connMu.Lock()
		if sm.ctx.Err() != nil || sm.getState() == SyncStateClosed {
			sm.connMu.Unlock()
			_ = conn.Close()
			return sm.ctx.Err()
		}
		sm.conn = conn
		conn.SetReadLimit(4 << 20)
		sm.connMu.Unlock()

		sm.setState(SyncStateConnected)
		sm.maintenanceMu.Lock()
		sm.stats.LastConnectedAt = time.Now()
		sm.maintenanceMu.Unlock()

		log.WithField("endpoint", endpoint).Info("WebSocket connected successfully")
		return nil
	}

	sm.setState(SyncStateDisconnected)
	if lastErr == nil {
		lastErr = fmt.Errorf("no websocket endpoints configured")
	}
	return fmt.Errorf("dial: %w", lastErr)
}

// buildWSURL 鏋勫缓 WebSocket URL
func (sm *SyncManager) wsEndpoints() []string {
	seen := make(map[string]struct{})
	endpoints := make([]string, 0, 1+len(sm.config.WSEndpointFallbacks))

	appendEndpoint := func(endpoint string) {
		ep := normalizeWSEndpoint(endpoint)
		if ep == "" {
			return
		}
		if _, exists := seen[ep]; exists {
			return
		}
		seen[ep] = struct{}{}
		endpoints = append(endpoints, ep)
	}

	appendEndpoint(sm.config.WSEndpoint)
	for _, endpoint := range sm.config.WSEndpointFallbacks {
		appendEndpoint(endpoint)
	}

	if len(endpoints) == 0 {
		endpoints = append(endpoints, "/api/v2/agent/ws")
	}

	return endpoints
}

func normalizeWSEndpoint(endpoint string) string {
	ep := strings.TrimSpace(endpoint)
	if ep == "" {
		return ""
	}
	if !strings.HasPrefix(ep, "/") {
		ep = "/" + ep
	}
	return ep
}

func normalizeIncomingMessageType(messageType panel.SyncMessageType) panel.SyncMessageType {
	switch messageType {
	case panel.SyncMessageType("config.update"):
		return panel.MsgTypeConfigUpdate
	case panel.SyncMessageType("user.update"):
		return panel.MsgTypeUserUpdate
	case panel.SyncMessageType("user.ban"):
		return panel.MsgTypeUserBan
	case panel.SyncMessageType("rule.update"):
		return panel.MsgTypeRuleUpdate
	case panel.SyncMessageType("cert.update"):
		return panel.MsgTypeCertUpdate
	case panel.SyncMessageType("traffic.report"):
		return panel.MsgTypeTrafficReport
	case panel.SyncMessageType("force.reload"):
		return panel.MsgTypeForceReload
	default:
		return messageType
	}
}

func (sm *SyncManager) buildWSURL(endpoint string) string {
	baseURL := sm.client.GetAPIHost()

	// 鏇挎崲 http -> ws, https -> wss
	baseURL = strings.Replace(baseURL, "https://", "wss://", 1)
	baseURL = strings.Replace(baseURL, "http://", "ws://", 1)

	// 瑙ｆ瀽骞舵坊鍔犳煡璇㈠弬鏁?
	u, err := url.Parse(baseURL + endpoint)
	if err != nil {
		return baseURL + endpoint
	}

	q := u.Query()
	q.Set("node_id", strconv.Itoa(sm.client.GetNodeID()))
	u.RawQuery = q.Encode()

	return u.String()
}

// buildHeaders 鏋勫缓璇锋眰澶?
func (sm *SyncManager) buildHeaders(endpoint string) http.Header {
	headers := http.Header{}
	headers.Set("X-API-Key", sm.client.GetAPIKey())
	headers.Set("X-Node-ID", strconv.Itoa(sm.client.GetNodeID()))

	// 娣诲姞绛惧悕
	if sm.client.IsSignEnabled() && sm.client.GetSecret() != "" {
		signer := sign.NewSigner(sm.client.GetSecret())
		signData := signer.Sign("GET", endpoint, nil)
		headers.Set("X-Timestamp", signData.Timestamp)
		headers.Set("X-Nonce", signData.Nonce)
		headers.Set("X-Signature", signData.Signature)
	}

	return headers
}

// startWorkers 鍚姩宸ヤ綔鍗忕▼
func (sm *SyncManager) startWorkers() {
	sm.workersOnce.Do(func() {
		sm.wg.Add(3)
		go sm.writeLoop()
		go sm.processLoop()
		go sm.heartbeatLoop()
	})
	sm.wg.Add(1)
	go sm.readLoop()
}

// readLoop 璇诲彇娑堟伅寰幆
func (sm *SyncManager) readLoop() {
	defer sm.wg.Done()
	defer sm.handleDisconnect()

	for {
		select {
		case <-sm.ctx.Done():
			return
		default:
		}

		sm.connMu.RLock()
		conn := sm.conn
		sm.connMu.RUnlock()

		if conn == nil {
			return
		}

		_, data, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.WithError(err).Error("WebSocket read error")
			}
			return
		}

		var msg panel.SyncMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			log.WithError(err).Error("Failed to unmarshal message")
			continue
		}
		msg.Type = normalizeIncomingMessageType(msg.Type)

		atomic.AddInt64(&sm.stats.MessagesReceived, 1)
		sm.maintenanceMu.Lock()
		sm.stats.LastMessageAt = time.Now()
		sm.maintenanceMu.Unlock()

		// 浼樺厛澶勭悊绱ф€ユ秷鎭?
		if msg.IsUrgent() {
			go sm.handleMessage(&msg)
		} else {
			select {
			case sm.inbound <- &msg:
			default:
				log.Warn("Inbound channel full, dropping message")
			}
		}
	}
}

// writeLoop 鍙戦€佹秷鎭惊鐜?
func (sm *SyncManager) writeLoop() {
	defer sm.wg.Done()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case msg := <-sm.outbound:
			var err error
			if msg != nil && msg.RequireAck {
				err = sm.sendWithAck(msg)
			} else {
				err = sm.send(msg)
			}
			if err != nil {
				log.WithError(err).Error("Failed to send message")
			}
		}
	}
}

// processLoop 澶勭悊娑堟伅寰幆
func (sm *SyncManager) processLoop() {
	defer sm.wg.Done()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case msg := <-sm.inbound:
			sm.handleMessage(msg)
		}
	}
}

// heartbeatLoop 蹇冭烦寰幆
func (sm *SyncManager) heartbeatLoop() {
	defer sm.wg.Done()

	ticker := time.NewTicker(sm.config.PingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			if sm.getState() != SyncStateConnected {
				continue
			}

			// 鍙戦€佸績璺?
			if err := sm.sendHeartbeat(); err != nil {
				log.WithError(err).Warn("Failed to send heartbeat")
			}
		}
	}
}

// handleMessage 澶勭悊娑堟伅
func (sm *SyncManager) handleMessage(msg *panel.SyncMessage) {
	if msg == nil {
		return
	}
	msg.Type = normalizeIncomingMessageType(msg.Type)

	log.WithFields(log.Fields{
		"type": msg.Type,
		"id":   msg.ID,
	}).Debug("Processing sync message")

	var err error
	if sm.config.MaintenanceOnly && msg.Type != panel.MsgTypeMaintenanceAck && msg.Type != panel.MsgTypePing {
		return
	}

	switch msg.Type {
	case panel.MsgTypeConfigUpdate:
		err = sm.handleConfigUpdate(msg)
	case panel.MsgTypeUserUpdate:
		err = sm.handleUserUpdate(msg)
	case panel.MsgTypeUserBan:
		err = sm.handleUserBan(msg)
	case panel.MsgTypeRuleUpdate:
		err = sm.handleRuleUpdate(msg)
	case panel.MsgTypeCertUpdate:
		err = sm.handleCertUpdate(msg)
	case panel.MsgTypePing:
		err = sm.handlePing(msg)
	case panel.MsgTypeForceReload:
		err = sm.handleForceReload(msg)
	case panel.MsgTypeMaintenanceAck:
		if err := sm.handleMaintenanceAck(msg); err != nil {
			log.WithError(err).Warn("Maintenance acknowledgment rejected")
		}
		return
	case panel.MsgTypeAck:
		sm.handleAck(msg)
		return // Ack 娑堟伅涓嶉渶瑕佸啀纭
	default:
		log.WithField("type", msg.Type).Warn("Unknown message type")
		return
	}

	// 鍙戦€佺‘璁?
	if msg.RequireAck {
		sm.sendAck(msg.ID, err)
	}
}

// handleConfigUpdate 澶勭悊閰嶇疆鏇存柊
func (sm *SyncManager) handleConfigUpdate(msg *panel.SyncMessage) error {
	var payload panel.ConfigUpdatePayload
	if err := msg.ParsePayload(&payload); err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}

	log.WithFields(log.Fields{
		"version":    payload.Version,
		"changeType": payload.ChangeType,
	}).Info("Received config update")

	if payload.ChangeType == "full" && payload.NodeInfo != nil {
		// 瀹屾暣閰嶇疆鏇存柊 - 瑙﹀彂鑺傜偣閲嶈浇
		return sm.controller.reloadNode(payload.NodeInfo)
	}

	// TODO: 瀹炵幇澧為噺閰嶇疆鏇存柊
	// 鐩墠鍏堜娇鐢ㄥ畬鏁撮噸杞?
	log.Debug("Partial config update, fetching full config")
	return sm.controller.nodeInfoMonitor()
}

// handleUserUpdate 澶勭悊鐢ㄦ埛鏇存柊
func (sm *SyncManager) handleUserUpdate(msg *panel.SyncMessage) error {
	var payload panel.UserUpdatePayload
	if err := msg.ParsePayload(&payload); err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}

	log.WithFields(log.Fields{
		"action": payload.Action,
		"count":  len(payload.Users),
	}).Info("Received user update")

	switch payload.Action {
	case "add":
		_, err := sm.controller.server.AddUsers(&vCore.AddUsersParams{
			Tag:      sm.controller.tag,
			Users:    payload.Users,
			NodeInfo: sm.controller.info,
		})
		if err != nil {
			return fmt.Errorf("add users: %w", err)
		}
		sm.controller.limiter.UpdateUser(sm.controller.tag, payload.Users, nil)

	case "remove":
		if err := sm.controller.server.DelUsers(payload.Users, sm.controller.tag, sm.controller.info); err != nil {
			return fmt.Errorf("del users: %w", err)
		}
		sm.controller.limiter.UpdateUser(sm.controller.tag, nil, payload.Users)

	case "update":
		// 鍏堝垹闄ゅ啀娣诲姞
		_ = sm.controller.server.DelUsers(payload.Users, sm.controller.tag, sm.controller.info)
		_, err := sm.controller.server.AddUsers(&vCore.AddUsersParams{
			Tag:      sm.controller.tag,
			Users:    payload.Users,
			NodeInfo: sm.controller.info,
		})
		if err != nil {
			return fmt.Errorf("update users: %w", err)
		}
		sm.controller.limiter.UpdateUser(sm.controller.tag, payload.Users, payload.Users)
	}

	return nil
}

// handleUserBan 澶勭悊鐢ㄦ埛灏佺 (绱ф€ヤ簨浠?
func (sm *SyncManager) handleUserBan(msg *panel.SyncMessage) error {
	var payload panel.UserBanPayload
	if err := msg.ParsePayload(&payload); err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}

	log.WithFields(log.Fields{
		"count":  len(payload.UUIDs),
		"reason": payload.Reason,
	}).Warn("Received user ban (URGENT)")

	// 鏋勫缓 UserInfo 鐢ㄤ簬鍒犻櫎
	users := make([]panel.UserInfo, 0, len(payload.UUIDs))
	for i, uuid := range payload.UUIDs {
		uid := 0
		if i < len(payload.UserIDs) {
			uid = payload.UserIDs[i]
		}
		users = append(users, panel.UserInfo{
			Id:   uid,
			Uuid: uuid,
		})
	}

	// 绔嬪嵆鍒犻櫎
	if err := sm.controller.server.DelUsers(users, sm.controller.tag, sm.controller.info); err != nil {
		return fmt.Errorf("ban users: %w", err)
	}

	sm.controller.limiter.UpdateUser(sm.controller.tag, nil, users)

	return nil
}

// handleRuleUpdate 澶勭悊瑙勫垯鏇存柊
func (sm *SyncManager) handleRuleUpdate(msg *panel.SyncMessage) error {
	var payload panel.RuleUpdatePayload
	if err := msg.ParsePayload(&payload); err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}

	log.WithField("action", payload.Action).Info("Received rule update")

	return sm.controller.limiter.UpdateRule(&payload.Rules)
}

// handleCertUpdate 澶勭悊璇佷功鏇存柊
func (sm *SyncManager) handleCertUpdate(msg *panel.SyncMessage) error {
	var payload panel.CertUpdatePayload
	if err := msg.ParsePayload(&payload); err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}

	log.WithField("domain", payload.Domain).Info("Received cert update")

	// TODO: 瀹炵幇璇佷功鐑洿鏂?
	// 鐩墠鍏堣Е鍙戝畬鏁撮噸杞?
	if payload.AutoReload {
		return sm.controller.nodeInfoMonitor()
	}

	return nil
}

// handlePing 澶勭悊 Ping
func (sm *SyncManager) handlePing(msg *panel.SyncMessage) error {
	var payload panel.PingPayload
	if err := msg.ParsePayload(&payload); err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}

	// 鍥炲 Pong
	pong := &panel.PongPayload{
		ServerTime: payload.ServerTime,
		ClientTime: time.Now().Unix(),
		Latency:    time.Now().UnixMilli() - payload.ServerTime*1000,
	}

	pongMsg, _ := panel.NewSyncMessage(panel.MsgTypePong, sm.client.GetNodeID(), pong)
	sm.outbound <- pongMsg

	return nil
}

// handleForceReload 澶勭悊寮哄埗閲嶈浇
func (sm *SyncManager) handleForceReload(msg *panel.SyncMessage) error {
	var payload panel.ForceReloadPayload
	if err := msg.ParsePayload(&payload); err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}

	log.WithField("reason", payload.Reason).Warn("Received force reload command")

	// 閲嶆柊鑾峰彇閰嶇疆骞堕噸杞借妭鐐?
	return sm.controller.nodeInfoMonitor()
}

// handleAck 澶勭悊纭娑堟伅
func (sm *SyncManager) handleAck(msg *panel.SyncMessage) {
	var payload panel.AckPayload
	if err := msg.ParsePayload(&payload); err != nil || payload.MessageID == "" {
		var alias struct {
			MsgID     string `json:"msg_id"`
			MessageID string `json:"message_id"`
			Success   bool   `json:"success"`
			Error     string `json:"error,omitempty"`
			Timestamp int64  `json:"timestamp"`
		}
		if err := json.Unmarshal(msg.Payload, &alias); err != nil {
			log.WithError(err).Error("Failed to parse ack payload")
			return
		}
		payload.MessageID = alias.MsgID
		if payload.MessageID == "" {
			payload.MessageID = alias.MessageID
		}
		payload.Success = alias.Success
		payload.Error = alias.Error
		payload.Timestamp = alias.Timestamp
	}

	if payload.MessageID == "" {
		return
	}

	if pending, ok := sm.pendingAcks.LoadAndDelete(payload.MessageID); ok {
		p := pending.(*pendingAck)
		select {
		case p.ackChan <- &payload:
		default:
		}
	}
}

// sendAck 鍙戦€佺‘璁ゆ秷鎭?
func (sm *SyncManager) sendAck(msgID string, err error) {
	payload := &panel.AckPayload{
		MessageID: msgID,
		Success:   err == nil,
		Timestamp: time.Now().Unix(),
	}
	if err != nil {
		payload.Error = err.Error()
	}

	ackMsg, _ := panel.NewSyncMessage(panel.MsgTypeAck, sm.client.GetNodeID(), payload)
	sm.outbound <- ackMsg
}

// sendHeartbeat 鍙戦€佸績璺?
func (sm *SyncManager) sendHeartbeat() error {
	sm.maintenanceMu.Lock()
	connectedAt := sm.stats.LastConnectedAt
	store := sm.maintenanceStore
	sm.maintenanceMu.Unlock()
	if sm.config.MaintenanceOnly {
		if store == nil {
			return nil
		}
		return sm.sendMaintenanceBatch(store)
	}
	payload := &panel.HeartbeatPayload{Uptime: int64(time.Since(connectedAt).Seconds()), Version: panel.Version}
	msg, err := panel.NewSyncMessage(panel.MsgTypeHeartbeat, sm.client.GetNodeID(), payload)
	if err != nil {
		return err
	}
	select {
	case sm.outbound <- msg:
	case <-sm.ctx.Done():
		return sm.ctx.Err()
	}
	if store == nil {
		return nil
	}
	return sm.sendMaintenanceBatch(store)
}

func (sm *SyncManager) SetMaintenanceStore(store *maintenance.Store) {
	sm.maintenanceMu.Lock()
	defer sm.maintenanceMu.Unlock()
	sm.maintenanceStore = store
}
func (sm *SyncManager) QueueMaintenanceEvent(event maintenance.Event) error {
	sm.maintenanceMu.Lock()
	store := sm.maintenanceStore
	sm.maintenanceMu.Unlock()
	if store == nil {
		return fmt.Errorf("durable maintenance outbox is not configured")
	}
	return store.Queue(event)
}
func (sm *SyncManager) sendMaintenanceBatch(store *maintenance.Store) error {
	events, err := store.Pending(maintenance.MaxBatchSize)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}
	batch := maintenance.Batch{Version: maintenance.Version, Events: events}
	msg, err := panel.NewSyncMessage(panel.MsgTypeMaintenanceEvents, sm.client.GetNodeID(), batch)
	if err != nil {
		return err
	}
	if len(msg.Payload) > maintenance.MaxPayloadBytes {
		return fmt.Errorf("maintenance batch exceeds payload limit")
	}
	select {
	case sm.outbound <- msg:
		return nil
	case <-sm.ctx.Done():
		return sm.ctx.Err()
	}
}
func (sm *SyncManager) handleMaintenanceAck(msg *panel.SyncMessage) error {
	if len(msg.Payload) > maintenance.MaxPayloadBytes {
		return fmt.Errorf("maintenance acknowledgment exceeds payload limit")
	}
	if msg.NodeID != 0 && msg.NodeID != sm.client.GetNodeID() {
		return fmt.Errorf("maintenance acknowledgment node mismatch")
	}
	var ack maintenance.Acknowledgment
	decoder := json.NewDecoder(bytes.NewReader(msg.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ack); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("invalid trailing acknowledgment data")
	}
	sm.maintenanceMu.Lock()
	store := sm.maintenanceStore
	sm.maintenanceMu.Unlock()
	if store == nil {
		return fmt.Errorf("durable maintenance outbox is not configured")
	}
	return store.Acknowledge(ack)
}

// send 鍙戦€佹秷鎭?
func (sm *SyncManager) sendWithAck(msg *panel.SyncMessage) error {
	if msg == nil {
		return nil
	}
	if msg.ID == "" {
		msg.ID = nextMessageID()
	}

	attempts := sm.config.AckRetries + 1
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		waiter := &pendingAck{
			msg:     msg,
			sentAt:  time.Now(),
			ackChan: make(chan *panel.AckPayload, 1),
			timeout: sm.config.AckTimeout,
		}
		sm.pendingAcks.Store(msg.ID, waiter)

		if err := sm.send(msg); err != nil {
			sm.pendingAcks.Delete(msg.ID)
			lastErr = err
			continue
		}

		select {
		case ack := <-waiter.ackChan:
			sm.pendingAcks.Delete(msg.ID)
			if ack == nil {
				lastErr = fmt.Errorf("empty ack for message %s", msg.ID)
				continue
			}
			if !ack.Success {
				if ack.Error == "" {
					return fmt.Errorf("ack failed for message %s", msg.ID)
				}
				return fmt.Errorf("ack failed: %s", ack.Error)
			}
			return nil
		case <-time.After(sm.config.AckTimeout):
			sm.pendingAcks.Delete(msg.ID)
			lastErr = fmt.Errorf("ack timeout after %s", sm.config.AckTimeout)
		case <-sm.ctx.Done():
			sm.pendingAcks.Delete(msg.ID)
			return sm.ctx.Err()
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("send with ack failed")
	}
	return lastErr
}

func nextMessageID() string {
	return fmt.Sprintf("sync-%d", time.Now().UnixNano())
}

func (sm *SyncManager) send(msg *panel.SyncMessage) error {
	if msg == nil {
		return nil
	}
	sm.writeMu.Lock()
	defer sm.writeMu.Unlock()
	sm.connMu.RLock()
	conn := sm.conn
	sm.connMu.RUnlock()

	if conn == nil {
		return fmt.Errorf("not connected")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		return err
	}

	atomic.AddInt64(&sm.stats.MessagesSent, 1)
	return nil
}

// handleDisconnect 澶勭悊鏂紑杩炴帴
func (sm *SyncManager) handleDisconnect() {
	sm.connMu.Lock()
	if sm.conn != nil {
		sm.conn.Close()
		sm.conn = nil
	}
	sm.connMu.Unlock()

	if sm.getState() == SyncStateClosed {
		return
	}

	if !sm.compareAndSetState(SyncStateConnected, SyncStateDisconnected) {
		return
	}

	// Reconnect is part of the manager lifetime.
	sm.startReconnect()
}

func (sm *SyncManager) startReconnect() {
	sm.wg.Add(1)
	go func() { defer sm.wg.Done(); sm.reconnectLoop() }()
}

// reconnectLoop 閲嶈繛寰幆
func (sm *SyncManager) reconnectLoop() {
	if !atomic.CompareAndSwapInt32(&sm.reconnecting, 0, 1) {
		return
	}
	defer atomic.StoreInt32(&sm.reconnecting, 0)

	tries := 0

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-time.After(sm.config.ReconnectInterval):
		}

		if sm.getState() == SyncStateClosed {
			return
		}

		tries++
		atomic.AddInt64(&sm.stats.ReconnectCount, 1)

		log.WithField("attempt", tries).Info("Attempting to reconnect...")

		if err := sm.connect(); err != nil {
			log.WithError(err).Warn("Reconnect failed")

			if sm.config.MaxReconnectTries > 0 && tries >= sm.config.MaxReconnectTries {
				log.Error("Max reconnect tries reached")

				if sm.config.EnableFallback {
					log.Info("Switching to fallback mode")
					sm.setState(SyncStateFallback)
					sm.wg.Add(1)
					go sm.runFallbackMode()
				}
				return
			}
			continue
		}

		// 閲嶈繛鎴愬姛
		sm.startWorkers()
		return
	}
}

// runFallbackMode 闄嶇骇鍒拌疆璇㈡ā寮?
func (sm *SyncManager) runFallbackMode() {
	defer sm.wg.Done()

	log.Info("Running in fallback polling mode")

	ticker := time.NewTicker(sm.config.FallbackInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			// 灏濊瘯鍗囩骇鍒?WebSocket
			if err := sm.connect(); err == nil {
				log.Info("Upgraded from fallback to WebSocket mode")
				sm.startWorkers()
				return
			}

			// 缁х画浣跨敤杞
			if sm.config.MaintenanceOnly {
				continue
			}
			if err := sm.controller.nodeInfoMonitor(); err != nil {
				log.WithError(err).Warn("Fallback poll failed")
			}
		}
	}
}

// State management

func (sm *SyncManager) getState() SyncState {
	return SyncState(atomic.LoadInt32(&sm.state))
}

func (sm *SyncManager) setState(s SyncState) {
	atomic.StoreInt32(&sm.state, int32(s))
}

func (sm *SyncManager) compareAndSetState(old, new SyncState) bool {
	return atomic.CompareAndSwapInt32(&sm.state, int32(old), int32(new))
}

// Close 鍏抽棴鍚屾绠＄悊鍣?
func (sm *SyncManager) Close() error {
	sm.setState(SyncStateClosed)
	sm.cancel()

	sm.connMu.Lock()
	if sm.conn != nil {
		sm.conn.Close()
		sm.conn = nil
	}
	sm.connMu.Unlock()

	// 绛夊緟鎵€鏈夊崗绋嬮€€鍑?
	sm.wg.Wait()

	return nil
}

// Stats 鑾峰彇缁熻淇℃伅
func (sm *SyncManager) Stats() *SyncStats {
	sm.maintenanceMu.Lock()
	defer sm.maintenanceMu.Unlock()
	return &SyncStats{
		MessagesReceived: atomic.LoadInt64(&sm.stats.MessagesReceived),
		MessagesSent:     atomic.LoadInt64(&sm.stats.MessagesSent),
		ReconnectCount:   atomic.LoadInt64(&sm.stats.ReconnectCount),
		LastConnectedAt:  sm.stats.LastConnectedAt,
		LastMessageAt:    sm.stats.LastMessageAt,
		CurrentLatency:   sm.stats.CurrentLatency,
	}
}

// IsConnected 鏄惁宸茶繛鎺?
func (sm *SyncManager) IsConnected() bool {
	return sm.getState() == SyncStateConnected
}
