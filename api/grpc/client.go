package grpc

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "github.com/AnixOps/anix-agent/v4/api/grpc/v2boardpb"
	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/common/monitor"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

// GRPCClientConfig defines gRPC dial and auth settings.
type GRPCClientConfig struct {
	Host          string
	APIHost       string
	NodeID        int
	APIKey        string
	Secret        string
	KeepaliveTime time.Duration
	UseTLS        bool
	ServerName    string
	EnableSign    bool
	SupportsSync  bool
	// Lazy connects on first use instead of at construction: a
	// credential-only node (no ApiKey) does not use the legacy services,
	// and must start while Control is still unreachable.
	Lazy bool
}

// GRPCClient is a gRPC transport implementation for panel communication.
type GRPCClient struct {
	conn          *grpc.ClientConn
	nodeClient    pb.NodeServiceClient
	nodeLogClient NodeLogServiceClient
	userClient    pb.UserServiceClient
	trafficClient pb.TrafficServiceClient
	healthClient  pb.HealthServiceClient

	nodeID       int
	apiKey       string
	secret       string
	apiHost      string
	nodeType     string
	enableSign   bool
	supportsSync bool

	statusStream  pb.NodeService_StatusStreamClient
	userStream    pb.UserService_UserChangesClient
	trafficStream pb.TrafficService_TrafficStreamClient
	onlineStream  pb.TrafficService_OnlineStreamClient

	onConfigUpdate func(*pb.NodeConfigResponse)
	onUserUpdate   func(*pb.StatusResponse)

	configMu          sync.Mutex
	nodeConfigHash    [sha256.Size]byte
	hasNodeConfigHash bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.RWMutex
}

// NewGRPCClient creates a gRPC client.
func NewGRPCClient(cfg *GRPCClientConfig) (*GRPCClient, error) {
	if cfg == nil {
		return nil, fmt.Errorf("grpc config is nil")
	}
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, fmt.Errorf("grpc host is empty")
	}

	ctx, cancel := context.WithCancel(context.Background())

	ka := keepalive.ClientParameters{
		Time:                30 * time.Second,
		Timeout:             10 * time.Second,
		PermitWithoutStream: true,
	}
	if cfg.KeepaliveTime > 0 {
		ka.Time = cfg.KeepaliveTime
	}

	dialOpts := []grpc.DialOption{
		grpc.WithKeepaliveParams(ka),
	}
	if !cfg.Lazy {
		dialOpts = append(dialOpts, grpc.WithBlock())
	}

	if cfg.UseTLS {
		tlsCfg := &tls.Config{}
		if cfg.ServerName != "" {
			tlsCfg.ServerName = cfg.ServerName
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()

	conn, err := grpc.DialContext(dialCtx, cfg.Host, dialOpts...)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("dial grpc: %w", err)
	}

	client := &GRPCClient{
		conn:          conn,
		nodeClient:    pb.NewNodeServiceClient(conn),
		nodeLogClient: NewNodeLogServiceClient(conn),
		userClient:    pb.NewUserServiceClient(conn),
		trafficClient: pb.NewTrafficServiceClient(conn),
		healthClient:  pb.NewHealthServiceClient(conn),
		nodeID:        cfg.NodeID,
		apiKey:        cfg.APIKey,
		secret:        cfg.Secret,
		apiHost:       cfg.APIHost,
		enableSign:    cfg.EnableSign,
		supportsSync:  cfg.SupportsSync,
		ctx:           ctx,
		cancel:        cancel,
	}

	if client.apiHost == "" {
		client.apiHost = cfg.Host
	}

	return client, nil
}

func (c *GRPCClient) withAuth(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	pairs := []string{"x-node-id", strconv.Itoa(c.nodeID)}
	if c.apiKey != "" {
		pairs = append(pairs, "x-api-key", c.apiKey)
	}
	if c.nodeType != "" {
		pairs = append(pairs, "x-node-type", c.nodeType)
	}
	return metadata.AppendToOutgoingContext(ctx, pairs...)
}

func normalizeNodeType(nodeType, fallback string) string {
	t := strings.ToLower(strings.TrimSpace(nodeType))
	if t == "" {
		t = strings.ToLower(strings.TrimSpace(fallback))
	}
	if t == "v2ray" {
		t = "vmess"
	}
	return t
}

func durationOrDefault(seconds int32, fallback int32) time.Duration {
	if seconds <= 0 {
		seconds = fallback
	}
	return time.Duration(seconds) * time.Second
}

func mapToRawJSONStringMap(m map[string]string) json.RawMessage {
	if len(m) == 0 {
		return nil
	}
	b, _ := json.Marshal(m)
	return b
}

func parseIntDefault(value string, fallback int) int {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return n
}

func parseStringList(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	var out []string
	if strings.HasPrefix(value, "[") {
		if err := json.Unmarshal([]byte(value), &out); err == nil {
			return compactStringList(out)
		}
	}
	return compactStringList(strings.Split(value, ","))
}

func compactStringList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func parseWireGuardRelay(value string) panel.WireGuardRelay {
	var relay panel.WireGuardRelay
	if strings.TrimSpace(value) == "" {
		return relay
	}
	_ = json.Unmarshal([]byte(value), &relay)
	return relay
}

func nodeConfigFingerprint(resp *pb.NodeConfigResponse) ([sha256.Size]byte, error) {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(resp)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("marshal node config: %w", err)
	}
	return sha256.Sum256(encoded), nil
}

func firstExtraValue(extra map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := extra[key]; value != "" {
			return value
		}
	}
	return ""
}

func parseRules(routes []*pb.Route) (rules panel.Rules, parsed []panel.Route) {
	parsed = make([]panel.Route, 0, len(routes))
	for i, r := range routes {
		if r == nil {
			continue
		}
		parsed = append(parsed, panel.Route{
			Id:     i,
			Match:  r.GetMatch(),
			Action: r.GetAction(),
		})

		if strings.ToLower(r.GetAction()) != "block" {
			continue
		}
		items := strings.Split(r.GetMatch(), ",")
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if strings.HasPrefix(item, "protocol:") {
				rules.Protocol = append(rules.Protocol, strings.TrimPrefix(item, "protocol:"))
				continue
			}
			rules.Regexp = append(rules.Regexp, strings.TrimPrefix(item, "regexp:"))
		}
	}
	return rules, parsed
}

// Close releases all resources.
func (c *GRPCClient) Close() error {
	c.cancel()
	c.wg.Wait()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Register registers node by auth key and returns credentials.
func (c *GRPCClient) Register(authKey, name, host string, port int32, serverVersion, serverOS string) (*panel.Credential, error) {
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()

	resp, err := c.nodeClient.Register(ctx, &pb.NodeRegisterRequest{
		AuthKey:            authKey,
		Name:               name,
		Host:               host,
		Port:               port,
		ServerVersion:      serverVersion,
		ServerOs:           serverOS,
		SupportedProtocols: []string{"vmess", "vless", "trojan", "shadowsocks", "hysteria", "hysteria2", "tuic", "anytls", "wireguard"},
	})
	if err != nil {
		return nil, fmt.Errorf("grpc register: %w", err)
	}

	return &panel.Credential{
		NodeID: int(resp.GetNodeId()),
		APIKey: resp.GetApiKey(),
		Secret: resp.GetSecret(),
	}, nil
}

// GetNodeConfig pulls node configuration from panel over gRPC.
func (c *GRPCClient) GetNodeConfig() (*panel.NodeInfo, error) {
	c.configMu.Lock()
	defer c.configMu.Unlock()

	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()

	resp, err := c.nodeClient.GetConfig(c.withAuth(ctx), &pb.NodeConfigRequest{NodeId: uint32(c.nodeID)})
	if err != nil {
		return nil, fmt.Errorf("grpc get config: %w", err)
	}
	if resp == nil {
		return nil, fmt.Errorf("grpc get config: nil response")
	}
	fingerprint, err := nodeConfigFingerprint(resp)
	if err != nil {
		return nil, fmt.Errorf("grpc get config fingerprint: %w", err)
	}

	nodeType := normalizeNodeType(resp.GetType(), resp.GetNodeType())
	if nodeType == "" {
		return nil, fmt.Errorf("grpc get config: empty node type")
	}
	c.nodeType = normalizeNodeType(resp.GetNodeType(), nodeType)

	rules, routes := parseRules(resp.GetRoutes())
	baseCfg := resp.GetBaseConfig()
	pushInterval := int32(60)
	pullInterval := int32(60)
	if baseCfg != nil {
		pushInterval = baseCfg.GetPushInterval()
		pullInterval = baseCfg.GetPullInterval()
	}

	common := panel.CommonNode{
		Host:       resp.GetHost(),
		ServerPort: int(resp.GetServerPort()),
		ServerName: resp.GetServerName(),
		Routes:     routes,
		BaseConfig: &panel.BaseConfig{PushInterval: int(pushInterval), PullInterval: int(pullInterval)},
	}

	node := &panel.NodeInfo{
		Id:           c.nodeID,
		Type:         nodeType,
		PushInterval: durationOrDefault(pushInterval, 60),
		PullInterval: durationOrDefault(pullInterval, 60),
		Rules:        rules,
		RawDNS:       panel.RawDNS{DNSMap: map[string]map[string]interface{}{}, DNSJson: []byte{}},
		Common:       &common,
	}

	tlsMode := int(resp.GetTls())
	switch tlsMode {
	case panel.Reality:
		node.Security = panel.Reality
	case panel.Tls:
		node.Security = panel.Tls
	default:
		node.Security = panel.None
	}

	switch nodeType {
	case "vmess", "vless":
		v := &panel.VAllssNode{
			CommonNode:      common,
			Tls:             tlsMode,
			Network:         resp.GetNetwork(),
			NetworkSettings: mapToRawJSONStringMap(resp.GetNetworkSettings()),
			Flow:            resp.GetFlow(),
			ServerName:      resp.GetServerName(),
		}
		tlsSettings := resp.GetTlsSettings()
		if len(tlsSettings) > 0 {
			v.TlsSettings = panel.TlsSettings{
				ServerName:  tlsSettings["server_name"],
				Dest:        tlsSettings["dest"],
				ServerPort:  tlsSettings["server_port"],
				ShortId:     tlsSettings["short_id"],
				PrivateKey:  tlsSettings["private_key"],
				Mldsa65Seed: tlsSettings["mldsa65Seed"],
			}
			if xver, err := strconv.ParseUint(tlsSettings["xver"], 10, 64); err == nil {
				v.TlsSettings.Xver = xver
			}
		}
		node.VAllss = v

	case "shadowsocks":
		node.Shadowsocks = &panel.ShadowsocksNode{
			CommonNode: common,
			Cipher:     resp.GetCipher(),
			ServerKey:  resp.GetServerKey(),
		}
		node.Security = panel.None

	case "trojan":
		node.Trojan = &panel.TrojanNode{
			CommonNode:      common,
			Network:         resp.GetNetwork(),
			NetworkSettings: mapToRawJSONStringMap(resp.GetNetworkSettings()),
		}
		node.Security = panel.Tls

	case "tuic":
		node.Tuic = &panel.TuicNode{CommonNode: common}
		node.Security = panel.Tls

	case "anytls":
		node.AnyTls = &panel.AnyTlsNode{CommonNode: common}
		node.Security = panel.Tls

	case "hysteria":
		node.Hysteria = &panel.HysteriaNode{CommonNode: common}
		node.Security = panel.Tls

	case "hysteria2":
		node.Hysteria2 = &panel.Hysteria2Node{CommonNode: common}
		node.Security = panel.Tls

	case "wireguard":
		extra := resp.GetExtra()
		node.WireGuard = &panel.WireGuardNode{
			CommonNode:       common,
			CIDR:             extra["cidr"],
			ServerAddress:    extra["server_address"],
			ServerPrivateKey: extra["server_private_key"],
			ServerPublicKey:  extra["server_public_key"],
			MTU:              parseIntDefault(extra["mtu"], 1280),
			DNS:              parseStringList(extra["dns"]),
			AllowedIPs:       parseStringList(extra["allowed_ips"]),
			TunnelType:       extra["tunnel_type"],
			Relay:            parseWireGuardRelay(extra["relay"]),
		}
		node.Security = panel.None
	}

	if c.hasNodeConfigHash && c.nodeConfigHash == fingerprint {
		return nil, nil
	}
	c.nodeConfigHash = fingerprint
	c.hasNodeConfigHash = true

	return node, nil
}

// GetUsers fetches users from panel over gRPC.
func (c *GRPCClient) GetUsers() ([]panel.UserInfo, error) {
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()

	resp, err := c.userClient.GetUsers(c.withAuth(ctx), &pb.UserListRequest{NodeId: uint32(c.nodeID)})
	if err != nil {
		return nil, fmt.Errorf("grpc get users: %w", err)
	}
	if resp == nil {
		return nil, fmt.Errorf("grpc get users: nil response")
	}

	users := make([]panel.UserInfo, 0, len(resp.GetUsers()))
	for _, u := range resp.GetUsers() {
		if u == nil {
			continue
		}
		users = append(users, panel.UserInfo{
			Id:                    int(u.GetId()),
			Uuid:                  u.GetUuid(),
			SpeedLimit:            int(u.GetSpeedLimit()),
			DeviceLimit:           int(u.GetDeviceLimit()),
			WireGuardPeerIP:       u.GetExtra()["wireguard_peer_ip"],
			WireGuardPublicKey:    firstExtraValue(u.GetExtra(), "wireguard_public_key", "wireguard_peer_public_key"),
			WireGuardPresharedKey: u.GetExtra()["wireguard_preshared_key"],
			Extra:                 u.GetExtra(),
		})
	}
	return users, nil
}

// ReportTraffic reports user traffic over gRPC.
func (c *GRPCClient) ReportTraffic(traffics []panel.UserTraffic) error {
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()

	trafficMap := make(map[uint32]*pb.TrafficData, len(traffics))
	for _, t := range traffics {
		trafficMap[uint32(t.UID)] = &pb.TrafficData{Upload: t.Upload, Download: t.Download}
	}

	_, err := c.trafficClient.ReportTraffic(c.withAuth(ctx), &pb.TrafficReportRequest{NodeId: uint32(c.nodeID), Traffics: trafficMap})
	if err != nil {
		return fmt.Errorf("grpc report traffic: %w", err)
	}
	return nil
}

// ReportOnline reports online user IP data over gRPC.
func (c *GRPCClient) ReportOnline(onlineUsers map[int][]string) error {
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()

	onlineMap := make(map[uint32]*pb.OnlineData, len(onlineUsers))
	now := time.Now().Unix()
	for uid, ips := range onlineUsers {
		onlineMap[uint32(uid)] = &pb.OnlineData{Ips: ips, Timestamp: now}
	}

	_, err := c.trafficClient.ReportOnline(c.withAuth(ctx), &pb.OnlineReportRequest{NodeId: uint32(c.nodeID), Online: onlineMap})
	if err != nil {
		return fmt.Errorf("grpc report online: %w", err)
	}
	return nil
}

// ReportStatus reports node metrics over gRPC.
func (c *GRPCClient) ReportStatus(stats *monitor.SystemInfo, onlineUsers int, upload, download int64) error {
	if stats == nil {
		stats = &monitor.SystemInfo{}
	}

	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()

	_, err := c.nodeClient.ReportStatus(c.withAuth(ctx), &pb.NodeStatusRequest{
		NodeId:      uint32(c.nodeID),
		CpuUsage:    stats.CPUUsage,
		MemoryUsage: stats.MemoryUsage,
		DiskUsage:   stats.DiskUsage,
		Uptime:      stats.Uptime,
		OnlineUsers: int32(onlineUsers),
		Upload:      upload,
		Download:    download,
	})
	if err != nil {
		return fmt.Errorf("grpc report status: %w", err)
	}
	return nil
}

func (c *GRPCClient) ReportNodeLogs(entries []panel.NodeLogEntry) error {
	if len(entries) == 0 {
		return nil
	}

	req, err := newNodeLogBatchMessage(c.nodeID, entries)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()

	if _, err := c.nodeLogClient.ReportLogs(c.withAuth(ctx), req); err != nil {
		return fmt.Errorf("grpc report node logs: %w", err)
	}
	return nil
}

// ReportNodeRuntimeHealth uses the existing node-log RPC so REST and gRPC
// transports expose the same runtime-health signal without a proto breaking
// change to the legacy heartbeat message.
func (c *GRPCClient) ReportNodeRuntimeHealth(healthy bool, message string) error {
	fields, err := json.Marshal(map[string]any{
		"runtime_healthy": healthy,
		"runtime_error":   message,
	})
	if err != nil {
		return fmt.Errorf("encode runtime health: %w", err)
	}
	level := "info"
	if !healthy {
		level = "error"
	}
	return c.ReportNodeLogs([]panel.NodeLogEntry{{
		Level:      level,
		Source:     "wireguard",
		Message:    "wireguard runtime health updated",
		Timestamp:  time.Now(),
		FieldsJSON: string(fields),
	}})
}

// StartStreams starts optional bidirectional streams.
func (c *GRPCClient) StartStreams() error {
	ctx := c.withAuth(c.ctx)

	statusStream, err := c.nodeClient.StatusStream(ctx)
	if err != nil {
		return fmt.Errorf("grpc status stream: %w", err)
	}
	userStream, err := c.userClient.UserChanges(ctx)
	if err != nil {
		return fmt.Errorf("grpc user stream: %w", err)
	}
	trafficStream, err := c.trafficClient.TrafficStream(ctx)
	if err != nil {
		return fmt.Errorf("grpc traffic stream: %w", err)
	}
	onlineStream, err := c.trafficClient.OnlineStream(ctx)
	if err != nil {
		return fmt.Errorf("grpc online stream: %w", err)
	}

	c.mu.Lock()
	c.statusStream = statusStream
	c.userStream = userStream
	c.trafficStream = trafficStream
	c.onlineStream = onlineStream
	c.mu.Unlock()

	c.wg.Add(2)
	go c.receiveConfigUpdates()
	go c.receiveUserChanges()

	log.WithField("node_id", c.nodeID).Info("gRPC streams started")
	return nil
}

func (c *GRPCClient) receiveConfigUpdates() {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		c.mu.RLock()
		stream := c.statusStream
		cb := c.onConfigUpdate
		c.mu.RUnlock()
		if stream == nil {
			time.Sleep(time.Second)
			continue
		}

		msg, err := stream.Recv()
		if err != nil {
			log.WithError(err).Warn("grpc status stream recv failed")
			time.Sleep(2 * time.Second)
			continue
		}
		if cb != nil {
			cb(msg)
		}
	}
}

func (c *GRPCClient) receiveUserChanges() {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		c.mu.RLock()
		stream := c.userStream
		cb := c.onUserUpdate
		c.mu.RUnlock()
		if stream == nil {
			time.Sleep(time.Second)
			continue
		}

		msg, err := stream.Recv()
		if err != nil {
			log.WithError(err).Warn("grpc user stream recv failed")
			time.Sleep(2 * time.Second)
			continue
		}
		if cb != nil {
			cb(msg)
		}
	}
}

func (c *GRPCClient) SetOnConfigUpdate(callback func(*pb.NodeConfigResponse)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onConfigUpdate = callback
}

func (c *GRPCClient) SetOnUserUpdate(callback func(*pb.StatusResponse)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onUserUpdate = callback
}

func (c *GRPCClient) SendStatus(stats *monitor.SystemInfo, onlineUsers int, upload, download int64) error {
	c.mu.RLock()
	stream := c.statusStream
	c.mu.RUnlock()
	if stream == nil {
		return fmt.Errorf("status stream not initialized")
	}

	return stream.Send(&pb.NodeStatusRequest{
		NodeId:      uint32(c.nodeID),
		CpuUsage:    stats.CPUUsage,
		MemoryUsage: stats.MemoryUsage,
		DiskUsage:   stats.DiskUsage,
		Uptime:      stats.Uptime,
		OnlineUsers: int32(onlineUsers),
		Upload:      upload,
		Download:    download,
	})
}

func (c *GRPCClient) SendTrafficThroughStream(traffics []panel.UserTraffic) error {
	c.mu.RLock()
	stream := c.trafficStream
	c.mu.RUnlock()
	if stream == nil {
		return fmt.Errorf("traffic stream not initialized")
	}

	trafficMap := make(map[uint32]*pb.TrafficData, len(traffics))
	for _, t := range traffics {
		trafficMap[uint32(t.UID)] = &pb.TrafficData{Upload: t.Upload, Download: t.Download}
	}

	return stream.Send(&pb.TrafficReportRequest{NodeId: uint32(c.nodeID), Traffics: trafficMap})
}

func (c *GRPCClient) SendOnlineThroughStream(onlineUsers map[int][]string) error {
	c.mu.RLock()
	stream := c.onlineStream
	c.mu.RUnlock()
	if stream == nil {
		return fmt.Errorf("online stream not initialized")
	}

	onlineMap := make(map[uint32]*pb.OnlineData, len(onlineUsers))
	now := time.Now().Unix()
	for uid, ips := range onlineUsers {
		onlineMap[uint32(uid)] = &pb.OnlineData{Ips: ips, Timestamp: now}
	}

	return stream.Send(&pb.OnlineReportRequest{NodeId: uint32(c.nodeID), Online: onlineMap})
}

func (c *GRPCClient) HealthCheck() error {
	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer cancel()

	resp, err := c.healthClient.Check(c.withAuth(ctx), &pb.HealthCheckRequest{NodeId: uint32(c.nodeID)})
	if err != nil {
		return err
	}
	if resp.GetStatus() != pb.HealthCheckResponse_SERVING {
		return fmt.Errorf("service not serving: %v", resp.GetStatus())
	}
	return nil
}

func (c *GRPCClient) IsConnected() bool {
	return c.conn != nil && c.conn.GetState() == connectivity.Ready
}

// NodeAPI adapter methods

func (c *GRPCClient) GetNodeInfo() (*panel.NodeInfo, error) {
	return c.GetNodeConfig()
}

func (c *GRPCClient) GetUserList() ([]panel.UserInfo, error) {
	return c.GetUsers()
}

func (c *GRPCClient) GetUserAlive() (map[int]int, error) {
	// Current gRPC contract does not provide alive-list query endpoint.
	return map[int]int{}, nil
}

func (c *GRPCClient) ReportUserTraffic(traffics []panel.UserTraffic) error {
	return c.ReportTraffic(traffics)
}

func (c *GRPCClient) ReportNodeOnlineUsers(data *map[int][]string) error {
	if data == nil {
		return nil
	}
	return c.ReportOnline(*data)
}

func (c *GRPCClient) ReportNodeStatus(stats *monitor.SystemInfo, onlineUsers int, upload, download int64) error {
	return c.ReportStatus(stats, onlineUsers, upload, download)
}

func (c *GRPCClient) GetNodeID() int { return c.nodeID }

func (c *GRPCClient) GetAPIHost() string { return c.apiHost }

func (c *GRPCClient) GetAPIKey() string { return c.apiKey }

func (c *GRPCClient) GetSecret() string { return c.secret }

func (c *GRPCClient) IsSignEnabled() bool { return c.enableSign }

func (c *GRPCClient) SetNodeType(nodeType string) { c.nodeType = normalizeNodeType(nodeType, "") }

func (c *GRPCClient) SupportsSync() bool { return c.supportsSync }

func (c *GRPCClient) setCredential(cred *panel.Credential) {
	if cred == nil {
		return
	}
	c.nodeID = cred.NodeID
	c.apiKey = cred.APIKey
	c.secret = cred.Secret
}
