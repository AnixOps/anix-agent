package panel

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/AnixOps/anix-agent/v4/common/monitor"
	"github.com/AnixOps/anix-agent/v4/common/sign"
	"github.com/AnixOps/anix-agent/v4/common/utils"
	"github.com/go-resty/resty/v2"
	"github.com/sirupsen/logrus"
)

// 确保 utils 被使用
var _ = utils.Redact

var Version = "4.2.0-rc.4"

// ========== 请求/响应结构 ==========

// RegisterRequest 注册请求
type RegisterRequest struct {
	AuthKey       string `json:"auth_key"`
	Name          string `json:"name,omitempty"`
	Host          string `json:"host,omitempty"`
	Port          int    `json:"port,omitempty"`
	ServerVersion string `json:"server_version,omitempty"`
	ServerOS      string `json:"server_os,omitempty"`
}

// RegisterResponse 注册响应
type RegisterResponse struct {
	Message string               `json:"message"`
	Data    RegisterResponseData `json:"data"`
}

// RegisterResponseData 注册响应数据
type RegisterResponseData struct {
	NodeID  int    `json:"node_id"`
	APIKey  string `json:"api_key"`
	Secret  string `json:"secret"`
	Message string `json:"message"`
}

// HeartbeatRequest 心跳请求
type HeartbeatRequest struct {
	CPUUsage    float64 `json:"cpu_usage"`
	MemoryUsage float64 `json:"memory_usage"`
	DiskUsage   float64 `json:"disk_usage"`
	Uptime      int64   `json:"uptime"`
	OnlineUsers int     `json:"online_users"`
	Upload      int64   `json:"upload"`
	Download    int64   `json:"download"`
}

// HeartbeatResponse 心跳响应
type HeartbeatResponse struct {
	Message string `json:"message"`
}

type RuntimeHealthRequest struct {
	Healthy bool   `json:"healthy"`
	Error   string `json:"error,omitempty"`
}

// ========== API 方法 ==========

// Register 节点注册
func (c *Client) Register(req *RegisterRequest) (*RegisterResponse, error) {
	var result RegisterResponse

	resp, err := c.client.R().
		SetBody(req).
		SetResult(&result).
		Post("/api/v2/node/register")

	if err != nil {
		return nil, fmt.Errorf("send register request: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("register failed: %s (status: %d)", result.Message, resp.StatusCode())
	}

	return &result, nil
}

// Heartbeat 发送心跳
func (c *Client) Heartbeat(req *HeartbeatRequest) error {
	if c.APIKey == "" {
		return fmt.Errorf("api key not set")
	}

	var result HeartbeatResponse

	r := c.client.R().
		SetHeader("X-API-Key", c.APIKey).
		SetBody(req).
		SetResult(&result)

	// 如果启用签名且有 secret
	if c.EnableSign && c.Secret != "" {
		c.addSignatureToRequest(r, "POST", "/api/v2/node/heartbeat", req)
	}

	resp, err := r.Post("/api/v2/node/heartbeat")

	if err != nil {
		return fmt.Errorf("send heartbeat request: %w", err)
	}

	if resp.StatusCode() == http.StatusUnauthorized {
		return fmt.Errorf("unauthorized: api key invalid or expired")
	}

	if resp.StatusCode() == http.StatusBadRequest {
		// 可能是签名错误
		logrus.WithField("response", string(resp.Body())).Debug("Heartbeat bad request")
		return fmt.Errorf("heartbeat failed: %s", result.Message)
	}

	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("heartbeat failed: %s (status: %d)", result.Message, resp.StatusCode())
	}

	return nil
}

func (c *Client) reportRuntimeHealth(req *RuntimeHealthRequest) error {
	if c.APIKey == "" {
		return fmt.Errorf("api key not set")
	}

	var result HeartbeatResponse
	r := c.client.R().
		SetHeader("X-API-Key", c.APIKey).
		SetBody(req).
		SetResult(&result)
	if c.EnableSign && c.Secret != "" {
		c.addSignatureToRequest(r, "POST", "/api/v2/node/runtime-health", req)
	}
	resp, err := r.Post("/api/v2/node/runtime-health")
	if err != nil {
		return fmt.Errorf("send runtime health: %w", err)
	}
	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("runtime health failed: %s (status: %d)", result.Message, resp.StatusCode())
	}
	return nil
}

// addSignatureToRequest 添加签名相关 Header 到 resty 请求
func (c *Client) addSignatureToRequest(r *resty.Request, method, path string, body interface{}) {
	if c.Secret == "" {
		return
	}

	signer := sign.NewSigner(c.Secret)

	// 序列化 body
	var bodyBytes []byte
	if body != nil {
		bodyBytes, _ = json.Marshal(body)
	}

	signData := signer.Sign(method, path, bodyBytes)

	r.SetHeader("X-Timestamp", signData.Timestamp)
	r.SetHeader("X-Nonce", signData.Nonce)
	r.SetHeader("X-Signature", signData.Signature)
}

// AutoRegister 自动注册节点 (明文凭证存储)
func (c *Client) AutoRegister(authKey, name, host string, port int, credStore *CredentialStore) (*Credential, error) {
	// 检查是否已有凭证
	cred, err := credStore.Load()
	if err != nil {
		return nil, fmt.Errorf("load credential: %w", err)
	}

	// 如果已有凭证，直接使用
	if cred != nil {
		c.NodeId = cred.NodeID
		c.APIKey = cred.APIKey
		c.Secret = cred.Secret // 设置 secret 用于签名
		logrus.Infof("Loaded credential: NodeID=%d, APIKey=%s", cred.NodeID, utils.Redact(cred.APIKey))
		return cred, nil
	}

	// 没有凭证，需要注册
	if authKey == "" {
		return nil, fmt.Errorf("auth key not configured for registration")
	}

	logrus.Infof("No credential found, registering with auth key: %s", utils.Redact(authKey))

	// 获取系统信息
	sysInfo, _ := monitor.GetSystemInfo()
	hostname := monitor.GetHostname()

	// 构建注册请求
	req := &RegisterRequest{
		AuthKey:       authKey,
		Name:          name,
		Host:          host,
		Port:          port,
		ServerVersion: Version,
		ServerOS:      sysInfo.OS,
	}

	// 如果没有配置名称，使用主机名
	if req.Name == "" {
		req.Name = hostname
	}

	// 发送注册请求
	resp, err := c.Register(req)
	if err != nil {
		return nil, fmt.Errorf("register failed: %w", err)
	}

	// 保存凭证
	cred = &Credential{
		NodeID: resp.Data.NodeID,
		APIKey: resp.Data.APIKey,
		Secret: resp.Data.Secret,
	}

	if err := credStore.Save(cred); err != nil {
		return nil, fmt.Errorf("save credential: %w", err)
	}

	// 更新客户端信息
	c.NodeId = cred.NodeID
	c.APIKey = cred.APIKey
	c.Secret = cred.Secret

	logrus.Infof("Registration successful: NodeID=%d", cred.NodeID)
	return cred, nil
}

// AutoRegisterEncrypted 自动注册节点 (加密凭证存储)
func (c *Client) AutoRegisterEncrypted(authKey, name, host string, port int, credStore *EncryptedCredentialStore) (*Credential, error) {
	// 检查是否已有凭证
	cred, err := credStore.Load()
	if err != nil {
		return nil, fmt.Errorf("load credential: %w", err)
	}

	// 如果已有凭证，直接使用
	if cred != nil {
		c.NodeId = cred.NodeID
		c.APIKey = cred.APIKey
		c.Secret = cred.Secret
		logrus.Infof("Loaded encrypted credential: NodeID=%d, APIKey=%s", cred.NodeID, utils.Redact(cred.APIKey))
		return cred, nil
	}

	// 没有凭证，需要注册
	if authKey == "" {
		return nil, fmt.Errorf("auth key not configured for registration")
	}

	logrus.Infof("No credential found, registering with auth key: %s", utils.Redact(authKey))

	// 获取系统信息
	sysInfo, _ := monitor.GetSystemInfo()
	hostname := monitor.GetHostname()

	// 构建注册请求
	req := &RegisterRequest{
		AuthKey:       authKey,
		Name:          name,
		Host:          host,
		Port:          port,
		ServerVersion: Version,
		ServerOS:      sysInfo.OS,
	}

	// 如果没有配置名称，使用主机名
	if req.Name == "" {
		req.Name = hostname
	}

	// 发送注册请求
	resp, err := c.Register(req)
	if err != nil {
		return nil, fmt.Errorf("register failed: %w", err)
	}

	// 保存凭证 (加密)
	cred = &Credential{
		NodeID: resp.Data.NodeID,
		APIKey: resp.Data.APIKey,
		Secret: resp.Data.Secret,
	}

	if err := credStore.Save(cred); err != nil {
		return nil, fmt.Errorf("save encrypted credential: %w", err)
	}

	// 更新客户端信息
	c.NodeId = cred.NodeID
	c.APIKey = cred.APIKey
	c.Secret = cred.Secret

	logrus.Infof("Registration successful (encrypted): NodeID=%d", cred.NodeID)
	return cred, nil
}

// SendHeartbeatWithSystemInfo 发送包含系统信息的心跳
func (c *Client) SendHeartbeatWithSystemInfo(onlineUsers int, upload, download int64) error {
	sysInfo, err := monitor.GetSystemInfo()
	if err != nil {
		return fmt.Errorf("get system info: %w", err)
	}

	req := &HeartbeatRequest{
		CPUUsage:    sysInfo.CPUUsage,
		MemoryUsage: sysInfo.MemoryUsage,
		DiskUsage:   sysInfo.DiskUsage,
		Uptime:      sysInfo.Uptime,
		OnlineUsers: onlineUsers,
		Upload:      upload,
		Download:    download,
	}

	return c.Heartbeat(req)
}
