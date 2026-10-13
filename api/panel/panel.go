package panel

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/AnixOps/anix-agent/v5/conf"
	"github.com/go-resty/resty/v2"
)

// Panel is the interface for different panel's api.

type Client struct {
	client           *resty.Client
	APIHost          string
	APISendIP        string
	Token            string
	APIKey           string // 用于自动发现模式
	Secret           string // 用于请求签名
	NodeType         string
	ProtocolType     string
	NodeId           int
	nodeEtag         string
	userEtag         string
	responseBodyHash string
	UserList         *UserListBody
	AliveMap         *AliveMap
	CredStore        *CredentialStore          // 凭证存储 (明文)
	EncCredStore     *EncryptedCredentialStore // 凭证存储 (加密)
	EnableSign       bool                      // 是否启用签名
	EncryptCred      bool                      // 是否加密凭证
	Debugger         *DebugDumper              // 调试工具
}

func New(c *conf.ApiConfig) (*Client, error) {
	var httpClient *resty.Client
	if c.APISendIP != "" {
		httpClient = resty.NewWithLocalAddr(&net.TCPAddr{
			IP: net.ParseIP(c.APISendIP),
		})
	} else {
		httpClient = resty.New()
	}
	httpClient.SetRetryCount(3)
	if c.Timeout > 0 {
		httpClient.SetTimeout(time.Duration(c.Timeout) * time.Second)
	} else {
		httpClient.SetTimeout(5 * time.Second)
	}
	httpClient.OnError(func(req *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			logrus.Error(v.Err)
		}
	})
	httpClient.SetBaseURL(c.APIHost)

	// 安全配置默认值
	enableSign := true
	encryptCred := true
	// 显式设置为 false 时才禁用
	if c.EnableSign == false && c.AutoRegister {
		enableSign = false
	}
	if c.EncryptCredential == false && c.AutoRegister {
		encryptCred = false
	}

	// 初始化凭证存储
	credFile := c.CredentialFile
	if credFile == "" {
		credFile = "data/credential.json"
	}

	var credStore *CredentialStore
	var encCredStore *EncryptedCredentialStore

	if encryptCred {
		// 使用加密存储
		var err error
		encCredStore, err = NewEncryptedCredentialStore(credFile + ".enc")
		if err != nil {
			logrus.WithError(err).Warn("Failed to create encrypted credential store, falling back to plain store")
			encryptCred = false
			credStore = NewCredentialStore(credFile)
		}
	} else {
		credStore = NewCredentialStore(credFile)
	}

	panelClient := &Client{
		client:       httpClient,
		Token:        c.Key,
		APIHost:      c.APIHost,
		APISendIP:    c.APISendIP,
		NodeId:       c.NodeID,
		UserList:     &UserListBody{},
		AliveMap:     &AliveMap{},
		CredStore:    credStore,
		EncCredStore: encCredStore,
		EnableSign:   enableSign,
		EncryptCred:  encryptCred,
	}

	// 初始化调试工具
	if c.EnableDebug {
		debugDir := c.DebugOutputDir
		if debugDir == "" {
			debugDir = "test_data/api_debug"
		}
		panelClient.Debugger = NewDebugDumper(&DebugConfig{
			Enable:    true,
			OutputDir: debugDir,
		})
		logrus.WithField("dir", panelClient.Debugger.GetSessionDir()).Info("API Debug enabled")
	}

	// 如果启用自动注册
	if c.AutoRegister {
		logrus.Info("Auto register mode enabled, checking credentials...")
		logrus.Infof("Security: Sign=%v, EncryptCredential=%v", enableSign, encryptCred)

		// 如果强制重新注册，删除现有凭证
		if c.ForceReRegister {
			logrus.Info("Force re-register: clearing existing credentials...")
			if encryptCred && encCredStore != nil {
				encCredStore.Clear()
			} else if credStore != nil {
				credStore.Clear()
			}
		}

		var cred *Credential
		var err error

		if encryptCred && encCredStore != nil {
			cred, err = panelClient.AutoRegisterEncrypted(
				c.AuthKey,
				c.NodeName,
				c.NodeHost,
				c.NodePort,
				encCredStore,
			)
		} else {
			cred, err = panelClient.AutoRegister(
				c.AuthKey,
				c.NodeName,
				c.NodeHost,
				c.NodePort,
				credStore,
			)
		}

		if err != nil {
			return nil, fmt.Errorf("auto register failed: %w", err)
		}
		logrus.Infof("Node registered/loaded successfully, NodeID: %d", cred.NodeID)

		// 更新凭证用于后续请求
		c.NodeID = cred.NodeID
		c.Key = cred.APIKey
		panelClient.NodeId = cred.NodeID
		panelClient.Token = cred.APIKey
		panelClient.Secret = cred.Secret
	}

	// set params
	httpClient.SetQueryParams(map[string]string{
		"node_id": strconv.Itoa(c.NodeID),
	})
	if panelClient.Token != "" {
		httpClient.SetHeader("X-API-Key", panelClient.Token)
	}

	return panelClient, nil
}
