package grpc

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/common/monitor"
	"github.com/AnixOps/anix-agent/v4/common/utils"
	"github.com/AnixOps/anix-agent/v4/conf"
	"github.com/sirupsen/logrus"
)

func resolveGRPCTarget(cfg *conf.ApiConfig) (target string, useTLS bool, serverName string, err error) {
	target = strings.TrimSpace(cfg.GRPCHost)
	rawHost := strings.TrimSpace(cfg.APIHost)

	if target == "" {
		switch {
		case strings.HasPrefix(rawHost, "grpc://"):
			target = strings.TrimPrefix(rawHost, "grpc://")
		case strings.HasPrefix(rawHost, "grpcs://"):
			target = strings.TrimPrefix(rawHost, "grpcs://")
			useTLS = true
		default:
			u, parseErr := url.Parse(rawHost)
			if parseErr == nil && u.Host != "" {
				target = u.Host
				if strings.EqualFold(u.Scheme, "https") {
					useTLS = true
				}
				serverName = u.Hostname()
			} else {
				target = rawHost
			}
		}
	}

	if target == "" {
		return "", false, "", fmt.Errorf("grpc target is empty")
	}
	if !strings.Contains(target, ":") {
		if useTLS {
			target += ":443"
		} else {
			target += ":80"
		}
	}
	if cfg.GRPCUseTLS {
		useTLS = true
	}
	if cfg.GRPCServerName != "" {
		serverName = cfg.GRPCServerName
	}
	if serverName == "" {
		hostPart := target
		if h, _, splitErr := strings.Cut(target, ":"); splitErr {
			hostPart = h
		}
		serverName = hostPart
	}
	return target, useTLS, serverName, nil
}

func loadOrRegisterCredential(client *GRPCClient, cfg *conf.ApiConfig, encryptCred bool) (*panel.Credential, error) {
	credFile := cfg.CredentialFile
	if credFile == "" {
		credFile = "data/credential.json"
	}

	if encryptCred {
		store, err := panel.NewEncryptedCredentialStore(credFile + ".enc")
		if err != nil {
			return nil, fmt.Errorf("create encrypted credential store: %w", err)
		}
		if cfg.ForceReRegister {
			store.Clear()
		}
		cred, err := store.Load()
		if err != nil {
			return nil, fmt.Errorf("load encrypted credential: %w", err)
		}
		if cred != nil {
			return cred, nil
		}
		cred, err = registerByAuthKey(client, cfg)
		if err != nil {
			return nil, err
		}
		if err := store.Save(cred); err != nil {
			return nil, fmt.Errorf("save encrypted credential: %w", err)
		}
		return cred, nil
	}

	store := panel.NewCredentialStore(credFile)
	if cfg.ForceReRegister {
		store.Clear()
	}
	cred, err := store.Load()
	if err != nil {
		return nil, fmt.Errorf("load credential: %w", err)
	}
	if cred != nil {
		return cred, nil
	}
	cred, err = registerByAuthKey(client, cfg)
	if err != nil {
		return nil, err
	}
	if err := store.Save(cred); err != nil {
		return nil, fmt.Errorf("save credential: %w", err)
	}
	return cred, nil
}

func registerByAuthKey(client *GRPCClient, cfg *conf.ApiConfig) (*panel.Credential, error) {
	if cfg.AuthKey == "" {
		return nil, fmt.Errorf("auth key not configured for grpc registration")
	}

	sysInfo, _ := monitor.GetSystemInfo()
	hostname := monitor.GetHostname()

	name := cfg.NodeName
	if name == "" {
		name = hostname
	}
	port := cfg.NodePort
	if port <= 0 {
		port = 443
	}

	cred, err := client.Register(
		cfg.AuthKey,
		name,
		cfg.NodeHost,
		int32(port),
		panel.Version,
		sysInfo.OS,
	)
	if err != nil {
		return nil, fmt.Errorf("grpc register failed: %w", err)
	}
	return cred, nil
}

// NewFromAPIConfig creates a GRPCClient from common node ApiConfig.
func NewFromAPIConfig(cfg *conf.ApiConfig) (*GRPCClient, error) {
	target, useTLS, serverName, err := resolveGRPCTarget(cfg)
	if err != nil {
		return nil, err
	}

	enableSign := true
	if cfg.EnableSign == false && cfg.AutoRegister {
		enableSign = false
	}
	encryptCred := true
	if cfg.EncryptCredential == false && cfg.AutoRegister {
		encryptCred = false
	}

	client, err := NewGRPCClient(&GRPCClientConfig{
		Host:          target,
		APIHost:       cfg.APIHost,
		NodeID:        cfg.NodeID,
		APIKey:        cfg.Key,
		Secret:        "",
		KeepaliveTime: time.Duration(cfg.GRPCKeepalive) * time.Second,
		UseTLS:        useTLS,
		ServerName:    serverName,
		EnableSign:    enableSign,
		SupportsSync:  false,
		Lazy:          cfg.KeyLess(),
	})
	if err != nil {
		return nil, err
	}

	if cfg.AutoRegister {
		cred, loadErr := loadOrRegisterCredential(client, cfg, encryptCred)
		if loadErr != nil {
			client.Close()
			return nil, loadErr
		}
		client.setCredential(cred)

		cfg.NodeID = cred.NodeID
		cfg.Key = cred.APIKey

		safeAPIKey := utils.Redact(cred.APIKey)
		safeSecret := utils.Redact(cred.Secret)
		sirupsenlog := logrus.WithFields(logrus.Fields{
			"node_id": cred.NodeID,
			"api_key": safeAPIKey,
			"secret":  safeSecret,
		})
		sirupsenlog.Info("Loaded gRPC node credential")
	}

	if cfg.NodeType != "" {
		client.SetNodeType(cfg.NodeType)
	}
	return client, nil
}
