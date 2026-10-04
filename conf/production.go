package conf

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// ValidateForProduction rejects partially configured machine telemetry nodes.
// Legacy and development configurations keep their existing behavior unless a
// node explicitly declares MaintenanceEnvironment=production.
func (p *Conf) ValidateForProduction() error {
	if p == nil {
		return fmt.Errorf("configuration is nil")
	}
	rootEnvironment := strings.ToLower(strings.TrimSpace(p.Environment))
	switch rootEnvironment {
	case "", "development", "test", "staging", "production":
	default:
		return fmt.Errorf("unsupported Environment %q", p.Environment)
	}
	rootProduction := rootEnvironment == "production"
	// A forward node's Agent runs no proxy node and no core.
	forwardOnly := p.Forward.ForwardNodeOnly()
	if rootProduction && forwardOnly {
		if err := validateProductionForwardNode(*p.Forward.ForwardNode); err != nil {
			return err
		}
	}
	if rootProduction && len(p.NodeConfig) == 0 && !forwardOnly {
		return fmt.Errorf("production configuration requires at least one node")
	}
	// Nodes configured from the stream (credential-only, the O1
	// installer's configuration) run on the compiled-in cores.
	streamOnly := len(p.NodeConfig) > 0
	for i := range p.NodeConfig {
		if !p.NodeConfig[i].ApiConfig.StreamCredentialOnly() {
			streamOnly = false
		}
	}
	if rootProduction && len(p.CoresConfig) == 0 && !forwardOnly && !streamOnly {
		return fmt.Errorf("production configuration requires at least one core")
	}
	configuredCores := make(map[string]struct{}, len(p.CoresConfig))
	for i := range p.CoresConfig {
		coreType := strings.ToLower(strings.TrimSpace(p.CoresConfig[i].Type))
		switch coreType {
		case "sing", "xray", "hysteria2", "wireguard":
			configuredCores[coreType] = struct{}{}
		default:
			if rootProduction {
				return fmt.Errorf("production core %d has unsupported Type %q", i, p.CoresConfig[i].Type)
			}
		}
	}
	seenNodeIDs := make(map[int]struct{})
	for i := range p.NodeConfig {
		api := p.NodeConfig[i].ApiConfig
		nodeEnvironment := strings.ToLower(strings.TrimSpace(api.MaintenanceEnvironment))
		switch nodeEnvironment {
		case "", "development", "test", "staging", "production":
		default:
			return fmt.Errorf("production node %d has unsupported MaintenanceEnvironment %q", i, api.MaintenanceEnvironment)
		}
		nodeProduction := nodeEnvironment == "production"
		if rootProduction && !nodeProduction {
			return fmt.Errorf("production node %d must set MaintenanceEnvironment=production", i)
		}
		if !rootProduction && !nodeProduction {
			continue
		}
		if api.NodeID > 0 && !api.AutoRegister {
			if _, duplicate := seenNodeIDs[api.NodeID]; duplicate {
				return fmt.Errorf("production NodeID %d is configured more than once", api.NodeID)
			}
			seenNodeIDs[api.NodeID] = struct{}{}
		}
		if err := validateProductionNode(i, api, p.NodeConfig[i].Options); err != nil {
			return err
		}
		if api.StreamCredentialOnly() && strings.TrimSpace(p.NodeConfig[i].Options.Core) == "" {
			continue
		}
		if _, exists := configuredCores[strings.ToLower(strings.TrimSpace(p.NodeConfig[i].Options.Core))]; !exists {
			return fmt.Errorf("production node %d references Core %q that is not configured", i, p.NodeConfig[i].Options.Core)
		}
	}
	return nil
}

func validateProductionNode(index int, api ApiConfig, options Options) error {
	var problems []string
	require := func(ok bool, message string) {
		if !ok {
			problems = append(problems, message)
		}
	}

	// A credential-only node (no ApiKey; an enrollment credential or an
	// enrolled identity, and the stream data plane) takes its
	// configuration, users and maintenance from the stream: no legacy
	// transport settings, no core to name, the plugin supervisor optional.
	streamOnly := api.StreamCredentialOnly()

	require(validProductionHTTPSURL(api.APIHost), "ApiHost must be a non-placeholder HTTPS URL")
	require(api.Transport == "http" || api.Transport == "grpc", "Transport must be http or grpc")
	require(api.AgentControlEnabled, "AgentControlEnabled must be true")
	require(!api.AgentControlAllowInsecure, "AgentControlAllowInsecure must be false")
	require(api.PluginSupervisorEnabled || streamOnly, "PluginSupervisorEnabled must be true")
	require(api.GRPCUseTLS, "GRPCUseTLS must be true")
	require(validProductionHostPort(api.GRPCHost), "GRPCHost must be a non-placeholder host:port")
	// A credential-only node may leave GRPCServerName out: the TLS name
	// is then GRPCHost's host, checked above.
	require(nonPlaceholder(api.GRPCServerName) || (streamOnly && strings.TrimSpace(api.GRPCServerName) == ""),
		"GRPCServerName is required and must not be a placeholder")
	require(api.GRPCKeepalive > 0 && api.GRPCKeepalive <= 300, "GRPCKeepalive must be between 1 and 300 seconds")
	require(api.Timeout > 0 && api.Timeout <= 300, "Timeout must be between 1 and 300 seconds")
	require(api.EnableSign || streamOnly, "EnableSign must be true")
	require(nonPlaceholder(options.Core) || (streamOnly && strings.TrimSpace(options.Core) == ""), "Core is required and must not be a placeholder")

	if api.PluginSupervisorEnabled || !streamOnly {
		decodedKey, keyErr := base64.StdEncoding.DecodeString(strings.TrimSpace(api.PluginOfficialPublicKey))
		require(keyErr == nil && len(decodedKey) == 32, "PluginOfficialPublicKey must be one base64 Ed25519 public key")
		require(filepath.IsAbs(api.PluginRootDir()), "PluginRoot must be an absolute path")
		require(filepath.IsAbs(api.PluginSocketBase()), "PluginSocketDir must be an absolute path")
		require(filepath.Clean(api.PluginRootDir()) != filepath.Clean(api.PluginSocketBase()), "PluginRoot and PluginSocketDir must be different")
	}

	if streamOnly {
		require(api.NodeID > 0, "NodeID must be positive")
	} else if api.AutoRegister {
		require(nonPlaceholderSecret(api.AuthKey), "AuthKey is required and must not be a placeholder when AutoRegister is true")
		require(api.EnableSign, "EnableSign must be true when AutoRegister is true")
		require(api.EncryptCredential, "EncryptCredential must be true when AutoRegister is true")
		require(filepath.IsAbs(api.CredentialFile), "CredentialFile must be an absolute path when AutoRegister is true")
	} else {
		require(api.NodeID > 0, "NodeID must be positive")
		require(nonPlaceholderSecret(api.Key), "ApiKey is required and must not be a placeholder")
	}

	syncConfig := options.SyncConfig
	require(syncConfig != nil || streamOnly, "SyncConfig is required")
	if syncConfig != nil && !streamOnly {
		require(syncConfig.EnableWebSocket, "SyncConfig.EnableWebSocket must be true")
		require(syncConfig.WSEndpoint == "/api/v2/agent/ws" || syncConfig.WSEndpoint == "/api/v2/node/ws", "SyncConfig.WSEndpoint must use an authenticated maintenance endpoint")
		require(syncConfig.ReconnectInterval > 0 && syncConfig.ReconnectInterval <= 300, "SyncConfig.ReconnectInterval must be between 1 and 300 seconds")
		require(syncConfig.MaxReconnectTries == 0, "SyncConfig.MaxReconnectTries must be 0 for unlimited production reconnects")
		require(syncConfig.PingInterval >= 5 && syncConfig.PingInterval <= 300, "SyncConfig.PingInterval must be between 5 and 300 seconds")
		require(syncConfig.PongTimeout > 0 && syncConfig.PongTimeout < syncConfig.PingInterval, "SyncConfig.PongTimeout must be positive and less than PingInterval")
		require(syncConfig.AckTimeout > 0 && syncConfig.AckTimeout <= 60, "SyncConfig.AckTimeout must be between 1 and 60 seconds")
		require(syncConfig.AckRetries > 0 && syncConfig.AckRetries <= 10, "SyncConfig.AckRetries must be between 1 and 10")
		require(syncConfig.BufferSize >= 50 && syncConfig.BufferSize <= 10000, "SyncConfig.BufferSize must be between 50 and 10000")
	}
	if options.CertConfig != nil && options.CertConfig.CertMode == "file" {
		require(nonPlaceholder(options.CertConfig.CertDomain), "CertConfig.CertDomain is required and must not be a placeholder in file mode")
		require(filepath.IsAbs(options.CertConfig.CertFile), "CertConfig.CertFile must be an absolute path in file mode")
		require(filepath.IsAbs(options.CertConfig.KeyFile), "CertConfig.KeyFile must be an absolute path in file mode")
	}

	if len(problems) > 0 {
		return fmt.Errorf("production node %d configuration is not ready: %s", index, strings.Join(problems, "; "))
	}
	return nil
}

func validProductionHTTPSURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return false
	}
	host := parsed.Hostname()
	if placeholder(host) {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || (!ip.IsUnspecified() && !ip.IsLoopback())
}

func nonPlaceholder(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	return trimmed != "" && !placeholder(trimmed)
}

func validProductionHostPort(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	if placeholder(trimmed) {
		return false
	}
	host, portText, err := net.SplitHostPort(trimmed)
	if err != nil || strings.TrimSpace(host) == "" {
		return false
	}
	port, err := strconv.Atoi(portText)
	return err == nil && port > 0 && port <= 65535
}

func nonPlaceholderSecret(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	return len(trimmed) >= 16 && !placeholder(trimmed)
}

func placeholder(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	return strings.Contains(lower, "example.com") || strings.Contains(lower, "example.org") ||
		strings.Contains(lower, "example.net") || strings.Contains(lower, ".invalid") ||
		strings.Contains(lower, ".test") || strings.Contains(lower, ".localhost") || lower == "localhost" ||
		strings.Contains(lower, "your-") || strings.Contains(lower, "replace") ||
		strings.Contains(lower, "change_me") || strings.Contains(lower, "change-me")
}

// validateProductionForwardNode checks a forward node's connection: TLS to
// a real Control, never plaintext, and an identity that enrolls.
func validateProductionForwardNode(api ApiConfig) error {
	var problems []string
	require := func(ok bool, message string) {
		if !ok {
			problems = append(problems, message)
		}
	}
	require(api.GRPCUseTLS, "GRPCUseTLS must be true")
	require(!api.AgentControlAllowInsecure, "AgentControlAllowInsecure must be false")
	require(validProductionHostPort(api.GRPCHost), "GRPCHost must be a non-placeholder host:port")
	// Without GRPCServerName the TLS name is GRPCHost's host (the O1
	// installer's configuration), checked above.
	require(strings.TrimSpace(api.GRPCServerName) == "" || nonPlaceholder(api.GRPCServerName), "GRPCServerName must not be a placeholder")
	require(api.NodeID > 0, "NodeID must be positive")
	// No ApiKey: a forward node enrolls with its token or a one-time
	// credential (AgentIdentity.EnrollCredentialFile, which the Agent
	// removes after use) and then presents its certificate only.
	require(api.Key == "" || nonPlaceholderSecret(api.Key), "ApiKey, when set, must not be a placeholder")
	if len(problems) > 0 {
		return fmt.Errorf("production forward node configuration is not ready: %s", strings.Join(problems, "; "))
	}
	return nil
}
