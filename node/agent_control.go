package node

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	"github.com/AnixOps/anix-agent/v4/api/agent/pki"
	"github.com/AnixOps/anix-agent/v4/api/agent/state"
	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/conf"
	vCore "github.com/AnixOps/anix-agent/v4/core"
	"github.com/AnixOps/anix-agent/v4/plugin"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	log "github.com/sirupsen/logrus"
)

// newAgentControlClientForSupervisor binds the control stream to the
// node-scoped Supervisor selected after registration.  The pointer is kept in
// the controller's operation handler as well, so a duplicate configuration
// for another node can never route plugin operations through a shared runtime.
func newAgentControlClientForSupervisor(apiConfig *conf.ApiConfig, controller *Controller, core vCore.Core, supervisor *plugin.Supervisor, dataPlane *nodeDataPlane) (*agentapi.Client, error) {
	if controller == nil {
		return nil, fmt.Errorf("agent control node configuration is missing")
	}
	if controller.pluginSupervisor != supervisor {
		return nil, fmt.Errorf("agent control Supervisor does not match controller node scope")
	}
	if apiConfig == nil || controller == nil {
		return nil, fmt.Errorf("agent control node configuration is missing")
	}
	nodeID := controller.apiClient.GetNodeID()
	apiKey := controller.apiClient.GetAPIKey()
	if nodeID <= 0 || strings.TrimSpace(apiKey) == "" {
		return nil, fmt.Errorf("agent control requires registered node credentials")
	}
	target, useTLS, serverName, err := resolveAgentControlTarget(apiConfig)
	if err != nil {
		return nil, err
	}

	identity, err := agentControlIdentity(apiConfig, nodeID, useTLS)
	if err != nil {
		return nil, err
	}

	var dataPlaneConfig *agentapi.DataPlaneConfig
	if dataPlane != nil {
		dataPlaneConfig, err = agentControlDataPlane(apiConfig, nodeID, target, dataPlane)
		if err != nil {
			return nil, err
		}
	}

	hostname, _ := os.Hostname()
	keepaliveTime := time.Duration(apiConfig.GRPCKeepalive) * time.Second
	client, err := agentapi.NewClient(agentapi.Config{
		Target:       target,
		NodeID:       nodeID,
		APIKey:       apiKey,
		UseTLS:       useTLS,
		ServerName:   serverName,
		Identity:     identity,
		AgentVersion: panel.Version,
		InstanceID:   fmt.Sprintf("%s-%d-%d", hostname, os.Getpid(), nodeID),
		Capabilities: agentCapabilities(core, supervisor != nil),
		Labels: map[string]string{
			"core":      core.Type(),
			"node_type": apiConfig.NodeType,
			"transport": apiConfig.Transport,
		},
		KeepaliveTime: keepaliveTime,
		RootCAs:       agentControlRootCAs,
		Handler:       agentapi.OperationHandlerFunc(controller.handleAgentOperation),
		MetricsProvider: func(ctx context.Context) (map[string]float64, error) {
			if supervisor == nil {
				return nil, nil
			}
			return supervisor.TelemetryMetrics(ctx)
		},
		PluginObservationsProvider: func(ctx context.Context) ([]*agentv1pb.PluginObservedState, error) {
			if supervisor == nil {
				return nil, nil
			}
			return supervisor.PluginObservations(ctx)
		},
		DataPlane: dataPlaneConfig,
	})
	if err != nil {
		return nil, err
	}
	if dataPlane != nil {
		dataPlane.client = client
		if dataPlane.forward != nil {
			attachForward(dataPlane.forward, client)
		}
	}
	controller.agentClient = client
	return client, nil
}

// agentControlDataPlane is the stream's data-plane configuration (AG-3):
// the node's state directory and the appliers of dataPlane.
func agentControlDataPlane(apiConfig *conf.ApiConfig, nodeID int, target string, dataPlane *nodeDataPlane) (*agentapi.DataPlaneConfig, error) {
	settings := apiConfig.AgentStream
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	store, err := state.Open(settings.Dir(), agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: uint32(nodeID)}) // #nosec G115 -- node IDs are uint32 on the wire.
	if err != nil {
		return nil, err
	}
	if apiConfig.ForceReRegister {
		if err := store.DiscardConfig(); err != nil {
			log.WithError(err).WithField("dir", store.Dir()).Warn("Could not remove the stored configuration snapshot on re-registration")
		}
	}
	if apiConfig.ForceReRegister {
		if err := store.DiscardUsers(); err != nil {
			log.WithError(err).WithField("dir", store.Dir()).Warn("Could not remove the stored user set on re-registration")
		}
	}
	config := &agentapi.DataPlaneConfig{
		State: store, Control: target, Config: dataPlane, Users: dataPlane, Alive: dataPlane, LegacyGrace: streamLegacyGrace,
		Reports: &agentapi.ReportsConfig{
			TrafficMaxBytes: settings.SpoolBytes(), LogsMaxBytes: settings.LogSpoolBytes(), MaxAge: settings.SpoolMaxAge(),
			Status: dataPlane.nodeStatus,
		},
	}
	if dataPlane.forward != nil {
		// The stream carries the node's forwarding (forward.v1).
		config.Forward = dataPlane.forward
	}
	if supervisor := dataPlane.supervisor(); supervisor != nil {
		// The plugin supervisor's maintenance outbox (maintenance.v1) and
		// its release downloads (artifacts.v1) ride the stream.
		config.PackageReports = &agentapi.PackageReportsConfig{Collect: supervisor.PackageReports}
		if store := supervisor.MaintenanceStore(); store != nil {
			config.Maintenance = &agentapi.MaintenanceConfig{Outbox: maintenanceOutbox{store: store}, Interval: streamMaintenanceInterval}
		}
		config.Artifacts = true
	}
	return config, nil
}

// dataPlaneEnabled tells whether the node's data rides the control stream
// when Control serves it.
func dataPlaneEnabled(apiConfig conf.ApiConfig) bool {
	return apiConfig.AgentControlEnabled && apiConfig.AgentStream.DataPlaneMode() == conf.AgentStreamDataPlaneAuto
}

// agentControlRootCAs verifies Control's TLS certificate; nil uses the
// system roots. Tests point it at their in-process Control's CA.
var agentControlRootCAs *x509.CertPool

// agentControlIdentity is the stream's mTLS identity configuration (AG-2),
// nil when the stream is not on TLS: a client certificate needs TLS, and an
// enrollment must never send the node API key in the clear. A forced
// re-registration drops the stored identity, as it drops the node
// credentials.
func agentControlIdentity(apiConfig *conf.ApiConfig, nodeID int, useTLS bool) (*agentapi.IdentityConfig, error) {
	settings := apiConfig.AgentIdentity
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if !useTLS {
		log.WithFields(log.Fields{"component": "agent-identity", "node_id": nodeID}).
			Warn("Agent control stream is not on TLS; the Agent cannot enroll or present a client certificate and authenticates with the node API key. Control 4.2 (agent_control.mtls: required) refuses it")
		return nil, nil
	}
	if apiConfig.ForceReRegister && nodeID > 0 {
		store, err := pki.NewStore(settings.Dir(), agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: uint32(nodeID)}) // #nosec G115 -- node IDs are uint32 on the wire.
		if err == nil {
			if err := store.Discard(); err != nil {
				log.WithError(err).WithField("dir", store.Dir()).Warn("Could not remove the agent identity on re-registration")
			} else {
				log.WithField("dir", store.Dir()).Info("Force re-register: removed the stored agent identity")
			}
		}
	}
	return &agentapi.IdentityConfig{
		Dir:                  settings.Dir(),
		Enroll:               settings.EnrollMode() == conf.AgentIdentityEnrollAuto,
		EnrollCredentialFile: strings.TrimSpace(settings.EnrollCredentialFile),
		Cluster:              strings.TrimSpace(settings.Cluster),
	}, nil
}

func resolveAgentControlTarget(config *conf.ApiConfig) (target string, useTLS bool, serverName string, err error) {
	if config == nil {
		return "", false, "", fmt.Errorf("agent control configuration is missing")
	}

	rawAPIHost := strings.TrimSpace(config.APIHost)
	apiURL, apiURLErr := url.Parse(rawAPIHost)
	apiUsesTLS := apiURLErr == nil && strings.EqualFold(apiURL.Scheme, "https")
	useTLS = config.GRPCUseTLS || apiUsesTLS

	target = strings.TrimSpace(config.GRPCHost)
	if target != "" {
		serverName = strings.TrimSpace(config.GRPCServerName)
		if serverName == "" {
			serverName = agentControlTargetHost(target)
		}
		if err := validateAgentControlTransport(target, useTLS, config.AgentControlAllowInsecure); err != nil {
			return "", false, "", err
		}
		return target, useTLS, serverName, nil
	}

	rawHost := rawAPIHost
	if rawHost == "" {
		return "", false, "", fmt.Errorf("agent control target is empty")
	}
	parsed, parseErr := url.Parse(rawHost)
	if parseErr == nil && parsed.Hostname() != "" {
		serverName = parsed.Hostname()
		target = net.JoinHostPort(serverName, "50051")
	} else {
		host := rawHost
		if strings.Contains(host, "://") {
			return "", false, "", fmt.Errorf("invalid agent control API host %q", rawHost)
		}
		if parsedHost, _, splitErr := net.SplitHostPort(host); splitErr == nil {
			host = parsedHost
		}
		serverName = strings.Trim(host, "[]")
		target = net.JoinHostPort(serverName, "50051")
	}
	if config.GRPCServerName != "" {
		serverName = strings.TrimSpace(config.GRPCServerName)
	}
	if err := validateAgentControlTransport(target, useTLS, config.AgentControlAllowInsecure); err != nil {
		return "", false, "", err
	}
	return target, useTLS, serverName, nil
}

func validateAgentControlTransport(target string, useTLS, allowInsecure bool) error {
	if useTLS || allowInsecure || isLoopbackAgentControlTarget(target) {
		return nil
	}
	return fmt.Errorf(
		"agent control refuses plaintext credentials to non-loopback target %q; enable TLS or set AgentControlAllowInsecure=true explicitly",
		target,
	)
}

func isLoopbackAgentControlTarget(target string) bool {
	host := agentControlTargetHost(target)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func agentControlTargetHost(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if parsed, err := url.Parse(target); err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	if host, _, err := net.SplitHostPort(target); err == nil {
		return strings.Trim(host, "[]")
	}
	if strings.HasPrefix(target, "[") && strings.HasSuffix(target, "]") {
		return strings.Trim(target, "[]")
	}
	return strings.Trim(target, "[]")
}

func agentCapabilities(core vCore.Core, pluginSupervisorEnabled bool) []*agentv1pb.Capability {
	capabilities := []*agentv1pb.Capability{
		{Name: "agent.control", Version: agentcontrol.CapabilityVersionV1},
		{Name: "operation.cancel", Version: agentcontrol.CapabilityVersionV1},
		{Name: "agent.ping", Version: agentcontrol.CapabilityVersionV1},
		{Name: "node.reload", Version: agentcontrol.CapabilityVersionV1},
		{Name: "users.reload", Version: agentcontrol.CapabilityVersionV1},
		{Name: "core." + core.Type(), Version: agentcontrol.CapabilityVersionV1},
	}
	for _, protocol := range core.Protocols() {
		capabilities = append(capabilities, &agentv1pb.Capability{
			Name:    "proxy.protocol." + strings.ToLower(protocol),
			Version: agentcontrol.CapabilityVersionV1,
		})
	}
	if pluginSupervisorEnabled {
		capabilities = append(capabilities, &agentv1pb.Capability{Name: "kernel.observed-state", Version: agentcontrol.CapabilityVersionV1})
		for _, operation := range []string{"plugin.install", "plugin.inspect", "plugin.configure", "plugin.enable", "plugin.disable", "plugin.update", "plugin.rollback", "plugin.health"} {
			capabilities = append(capabilities, &agentv1pb.Capability{Name: operation, Version: agentcontrol.CapabilityVersionV1})
		}
	}
	return capabilities
}

func (c *Controller) handleAgentOperation(ctx context.Context, operation *agentv1pb.DesiredOperation) (json.RawMessage, error) {
	if operation == nil {
		return nil, fmt.Errorf("desired operation is nil")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	switch operation.Kind {
	case "plugin.install":
		if c.pluginSupervisor == nil {
			return nil, fmt.Errorf("plugin supervisor is not enabled")
		}
		envelope, err := agentapi.DecodeOperationEnvelopeContext(ctx, operation)
		if err != nil {
			return nil, err
		}
		installer, err := c.pluginInstaller()
		if err != nil {
			return nil, err
		}
		return installer.Handle(ctx, envelope)
	case "plugin.inspect", "plugin.configure", "plugin.enable", "plugin.disable", "plugin.update", "plugin.rollback", "plugin.health":
		if c.pluginSupervisor == nil {
			return nil, fmt.Errorf("plugin supervisor is not enabled")
		}
		envelope, err := agentapi.DecodeOperationEnvelopeContext(ctx, operation)
		if err != nil {
			return nil, err
		}
		return c.pluginSupervisor.Handle(ctx, operation.Kind, envelope)
	case "agent.ping":
		return json.Marshal(map[string]any{
			"node_id": c.apiClient.GetNodeID(),
			"tag":     c.tag,
			"time":    time.Now().UnixMilli(),
		})
	case "node.reload", "users.reload":
		if !c.isStarted() {
			return nil, fmt.Errorf("node %d is still starting", c.apiClient.GetNodeID())
		}
		// While the stream carries the configuration (config.v1), a
		// reload re-pulls nothing over the legacy transport: Control
		// pushes snapshots instead (nodeInfoMonitor skips the pull).
		if err := c.nodeInfoMonitor(); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{
			"node_id":  c.apiClient.GetNodeID(),
			"tag":      c.tag,
			"revision": operation.Revision,
			"config":   c.stream.mode(agentcontrol.CapabilityConfig).String(),
		})
	default:
		return nil, fmt.Errorf("unsupported desired operation %q", operation.Kind)
	}
}

// pluginInstaller downloads plugin releases from AgentArtifacts by the
// client certificate when the session negotiated artifacts.v1 (the API key
// is never sent then), and over HTTP with the node API key otherwise: an
// Agent that is not enrolled, or whose Control predates AgentArtifacts
// (4.1.x; the v4.2 upgrade runs the new Agent before the new Control).
func (c *Controller) pluginInstaller() (*plugin.RemoteInstaller, error) {
	download := agentapi.PluginDownloadHTTP
	if c.agentClient != nil {
		download = c.agentClient.PluginDownload()
	}
	switch download {
	case agentapi.PluginDownloadArtifacts:
		artifacts, err := c.agentClient.PluginArtifacts()
		if err != nil {
			return nil, err
		}
		return plugin.NewRemoteInstaller(plugin.RemoteInstallerConfig{Supervisor: c.pluginSupervisor, Artifacts: artifacts})
	default:
		return plugin.NewRemoteInstaller(plugin.RemoteInstallerConfig{
			Supervisor: c.pluginSupervisor,
			BaseURL:    c.apiClient.GetAPIHost(),
			APIKey:     c.apiClient.GetAPIKey(),
		})
	}
}

func logAgentControlUnavailable(nodeID int, err error) {
	log.WithFields(log.Fields{
		"component": "agent-control",
		"node_id":   strconv.Itoa(nodeID),
		"error":     err,
	}).Warn("Agent control stream is unavailable; legacy transport remains active")
}
