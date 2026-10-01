// Command agent-control-fixture is a test-only Agent process used by the
// cross-repository Control KernelOperationBridge E2E harness.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	"github.com/AnixOps/anix-agent/v4/plugin"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
)

type fixtureResult struct {
	OperationID   string          `json:"operation_id"`
	Kind          string          `json:"kind"`
	SessionID     string          `json:"session_id"`
	Revision      uint64          `json:"revision"`
	PluginID      string          `json:"plugin_id"`
	TargetVersion string          `json:"target_version"`
	ConfigHash    string          `json:"config_hash"`
	Config        json.RawMessage `json:"config"`
}

func main() {
	var (
		target          = flag.String("target", "", "Control gRPC host:port")
		nodeID          = flag.Int("node-id", 0, "Control node ID")
		apiKey          = flag.String("api-key", "", "Control node API key")
		readyFile       = flag.String("ready-file", "", "file written after the Agent stream is ready")
		resultFile      = flag.String("result-file", "", "file written after an operation is handled")
		timeout         = flag.Duration("timeout", 30*time.Second, "maximum fixture lifetime")
		pluginRoot      = flag.String("plugin-root", "", "enable the production plugin Supervisor at this root")
		pluginSockets   = flag.String("plugin-socket-dir", "", "private Unix socket directory for plugin processes")
		pluginPublicKey = flag.String("plugin-public-key", "", "base64 Ed25519 official plugin public key")
		pluginBaseURL   = flag.String("plugin-base-url", "", "Control HTTP origin used for signed plugin downloads")
	)
	flag.Parse()
	if *target == "" || *nodeID <= 0 || *apiKey == "" || *readyFile == "" || *resultFile == "" {
		fatal(errors.New("target, node-id, api-key, ready-file, and result-file are required"))
	}

	operationHandler, capabilities, metricsProvider, closePlugins, err := newOperationHandler(pluginFixtureConfig{
		RootDir: *pluginRoot, SocketDir: *pluginSockets, PublicKey: *pluginPublicKey,
		BaseURL: *pluginBaseURL, APIKey: *apiKey, ResultFile: *resultFile,
	})
	if err != nil {
		fatal(err)
	}
	if closePlugins != nil {
		defer func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if closeErr := closePlugins(closeCtx); closeErr != nil {
				fmt.Fprintln(os.Stderr, closeErr)
			}
		}()
	}

	client, err := agentapi.NewClient(agentapi.Config{
		Target: *target, NodeID: *nodeID, APIKey: *apiKey,
		AgentVersion: "agent-control-fixture", InstanceID: "agent-control-fixture-" + strconv.Itoa(os.Getpid()),
		Capabilities: capabilities,
		ReconnectMin: 20 * time.Millisecond, ReconnectMax: 100 * time.Millisecond,
		Heartbeat: 5 * time.Second, DialTimeout: 3 * time.Second, HandshakeTimeout: 3 * time.Second,
		Handler: operationHandler, MetricsProvider: metricsProvider,
	})
	if err != nil {
		fatal(err)
	}
	if err := client.Start(); err != nil {
		fatal(err)
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			fmt.Fprintln(os.Stderr, closeErr)
		}
	}()

	startup := time.NewTimer(*timeout)
	defer startup.Stop()
	select {
	case <-client.Ready():
		if err := writeJSONAtomically(*readyFile, map[string]any{
			"node_id": *nodeID, "session_id": client.SessionID(), "pid": os.Getpid(),
		}); err != nil {
			fatal(err)
		}
	case <-startup.C:
		fatal(errors.New("Agent fixture did not connect before timeout"))
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	lifetime := time.NewTimer(*timeout)
	defer lifetime.Stop()
	select {
	case <-signals:
	case <-lifetime.C:
		fatal(errors.New("Agent fixture timed out waiting for an operation"))
	}
}

type pluginFixtureConfig struct {
	RootDir    string
	SocketDir  string
	PublicKey  string
	BaseURL    string
	APIKey     string
	ResultFile string
}

func newOperationHandler(config pluginFixtureConfig) (agentapi.OperationHandler, []*agentv1pb.Capability, func(context.Context) (map[string]float64, error), func(context.Context) error, error) {
	capabilities := []*agentv1pb.Capability{
		{Name: "agent.control", Version: "v1"},
		{Name: "operation.cancel", Version: "v1"},
		{Name: "plugin.health", Version: "v1"},
	}
	record := func(ctx context.Context, operation *agentv1pb.DesiredOperation) (*agentapi.OperationEnvelope, error) {
		envelope, err := agentapi.DecodeOperationEnvelopeContext(ctx, operation)
		if err != nil {
			return nil, err
		}
		result := fixtureResult{
			OperationID: operation.OperationId, Kind: operation.Kind, SessionID: envelope.SessionID,
			Revision: envelope.Revision, PluginID: envelope.PluginID, TargetVersion: envelope.TargetVersion,
			ConfigHash: envelope.ConfigHash, Config: append(json.RawMessage(nil), envelope.Config...),
		}
		if err := writeJSONAtomically(config.ResultFile, result); err != nil {
			return nil, err
		}
		return envelope, nil
	}

	pluginMode := config.RootDir != "" || config.SocketDir != "" || config.PublicKey != "" || config.BaseURL != ""
	if !pluginMode {
		return agentapi.OperationHandlerFunc(func(ctx context.Context, operation *agentv1pb.DesiredOperation) (json.RawMessage, error) {
			if _, err := record(ctx, operation); err != nil {
				return nil, err
			}
			return json.RawMessage(`{"fixture":"agent-control","status":"ok"}`), nil
		}), capabilities, nil, nil, nil
	}
	if config.RootDir == "" || config.SocketDir == "" || config.PublicKey == "" || config.BaseURL == "" {
		return nil, nil, nil, nil, errors.New("plugin-root, plugin-socket-dir, plugin-public-key, and plugin-base-url are all required in plugin mode")
	}
	decodedKey, err := base64.StdEncoding.DecodeString(config.PublicKey)
	if err != nil || len(decodedKey) != ed25519.PublicKeySize {
		return nil, nil, nil, nil, errors.New("plugin-public-key must be a base64 Ed25519 public key")
	}
	supervisor, err := plugin.NewSupervisor(plugin.Config{
		RootDir: config.RootDir, SocketDir: config.SocketDir, PublicKey: ed25519.PublicKey(decodedKey),
	})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	installer, err := plugin.NewRemoteInstaller(plugin.RemoteInstallerConfig{
		Supervisor: supervisor, BaseURL: config.BaseURL, APIKey: config.APIKey,
	})
	if err != nil {
		_ = supervisor.Close(context.Background())
		return nil, nil, nil, nil, err
	}
	capabilities = capabilities[:2]
	for _, name := range []string{
		"plugin.install", "plugin.inspect", "plugin.configure", "plugin.enable",
		"plugin.disable", "plugin.update", "plugin.rollback", "plugin.health",
	} {
		capabilities = append(capabilities, &agentv1pb.Capability{Name: name, Version: "v1"})
	}
	handler := agentapi.OperationHandlerFunc(func(ctx context.Context, operation *agentv1pb.DesiredOperation) (json.RawMessage, error) {
		envelope, err := record(ctx, operation)
		if err != nil {
			return nil, err
		}
		if operation.Kind == "plugin.install" {
			return installer.Handle(ctx, envelope)
		}
		return supervisor.Handle(ctx, operation.Kind, envelope)
	})
	return handler, capabilities, supervisor.TelemetryMetrics, supervisor.Close, nil
}

func writeJSONAtomically(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temporary := path + ".tmp-" + strconv.Itoa(os.Getpid())
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "agent-control-fixture:", err)
	os.Exit(1)
}
