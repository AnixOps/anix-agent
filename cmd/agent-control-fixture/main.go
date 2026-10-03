// Command agent-control-fixture is a test-only Agent process used by the
// cross-repository Control KernelOperationBridge E2E harness.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	"github.com/AnixOps/anix-agent/v4/api/agent/state"
	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/plugin"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
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
		useTLS          = flag.Bool("tls", false, "dial Control over TLS")
		tlsCAFile       = flag.String("tls-ca-file", "", "PEM roots for Control's TLS certificate (default: system roots)")
		serverName      = flag.String("server-name", "", "TLS server name of Control")
		pkiDir          = flag.String("pki-dir", "", "enable the mTLS identity (AG-2) with this identity root; needs -tls")
		enroll          = flag.Bool("enroll", true, "with -pki-dir: enroll when the node has no identity")
		enrollCredFile  = flag.String("enroll-credential-file", "", "with -pki-dir: one-time anixagt_ enrollment credential file")
		cluster         = flag.String("cluster", "", "with -pki-dir: pin the SPIFFE cluster")
		dataPlaneDir    = flag.String("data-plane-dir", "", "turn on the stream data plane (config.v1) with this state root")
		configRecord    = flag.String("config-record", "", "with -data-plane-dir: file written after each applied configuration snapshot")
		usersRecord     = flag.String("users-record", "", "with -data-plane-dir: take users from the stream (users.v1); file written after each applied user set")
		reports         = flag.Bool("reports", false, "with -data-plane-dir: report on the stream (reports.v1) with the spool and a fixed node status")
		traffic         = flag.String("traffic", "", "with -reports: uid:upload:download,... submitted once as a TrafficReport after the stream is ready")
		packageReport   = flag.String("package-report-file", "", "with -data-plane-dir: JSON PackageReport (plugin_id, kind, version, payload_json, observed_at_unix_ms) sent with package-reports.v1")
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

	var roots *x509.CertPool
	if *tlsCAFile != "" {
		pemBytes, err := os.ReadFile(*tlsCAFile)
		if err != nil {
			fatal(err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pemBytes) {
			fatal(fmt.Errorf("%s holds no PEM certificate", *tlsCAFile))
		}
	}
	var identity *agentapi.IdentityConfig
	if *pkiDir != "" {
		identity = &agentapi.IdentityConfig{Dir: *pkiDir, Enroll: *enroll, EnrollCredentialFile: *enrollCredFile, Cluster: *cluster}
	}
	dataPlane, err := newFixtureDataPlane(*dataPlaneDir, *configRecord, *usersRecord, *nodeID)
	if err != nil {
		fatal(err)
	}
	if dataPlane != nil && *reports {
		dataPlane.Reports = &agentapi.ReportsConfig{Status: func(context.Context) (*agentv1pb.NodeStatus, error) {
			return &agentv1pb.NodeStatus{CpuUsagePercent: 1.5, MemoryUsagePercent: 2.5, DiskUsagePercent: 3.5, UptimeSeconds: 60, RuntimeHealthy: true, ObservedAtUnixMs: time.Now().UnixMilli()}, nil
		}}
	}
	if dataPlane != nil && *packageReport != "" {
		report, err := readPackageReport(*packageReport)
		if err != nil {
			fatal(err)
		}
		dataPlane.PackageReports = &agentapi.PackageReportsConfig{Collect: func(context.Context) ([]*agentv1pb.PackageReport, error) {
			return []*agentv1pb.PackageReport{report}, nil
		}}
	}
	client, err := agentapi.NewClient(agentapi.Config{
		Target: *target, NodeID: *nodeID, APIKey: *apiKey,
		UseTLS: *useTLS, ServerName: *serverName, RootCAs: roots, Identity: identity,
		AgentVersion: "agent-control-fixture", InstanceID: "agent-control-fixture-" + strconv.Itoa(os.Getpid()),
		Capabilities: capabilities,
		ReconnectMin: 20 * time.Millisecond, ReconnectMax: 100 * time.Millisecond,
		Heartbeat: 5 * time.Second, DialTimeout: 3 * time.Second, HandshakeTimeout: 3 * time.Second,
		Handler: operationHandler, MetricsProvider: metricsProvider,
		DataPlane: dataPlane,
	})
	if err != nil {
		fatal(err)
	}
	if plane := client.DataPlane(); plane != nil {
		// As a restarted Agent: run the stored snapshot, then take every
		// later one as it arrives.
		if persisted := plane.PersistedConfig(); persisted != nil {
			if err := dataPlane.Config.ApplyConfig(context.Background(), persisted); err != nil {
				plane.DiscardPersistedConfig()
			} else {
				plane.RestoreConfig(persisted)
			}
		}
		if persisted := plane.PersistedUsers(); persisted != nil && dataPlane.Users != nil {
			if err := dataPlane.Users.ApplyUsers(context.Background(), *persisted); err != nil {
				plane.DiscardPersistedUsers()
			} else {
				plane.RestoreUsers(*persisted)
			}
		}
		plane.Activate()
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
		status := client.TransportStatus()
		ready := map[string]any{
			"node_id": *nodeID, "session_id": client.SessionID(), "pid": os.Getpid(),
			"authentication": status.Authentication,
		}
		if status.Identity != nil {
			ready["spiffe_id"], ready["serial"] = status.Identity.SPIFFEID, status.Identity.Serial
		}
		if err := writeJSONAtomically(*readyFile, ready); err != nil {
			fatal(err)
		}
		if *traffic != "" {
			if err := submitFixtureTraffic(client.DataPlane(), *traffic); err != nil {
				fatal(err)
			}
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

// fixtureConfigApplier records each applied snapshot: the revision, the
// hash and the node configuration the Agent's UniProxy parser reads from
// legacy_pull.default, as the node controller runs it.
type fixtureConfigApplier struct {
	record string
	nodeID int
}

func (a fixtureConfigApplier) ApplyConfig(_ context.Context, snapshot *agentv1pb.ConfigSnapshot) error {
	var document struct {
		Kind       string `json:"kind"`
		LegacyPull struct {
			Default json.RawMessage            `json:"default"`
			Types   map[string]json.RawMessage `json:"types"`
		} `json:"legacy_pull"`
	}
	if err := json.Unmarshal(snapshot.GetConfigJson(), &document); err != nil {
		return fmt.Errorf("decode the configuration document: %w", err)
	}
	result := map[string]any{
		"config_revision": snapshot.GetConfigRevision(), "config_hash": snapshot.GetConfigHash(),
		"format": snapshot.GetFormat(), "kind": document.Kind,
	}
	if document.Kind == "proxy" {
		info, nodeType, err := panel.ParseNodeInfo(document.LegacyPull.Default, a.nodeID)
		if err != nil {
			return fmt.Errorf("parse legacy_pull.default: %w", err)
		}
		types := make([]string, 0, len(document.LegacyPull.Types))
		for name := range document.LegacyPull.Types {
			types = append(types, name)
		}
		result["node_type"], result["protocol"], result["types"] = nodeType, info.Type, types
		if info.Common != nil {
			result["server_port"] = info.Common.ServerPort
		}
	}
	if a.record == "" {
		return nil
	}
	return writeJSONAtomically(a.record, result)
}

// fixtureUsersApplier records each applied user set: the cursor and the
// users as the node receives them (ids, uuids, limits; extra_json keys).
type fixtureUsersApplier struct{ record string }

func (a fixtureUsersApplier) ApplyUsers(_ context.Context, set agentapi.UserSet) error {
	users := make([]map[string]any, 0, len(set.Users))
	for _, user := range set.Users {
		entry := map[string]any{
			"id": user.GetUserId(), "uuid": user.GetUuid(),
			"speed_limit": user.GetSpeedLimitMbps(), "device_limit": user.GetDeviceLimit(),
		}
		if len(user.GetExtraJson()) > 0 {
			var extra map[string]string
			if err := json.Unmarshal(user.GetExtraJson(), &extra); err != nil {
				return fmt.Errorf("user %d: extra_json: %w", user.GetUserId(), err)
			}
			keys := make([]string, 0, len(extra))
			for key := range extra {
				keys = append(keys, key)
			}
			entry["extra_keys"] = keys
		}
		users = append(users, entry)
	}
	return writeJSONAtomically(a.record, map[string]any{"cursor": set.Cursor, "users": users})
}

// submitFixtureTraffic spools one TrafficReport of uid:upload:download
// entries.
func submitFixtureTraffic(plane *agentapi.DataPlane, entries string) error {
	if plane == nil {
		return errors.New("-traffic needs -data-plane-dir and -reports")
	}
	report := &agentv1pb.TrafficReport{WindowEndUnixMs: time.Now().UnixMilli()}
	for _, entry := range strings.Split(entries, ",") {
		parts := strings.Split(strings.TrimSpace(entry), ":")
		if len(parts) != 3 {
			return fmt.Errorf("-traffic entry %q is not uid:upload:download", entry)
		}
		var numbers [3]uint64
		for index, part := range parts {
			value, err := strconv.ParseUint(part, 10, 64)
			if err != nil {
				return fmt.Errorf("-traffic entry %q: %w", entry, err)
			}
			numbers[index] = value
		}
		report.Users = append(report.Users, &agentv1pb.UserTraffic{UserId: numbers[0], UploadBytes: numbers[1], DownloadBytes: numbers[2]})
	}
	return plane.SubmitTraffic(report)
}

// readPackageReport reads -package-report-file.
func readPackageReport(path string) (*agentv1pb.PackageReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file struct {
		PluginID   string          `json:"plugin_id"`
		Kind       string          `json:"kind"`
		Version    string          `json:"version"`
		Payload    json.RawMessage `json:"payload_json"`
		ObservedAt int64           `json:"observed_at_unix_ms"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	return &agentv1pb.PackageReport{PluginId: file.PluginID, Kind: file.Kind, Version: file.Version, PayloadJson: file.Payload, ObservedAtUnixMs: file.ObservedAt}, nil
}

// newFixtureDataPlane is the data plane of -data-plane-dir, nil without it.
func newFixtureDataPlane(dir, configRecord, usersRecord string, nodeID int) (*agentapi.DataPlaneConfig, error) {
	if dir == "" {
		return nil, nil
	}
	store, err := state.Open(dir, agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: uint32(nodeID)}) // #nosec G115 -- node IDs are uint32 on the wire.
	if err != nil {
		return nil, err
	}
	plane := &agentapi.DataPlaneConfig{State: store, Config: fixtureConfigApplier{record: configRecord, nodeID: nodeID}}
	if usersRecord != "" {
		plane.Users = fixtureUsersApplier{record: usersRecord}
	}
	return plane, nil
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
