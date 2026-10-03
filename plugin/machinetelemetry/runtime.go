package machinetelemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AnixOps/anix-agent/v4/common/monitor"
	"github.com/AnixOps/anix-control/sdk/telemetry/systemdreport"
	"github.com/shirou/gopsutil/v3/host"
	gopsnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	ID                     = "machine-telemetry"
	Version                = "1.1.0"
	DefaultIntervalSeconds = 60
	MinimumIntervalSeconds = 5
	MaximumIntervalSeconds = 3600
	// maxConfigBytes leaves room for systemd_services with its 4096 nodes;
	// the operation envelope that carries the document is capped at 6 MiB.
	maxConfigBytes       = 1 << 20
	TelemetryServiceName = "anixops.plugin.v1.Telemetry"
	TelemetryMethodName  = "Snapshot"
	// ServicesMethodName returns the latest systemd.services report. Plugin
	// binaries before the collector answer Unimplemented.
	ServicesMethodName = "SystemdServices"
	// NodeIDEnvironment carries the Agent's node id to the plugin process.
	// The plugin reads only that node's systemd_services entry; without it
	// the services collector stays off.
	NodeIDEnvironment  = "ANIXOPS_NODE_ID"
	MaxMetrics         = 32
	MaxMetricKeyLength = 96
)

type Config struct {
	IntervalSeconds int
	// Services is the per-node systemd services settings
	// (ServicesConfigKey); every node is off unless listed and enabled.
	Services ServicesConfig
}

func (c Config) Interval() time.Duration {
	return time.Duration(c.IntervalSeconds) * time.Second
}

type rawConfig struct {
	IntervalSeconds json.RawMessage `json:"interval_seconds"`
	// SystemdServices is parsed by ParseServicesConfig; it is listed here
	// so every other unknown key is still refused.
	SystemdServices json.RawMessage `json:"systemd_services"`
}

// LoadConfig reads the Supervisor-owned configuration without following a
// final-path symlink. The manifest schema is enforced again at the process
// boundary so a manually modified file cannot relax the signed contract.
func LoadConfig(path string) (Config, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Config{}, errors.New("--anixops-config is required")
	}
	if !filepath.IsAbs(path) {
		return Config{}, errors.New("--anixops-config must be an absolute path")
	}

	before, err := os.Lstat(path)
	if err != nil {
		return Config{}, fmt.Errorf("inspect plugin config: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return Config{}, errors.New("plugin config must be a regular file, not a symlink")
	}
	if before.Mode().Perm()&0o022 != 0 {
		return Config{}, errors.New("plugin config must not be writable by group or other users")
	}
	if before.Size() > maxConfigBytes {
		return Config{}, fmt.Errorf("plugin config exceeds %d bytes", maxConfigBytes)
	}

	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open plugin config: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("stat opened plugin config: %w", err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return Config{}, errors.New("plugin config changed while it was being opened")
	}

	contents, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read plugin config: %w", err)
	}
	if len(contents) > maxConfigBytes {
		return Config{}, fmt.Errorf("plugin config exceeds %d bytes", maxConfigBytes)
	}

	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var raw *rawConfig
	if err := decoder.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("decode plugin config: %w", err)
	}
	if raw == nil {
		return Config{}, errors.New("plugin config must be a JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("plugin config must contain exactly one JSON object")
		}
		return Config{}, fmt.Errorf("decode trailing plugin config data: %w", err)
	}

	services, err := ParseServicesConfig(contents)
	if err != nil {
		return Config{}, err
	}
	config := Config{IntervalSeconds: DefaultIntervalSeconds, Services: services}
	if len(raw.IntervalSeconds) == 0 {
		return config, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw.IntervalSeconds), []byte("null")) {
		return Config{}, errors.New("interval_seconds must be an integer")
	}
	if err := json.Unmarshal(raw.IntervalSeconds, &config.IntervalSeconds); err != nil {
		return Config{}, fmt.Errorf("interval_seconds must be an integer: %w", err)
	}
	if config.IntervalSeconds < MinimumIntervalSeconds {
		return Config{}, fmt.Errorf("interval_seconds must be at least %d", MinimumIntervalSeconds)
	}
	if config.IntervalSeconds > MaximumIntervalSeconds {
		return Config{}, fmt.Errorf("interval_seconds must be at most %d", MaximumIntervalSeconds)
	}
	return config, nil
}

type Options struct {
	SocketPath string
	ConfigPath string
	// NodeID is the Agent node this plugin instance serves (from
	// NodeIDEnvironment); 0 leaves the systemd services collector off.
	NodeID uint64
	// ServicesPlatform overrides DefaultServicesPlatform in tests.
	ServicesPlatform *ServicesPlatform
	// Logf receives non-fatal collector errors.
	Logf func(string, ...any)
}

// Snapshot is the versioned, read-only payload exposed to the Agent
// Supervisor. Values are deliberately scalar and bounded so a plugin cannot
// smuggle arbitrary data through the heartbeat metrics map.
type Snapshot struct {
	Metrics          map[string]float64
	ObservedAtUnixMs int64
}

func (s Snapshot) Validate() error {
	if len(s.Metrics) == 0 {
		return errors.New("telemetry snapshot has no metrics")
	}
	if len(s.Metrics) > MaxMetrics {
		return fmt.Errorf("telemetry snapshot has more than %d metrics", MaxMetrics)
	}
	for key, value := range s.Metrics {
		if !validMetricKey(key) {
			return fmt.Errorf("telemetry metric key %q is invalid", key)
		}
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return fmt.Errorf("telemetry metric %q is not finite", key)
		}
	}
	if s.ObservedAtUnixMs <= 0 {
		return errors.New("telemetry snapshot observed_at_unix_ms is required")
	}
	return nil
}

func validMetricKey(key string) bool {
	if key == "" || len(key) > MaxMetricKeyLength {
		return false
	}
	for index, character := range key {
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '.' || character == '-' {
			if index == 0 && character >= '0' && character <= '9' {
				return false
			}
			continue
		}
		return false
	}
	return true
}

func (s Snapshot) toStruct() (*structpb.Struct, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	metrics := make(map[string]*structpb.Value, len(s.Metrics))
	for key, value := range s.Metrics {
		metrics[key] = structpb.NewNumberValue(value)
	}
	return &structpb.Struct{Fields: map[string]*structpb.Value{
		"metrics":             structpb.NewStructValue(&structpb.Struct{Fields: metrics}),
		"observed_at_unix_ms": structpb.NewNumberValue(float64(s.ObservedAtUnixMs)),
	}}, nil
}

func snapshotFromStruct(payload *structpb.Struct) (Snapshot, error) {
	if payload == nil {
		return Snapshot{}, errors.New("telemetry snapshot response is empty")
	}
	metricsValue, ok := payload.Fields["metrics"]
	if !ok || metricsValue.GetStructValue() == nil {
		return Snapshot{}, errors.New("telemetry snapshot metrics are missing")
	}
	metrics := make(map[string]float64, len(metricsValue.GetStructValue().Fields))
	for key, value := range metricsValue.GetStructValue().Fields {
		number, ok := value.Kind.(*structpb.Value_NumberValue)
		if !ok {
			return Snapshot{}, fmt.Errorf("telemetry metric %q is not numeric", key)
		}
		metrics[key] = number.NumberValue
	}
	observedValue, ok := payload.Fields["observed_at_unix_ms"]
	if !ok {
		return Snapshot{}, errors.New("telemetry snapshot observed_at_unix_ms is missing")
	}
	observed := observedValue.GetNumberValue()
	if observed <= 0 || math.IsNaN(observed) || math.IsInf(observed, 0) || math.Trunc(observed) != observed {
		return Snapshot{}, errors.New("telemetry snapshot observed_at_unix_ms is invalid")
	}
	snapshot := Snapshot{Metrics: metrics, ObservedAtUnixMs: int64(observed)}
	if err := snapshot.Validate(); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

type telemetryServer interface {
	Snapshot(context.Context, *emptypb.Empty) (*structpb.Struct, error)
	SystemdServices(context.Context, *emptypb.Empty) (*structpb.Struct, error)
}

func telemetryMethod(name string, call func(telemetryServer, context.Context, *emptypb.Empty) (*structpb.Struct, error)) grpc.MethodDesc {
	return grpc.MethodDesc{
		MethodName: name,
		Handler: func(srv interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
			request := new(emptypb.Empty)
			if err := decoder(request); err != nil {
				return nil, err
			}
			if interceptor == nil {
				return call(srv.(telemetryServer), ctx, request)
			}
			info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + TelemetryServiceName + "/" + name}
			handler := func(ctx context.Context, request any) (any, error) {
				return call(srv.(telemetryServer), ctx, request.(*emptypb.Empty))
			}
			return interceptor(ctx, request, info, handler)
		},
	}
}

// RegisterTelemetryServer registers the stable local RPC without requiring a
// generated protobuf file. The wire messages are standard protobuf Structs,
// allowing the Agent and plugin to evolve independently within API v1.
func RegisterTelemetryServer(registrar grpc.ServiceRegistrar, server telemetryServer) {
	registrar.RegisterService(&grpc.ServiceDesc{
		ServiceName: TelemetryServiceName,
		HandlerType: (*telemetryServer)(nil),
		Methods: []grpc.MethodDesc{
			telemetryMethod(TelemetryMethodName, telemetryServer.Snapshot),
			telemetryMethod(ServicesMethodName, telemetryServer.SystemdServices),
		},
	}, server)
}

type telemetryClient struct{ connection grpc.ClientConnInterface }

// NewTelemetryClient creates an Agent-side client for the local v1 RPC.
func NewTelemetryClient(connection grpc.ClientConnInterface) *telemetryClient {
	return &telemetryClient{connection: connection}
}

func (c *telemetryClient) Snapshot(ctx context.Context) (Snapshot, error) {
	if c == nil || c.connection == nil {
		return Snapshot{}, errors.New("telemetry client connection is unavailable")
	}
	response := new(structpb.Struct)
	if err := c.connection.Invoke(ctx, "/"+TelemetryServiceName+"/"+TelemetryMethodName, &emptypb.Empty{}, response); err != nil {
		return Snapshot{}, err
	}
	return snapshotFromStruct(response)
}

// SystemdServices reads the latest systemd.services report. ok is false when
// the plugin has none to give: collection is off for the node, no sample was
// taken yet, or the plugin predates the collector (Unimplemented).
func (c *telemetryClient) SystemdServices(ctx context.Context) (report ServicesReport, ok bool, err error) {
	if c == nil || c.connection == nil {
		return ServicesReport{}, false, errors.New("telemetry client connection is unavailable")
	}
	response := new(structpb.Struct)
	if err := c.connection.Invoke(ctx, "/"+TelemetryServiceName+"/"+ServicesMethodName, &emptypb.Empty{}, response); err != nil {
		switch status.Code(err) {
		case codes.Unimplemented, codes.FailedPrecondition, codes.Unavailable:
			return ServicesReport{}, false, nil
		}
		return ServicesReport{}, false, err
	}
	report, err = servicesReportFromStruct(response)
	if err != nil {
		return ServicesReport{}, false, err
	}
	return report, true, nil
}

func (r ServicesReport) toStruct() *structpb.Struct {
	return &structpb.Struct{Fields: map[string]*structpb.Value{
		"kind":                structpb.NewStringValue(r.Kind),
		"payload_json":        structpb.NewStringValue(string(r.PayloadJSON)),
		"observed_at_unix_ms": structpb.NewNumberValue(float64(r.ObservedAtUnixMs)),
	}}
}

func servicesReportFromStruct(payload *structpb.Struct) (ServicesReport, error) {
	if payload == nil {
		return ServicesReport{}, errors.New("systemd services response is empty")
	}
	kind := payload.Fields["kind"].GetStringValue()
	if kind != systemdreport.Kind {
		return ServicesReport{}, fmt.Errorf("systemd services response has kind %q", kind)
	}
	body := payload.Fields["payload_json"].GetStringValue()
	if _, err := systemdreport.Sanitize([]byte(body)); err != nil {
		return ServicesReport{}, err
	}
	observed := payload.Fields["observed_at_unix_ms"].GetNumberValue()
	if observed <= 0 || math.IsNaN(observed) || math.IsInf(observed, 0) || math.Trunc(observed) != observed {
		return ServicesReport{}, errors.New("systemd services observed_at_unix_ms is invalid")
	}
	return ServicesReport{Kind: kind, PayloadJSON: []byte(body), ObservedAtUnixMs: int64(observed)}, nil
}

type snapshotStore struct {
	mu       sync.RWMutex
	snapshot Snapshot
}

func (s *snapshotStore) get() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Snapshot{Metrics: cloneMetrics(s.snapshot.Metrics), ObservedAtUnixMs: s.snapshot.ObservedAtUnixMs}
}

func (s *snapshotStore) refresh() {
	info, err := monitor.GetSystemInfo()
	if err != nil || info == nil {
		return
	}
	metrics := map[string]float64{
		"cpu_usage_percent":      info.CPUUsage,
		"memory_usage_percent":   info.MemoryUsage,
		"disk_usage_percent":     info.DiskUsage,
		"process_uptime_seconds": float64(info.Uptime),
	}
	if uptime, err := host.Uptime(); err == nil {
		metrics["uptime_seconds"] = float64(uptime)
	} else {
		metrics["uptime_seconds"] = float64(info.Uptime)
	}
	if counters, err := gopsnet.IOCounters(false); err == nil && len(counters) > 0 {
		metrics["network_bytes_sent"] = float64(counters[0].BytesSent)
		metrics["network_bytes_recv"] = float64(counters[0].BytesRecv)
	}
	if processes, err := process.Processes(); err == nil {
		metrics["process_count"] = float64(len(processes))
	}
	for key, value := range metrics {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			delete(metrics, key)
		}
	}
	if len(metrics) == 0 {
		return
	}
	s.mu.Lock()
	s.snapshot = Snapshot{Metrics: metrics, ObservedAtUnixMs: time.Now().UnixMilli()}
	s.mu.Unlock()
}

func cloneMetrics(metrics map[string]float64) map[string]float64 {
	cloned := make(map[string]float64, len(metrics))
	for key, value := range metrics {
		cloned[key] = value
	}
	return cloned
}

type telemetryRPC struct {
	store *snapshotStore
	// services is nil when collection is off for this node.
	services *ServicesCollector
}

func (r telemetryRPC) SystemdServices(ctx context.Context, _ *emptypb.Empty) (*structpb.Struct, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.services == nil {
		return nil, status.Error(codes.FailedPrecondition, "systemd services collection is not enabled for this node")
	}
	report, ok := r.services.Latest()
	if !ok {
		return nil, status.Error(codes.Unavailable, "no systemd services report has been collected yet")
	}
	return report.toStruct(), nil
}

func (r telemetryRPC) Snapshot(ctx context.Context, _ *emptypb.Empty) (*structpb.Struct, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.store == nil {
		return nil, errors.New("telemetry snapshot store is unavailable")
	}
	snapshot := r.store.get()
	return snapshot.toStruct()
}

// Run serves the versioned reference plugin until ctx is cancelled.
func Run(ctx context.Context, options Options) error {
	if ctx == nil {
		return errors.New("plugin context is required")
	}
	config, err := LoadConfig(options.ConfigPath)
	if err != nil {
		return err
	}
	listener, err := listenUnixSocket(options.SocketPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = removeUnixSocket(options.SocketPath)
	}()

	server := grpc.NewServer()
	store := &snapshotStore{}
	store.refresh()
	rpc := telemetryRPC{store: store}
	collectorCtx, stopCollector := context.WithCancel(ctx)
	collectorDone := make(chan struct{})
	defer func() {
		stopCollector()
		<-collectorDone
	}()
	if node := config.Services.Node(options.NodeID); options.NodeID != 0 && node.Enabled {
		platform := DefaultServicesPlatform()
		if options.ServicesPlatform != nil {
			platform = *options.ServicesPlatform
		}
		rpc.services = NewServicesCollector(platform, node, nil)
		go func() {
			defer close(collectorDone)
			RunServicesCollector(collectorCtx, rpc.services, ServicesCollectInterval, options.Logf)
		}()
	} else {
		close(collectorDone)
	}
	RegisterTelemetryServer(server, rpc)
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus(ID, healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(server, healthServer)

	serveResult := make(chan error, 1)
	go func() {
		serveResult <- server.Serve(listener)
	}()

	ticker := time.NewTicker(config.Interval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			healthServer.Shutdown()
			// A health Watch stream can be long lived. Shutdown must not let a
			// disable operation wait indefinitely for an untrusted local client.
			server.Stop()
			err := <-serveResult
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				return fmt.Errorf("serve plugin health API: %w", err)
			}
			return nil
		case err := <-serveResult:
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				return fmt.Errorf("serve plugin health API: %w", err)
			}
			return nil
		case <-ticker.C:
			store.refresh()
			healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
			healthServer.SetServingStatus(ID, healthpb.HealthCheckResponse_SERVING)
		}
	}
}

func listenUnixSocket(path string) (net.Listener, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("--anixops-socket is required")
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("--anixops-socket must be an absolute path")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("inspect plugin socket directory: %w", err)
	}
	if parent.Mode()&os.ModeSymlink != 0 || !parent.IsDir() {
		return nil, errors.New("plugin socket directory must be a real directory")
	}
	if parent.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("plugin socket directory must not be writable by group or other users")
	}
	if err := removeUnixSocket(path); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on plugin Unix socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = removeUnixSocket(path)
		return nil, fmt.Errorf("protect plugin Unix socket: %w", err)
	}
	return listener, nil
}

func removeUnixSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove non-socket plugin path %q", path)
	}
	return os.Remove(path)
}
