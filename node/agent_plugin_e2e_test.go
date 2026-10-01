package node

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	"github.com/AnixOps/anix-agent/v4/conf"
	"github.com/AnixOps/anix-agent/v4/plugin"
	"github.com/AnixOps/anix-agent/v4/plugin/machinetelemetry"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	agentPluginE2ENodeID = uint32(77)
	agentPluginE2EAPIKey = "agent-plugin-e2e-key"
)

type e2eHealthGate struct {
	delegate plugin.HealthChecker

	mu      sync.Mutex
	block   bool
	entered chan struct{}
	release chan struct{}
}

func (g *e2eHealthGate) BlockNext() (<-chan struct{}, chan<- struct{}) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.block = true
	g.entered = make(chan struct{})
	g.release = make(chan struct{})
	return g.entered, g.release
}

func (g *e2eHealthGate) Check(ctx context.Context, socketPath string) error {
	g.mu.Lock()
	block := g.block
	entered := g.entered
	release := g.release
	if block {
		g.block = false
	}
	g.mu.Unlock()
	if block {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return g.delegate.Check(ctx, socketPath)
}

type e2eControlServer struct {
	agentv1pb.UnimplementedAgentControlServiceServer
	nodeID uint32
	apiKey string
	gate   *e2eHealthGate

	sessions      atomic.Int32
	firstErr      chan error
	firstTerminal chan *agentv1pb.ObservedState
	replayDone    chan *agentv1pb.ObservedState
}

func newE2EControlServer(gate *e2eHealthGate) *e2eControlServer {
	return &e2eControlServer{
		nodeID: agentPluginE2ENodeID, apiKey: agentPluginE2EAPIKey, gate: gate,
		firstErr: make(chan error, 1), firstTerminal: make(chan *agentv1pb.ObservedState, 1),
		replayDone: make(chan *agentv1pb.ObservedState, 1),
	}
}

func (s *e2eControlServer) ControlStream(stream agentv1pb.AgentControlService_ControlStreamServer) error {
	if err := s.authenticate(stream.Context()); err != nil {
		return err
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil || hello.Protocol != agentapi.ProtocolVersion {
		return status.Error(codes.FailedPrecondition, "invalid agent hello")
	}
	if !hasE2ECapability(hello.Capabilities, "operation.cancel", "v1") {
		return status.Error(codes.FailedPrecondition, "operation.cancel capability is required")
	}
	sessionNumber := s.sessions.Add(1)
	sessionID := fmt.Sprintf("machine-e2e-session-%d", sessionNumber)
	helloAck := &agentv1pb.ControlToAgent{
		RequestId: first.RequestId, NodeId: s.nodeID, SentAtUnixMs: time.Now().UnixMilli(),
		Payload: &agentv1pb.ControlToAgent_HelloAck{HelloAck: &agentv1pb.HelloAck{
			SessionId: sessionID, DesiredRevision: map[int32]uint64{1: 0, 2: 3}[sessionNumber],
		}},
	}
	if err := stream.Send(helloAck); err != nil {
		return err
	}
	if sessionNumber == 1 {
		err := s.runFirstSession(stream, sessionID)
		s.firstErr <- err
		return err
	}
	return s.runReplaySession(stream, sessionID)
}

func (s *e2eControlServer) authenticate(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(md.Get("x-node-id")) == 0 || len(md.Get("x-api-key")) == 0 {
		return status.Error(codes.Unauthenticated, "agent credentials are required")
	}
	if md.Get("x-node-id")[0] != strconv.FormatUint(uint64(s.nodeID), 10) || md.Get("x-api-key")[0] != s.apiKey {
		return status.Error(codes.Unauthenticated, "agent credentials are invalid")
	}
	return nil
}

func (s *e2eControlServer) runFirstSession(stream agentv1pb.AgentControlService_ControlStreamServer, sessionID string) error {
	configure := &agentv1pb.DesiredOperation{
		OperationId: "machine-e2e-configure", Kind: "plugin.configure", Revision: 1,
		PayloadJson: e2eOperationEnvelope("machine-e2e-configure", "configure-key", sessionID, 1, "machine-telemetry", machinetelemetry.Version, []byte(`{"interval_seconds":60}`)),
	}
	if err := s.sendDesired(stream, configure); err != nil {
		return err
	}
	if _, err := waitE2EOperation(stream, configure.OperationId, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED, false); err != nil {
		return err
	}

	enable := &agentv1pb.DesiredOperation{
		OperationId: "machine-e2e-enable", Kind: "plugin.enable", Revision: 2,
		PayloadJson: e2eOperationEnvelope("machine-e2e-enable", "enable-key", sessionID, 2, "machine-telemetry", machinetelemetry.Version, []byte(`{}`)),
	}
	if err := s.sendDesired(stream, enable); err != nil {
		return err
	}
	if _, err := waitE2EOperation(stream, enable.OperationId, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED, false); err != nil {
		return err
	}

	health := &agentv1pb.DesiredOperation{
		OperationId: "machine-e2e-health-cancel", Kind: "plugin.health", Revision: 3,
		PayloadJson: e2eOperationEnvelope("machine-e2e-health-cancel", "health-key", sessionID, 3, "machine-telemetry", machinetelemetry.Version, []byte(`{}`)),
	}
	entered, _ := s.gate.BlockNext()
	if err := s.sendDesired(stream, health); err != nil {
		return err
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		return errors.New("machine telemetry health operation did not enter cancellation gate")
	}
	terminal, err := s.cancelAndWait(stream, health)
	if err != nil {
		return err
	}
	s.firstTerminal <- terminal
	return io.EOF
}

func (s *e2eControlServer) runReplaySession(stream agentv1pb.AgentControlService_ControlStreamServer, sessionID string) error {
	replay := &agentv1pb.DesiredOperation{
		OperationId: "machine-e2e-health-cancel", Kind: "plugin.health", Revision: 3,
		PayloadJson: e2eOperationEnvelope("machine-e2e-health-cancel", "health-key", sessionID, 3, "machine-telemetry", machinetelemetry.Version, []byte(`{}`)),
	}
	if err := s.sendDesired(stream, replay); err != nil {
		return err
	}
	terminal, err := waitE2EOperation(stream, replay.OperationId, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUPERSEDED, false)
	if err != nil {
		return err
	}
	s.replayDone <- terminal
	return io.EOF
}

func (s *e2eControlServer) sendDesired(stream agentv1pb.AgentControlService_ControlStreamServer, operation *agentv1pb.DesiredOperation) error {
	return stream.Send(&agentv1pb.ControlToAgent{
		RequestId: "desired-" + operation.OperationId, NodeId: s.nodeID, Revision: operation.Revision,
		SentAtUnixMs: time.Now().UnixMilli(),
		Payload:      &agentv1pb.ControlToAgent_DesiredOperation{DesiredOperation: proto.Clone(operation).(*agentv1pb.DesiredOperation)},
	})
}

func (s *e2eControlServer) cancelAndWait(stream agentv1pb.AgentControlService_ControlStreamServer, operation *agentv1pb.DesiredOperation) (*agentv1pb.ObservedState, error) {
	if err := s.sendDesired(stream, &agentv1pb.DesiredOperation{
		OperationId: operation.OperationId, Kind: "operation.cancel", Revision: operation.Revision,
	}); err != nil {
		return nil, err
	}
	return waitE2EOperation(stream, operation.OperationId, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUPERSEDED, true)
}

func waitE2EOperation(stream agentv1pb.AgentControlService_ControlStreamServer, operationID string, phase agentv1pb.ObservedPhase, cancellation bool) (*agentv1pb.ObservedState, error) {
	ack := false
	cancelAck := !cancellation
	var terminal *agentv1pb.ObservedState
	for !ack || !cancelAck || terminal == nil {
		message, err := stream.Recv()
		if err != nil {
			return nil, err
		}
		if operationAck := message.GetOperationAck(); operationAck != nil && operationAck.OperationId == operationID {
			if !operationAck.Accepted {
				return nil, fmt.Errorf("operation %s was rejected: %s", operationID, operationAck.Error)
			}
			if cancellation && !cancelAck {
				cancelAck = true
			} else {
				ack = true
			}
		}
		if observed := message.GetObservedState(); observed != nil && observed.OperationId == operationID && observed.Phase == phase {
			terminal = proto.Clone(observed).(*agentv1pb.ObservedState)
		}
	}
	return terminal, nil
}

func hasE2ECapability(capabilities []*agentv1pb.Capability, name, version string) bool {
	return agentcontrol.HasCapabilityVersion(capabilities, name, version)
}

func e2eOperationEnvelope(operationID, idempotencyKey, sessionID string, revision uint64, pluginID, targetVersion string, config []byte) []byte {
	digest := sha256.Sum256(config)
	envelope := agentapi.OperationEnvelope{
		Version: agentapi.OperationEnvelopeVersion, OperationID: operationID, IdempotencyKey: idempotencyKey,
		SessionID: sessionID, Revision: revision, PluginID: pluginID, TargetVersion: targetVersion,
		ConfigHash: hex.EncodeToString(digest[:]), Config: json.RawMessage(config),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		panic(err)
	}
	return encoded
}

func TestAgentClientControllerSupervisorMachineTelemetryE2E(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix plugin process E2E")
	}
	if testing.Short() {
		t.Skip("builds and launches the reference plugin")
	}

	root := t.TempDir()
	buildDir := filepath.Join(root, "build")
	require.NoError(t, os.MkdirAll(buildDir, 0o700))
	binaryPath := filepath.Join(buildDir, "machine-telemetry")
	build := exec.Command("go", "build", "-o", binaryPath, "./cmd/machine-telemetry")
	_, sourceFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	build.Dir = filepath.Dir(filepath.Dir(sourceFile))
	build.Env = append(os.Environ(), "GOWORK=off", "GOEXPERIMENT=jsonv2")
	output, err := build.CombinedOutput()
	require.NoError(t, err, string(output))
	binary, err := os.ReadFile(binaryPath)
	require.NoError(t, err)

	entrypoint := filepath.ToSlash(filepath.Join("agent", runtime.GOOS+"-"+runtime.GOARCH, "plugin"))
	artifact := makeE2EPackage(t, entrypoint, binary)
	artifactDigest := sha256.Sum256(artifact)
	manifest := plugin.Manifest{
		ID: "machine-telemetry", Name: "Machine Telemetry", Version: machinetelemetry.Version, APIVersion: "v1", Publisher: "AnixOps",
		Targets: []string{"agent"}, Architectures: []string{runtime.GOOS + "/" + runtime.GOARCH},
		ArtifactSHA256: hex.EncodeToString(artifactDigest[:]), Capabilities: []string{"telemetry.read"},
		ConfigSchema: json.RawMessage(`{"additionalProperties":false,"properties":{"interval_seconds":{"maximum":3600,"minimum":5,"type":"integer"}},"type":"object"}`),
		Entrypoints:  map[string]string{"agent-" + runtime.GOOS + "-" + runtime.GOARCH: entrypoint},
	}
	canonical, err := plugin.CanonicalManifest(manifest)
	require.NoError(t, err)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))

	socketDir, err := os.MkdirTemp("", "anix-e2e-sock-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	gate := &e2eHealthGate{delegate: plugin.GRPCHealthChecker{Timeout: 3 * time.Second}}
	supervisor, err := plugin.NewSupervisor(plugin.Config{
		RootDir: filepath.Join(root, "state"), SocketDir: socketDir, PublicKey: publicKey, Health: gate,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = supervisor.Close(context.Background()) })
	_, err = supervisor.Install(context.Background(), plugin.InstallRequest{
		ManifestJSON: string(canonical), Signature: signature, Artifact: artifact,
	})
	require.NoError(t, err)

	controller := &Controller{
		apiClient: &errorTestNodeAPI{}, server: &errorTestCore{}, Options: &conf.Options{}, pluginSupervisor: supervisor,
	}
	var handlerCalls atomic.Int32
	control := newE2EControlServer(gate)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	grpcServer := grpc.NewServer()
	agentv1pb.RegisterAgentControlServiceServer(grpcServer, control)
	serverErr := make(chan error, 1)
	go func() { serverErr <- grpcServer.Serve(listener) }()
	t.Cleanup(func() {
		grpcServer.Stop()
		select {
		case <-serverErr:
		case <-time.After(time.Second):
		}
	})

	client, err := agentapi.NewClient(agentapi.Config{
		Target: listener.Addr().String(), NodeID: int(agentPluginE2ENodeID), APIKey: agentPluginE2EAPIKey,
		AgentVersion: "machine-e2e-agent", InstanceID: "machine-e2e-instance",
		Capabilities: []*agentv1pb.Capability{
			{Name: "agent.control", Version: agentcontrol.CapabilityVersionV1}, {Name: "operation.cancel", Version: agentcontrol.CapabilityVersionV1},
			{Name: "plugin.configure", Version: agentcontrol.CapabilityVersionV1}, {Name: "plugin.enable", Version: agentcontrol.CapabilityVersionV1}, {Name: "plugin.health", Version: agentcontrol.CapabilityVersionV1},
		},
		Handler: agentapi.OperationHandlerFunc(func(ctx context.Context, operation *agentv1pb.DesiredOperation) (json.RawMessage, error) {
			handlerCalls.Add(1)
			return controller.handleAgentOperation(ctx, operation)
		}),
		ReconnectMin: 20 * time.Millisecond, ReconnectMax: 100 * time.Millisecond,
		Heartbeat: 5 * time.Second,
	})
	require.NoError(t, err)
	require.NoError(t, client.Start())
	t.Cleanup(func() { _ = client.Close() })

	select {
	case <-client.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("Agent client did not connect to Control harness")
	}
	select {
	case firstErr := <-control.firstErr:
		require.ErrorIs(t, firstErr, io.EOF)
	case <-time.After(15 * time.Second):
		t.Fatal("first Control session did not complete configure/enable/cancel")
	}
	select {
	case terminal := <-control.firstTerminal:
		require.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUPERSEDED, terminal.Phase)
		require.Equal(t, "operation cancelled", terminal.Message)
	case <-time.After(time.Second):
		t.Fatal("first cancellation terminal was not captured")
	}
	select {
	case replayed := <-control.replayDone:
		require.Equal(t, "machine-e2e-health-cancel", replayed.OperationId)
		require.Equal(t, uint64(3), replayed.Revision)
		require.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUPERSEDED, replayed.Phase)
	case <-time.After(15 * time.Second):
		t.Fatal("Control reconnect replay did not complete")
	}
	require.Equal(t, int32(3), handlerCalls.Load(), "replay must be served from Agent completed cache")
	require.NoError(t, client.Close())

	socketPath := filepath.Join(socketDir, "machine-telemetry.sock")
	healthCtx, cancelHealth := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelHealth()
	// The cancelled health operation intentionally records an unhealthy probe;
	// the independently running process must still expose its local health API.
	require.NoError(t, (plugin.GRPCHealthChecker{Timeout: time.Second}).Check(healthCtx, socketPath))
}

func makeE2EPackage(t *testing.T, entrypoint string, binary []byte) []byte {
	t.Helper()
	var artifact bytes.Buffer
	writer := zip.NewWriter(&artifact)
	file, err := writer.Create(entrypoint)
	require.NoError(t, err)
	_, err = file.Write(binary)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return artifact.Bytes()
}
