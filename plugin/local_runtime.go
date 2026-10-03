package plugin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// NodeIDEnvironment carries the Agent's node id to plugin processes
// (machinetelemetry.NodeIDEnvironment). An environment variable rather
// than a flag keeps older plugin binaries, which refuse unknown flags,
// startable.
const NodeIDEnvironment = "ANIXOPS_NODE_ID"

// CommandRunner starts one signed plugin binary. Plugin binaries must expose
// the standard gRPC health service on the supplied Unix socket.
type CommandRunner struct {
	ExtraArgs []string
	// NodeID, when positive, is set as ANIXOPS_NODE_ID in the plugin's
	// environment; an inherited value is never passed on.
	NodeID int
}

// environment is the plugin process environment: the Agent's, without an
// inherited ANIXOPS_NODE_ID, with the runner's node id.
func (r CommandRunner) environment() []string {
	inherited := os.Environ()
	environment := make([]string, 0, len(inherited)+1)
	for _, entry := range inherited {
		if strings.HasPrefix(entry, NodeIDEnvironment+"=") {
			continue
		}
		environment = append(environment, entry)
	}
	if r.NodeID > 0 {
		environment = append(environment, NodeIDEnvironment+"="+strconv.Itoa(r.NodeID))
	}
	return environment
}

func (r CommandRunner) Start(ctx context.Context, binaryPath, socketPath, configPath string) (Process, error) {
	return r.start(ctx, binaryPath, socketPath, configPath, "")
}

func (r CommandRunner) StartWithState(ctx context.Context, binaryPath, socketPath, configPath, statePath string) (Process, error) {
	return r.start(ctx, binaryPath, socketPath, configPath, statePath)
}

func (r CommandRunner) start(ctx context.Context, binaryPath, socketPath, configPath, statePath string) (Process, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if runtime.GOOS == "windows" {
		return nil, errors.New("plugin Unix-socket runtime is not supported on Windows")
	}
	if err := removeSocket(socketPath); err != nil {
		return nil, err
	}
	args := append([]string(nil), r.ExtraArgs...)
	args = append(args, "--anixops-socket", socketPath, "--anixops-config", configPath)
	if statePath != "" {
		args = append(args, "--anixops-state", statePath)
	}
	// The operation context only bounds startup and health verification. The
	// plugin process must outlive the operation that enabled it and is stopped
	// explicitly by disable, update, rollback, or Supervisor.Close.
	command := exec.Command(binaryPath, args...)
	command.Env = r.environment()
	configurePluginCommand(command)
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start plugin process: %w", err)
	}
	process := &commandProcess{command: command, done: make(chan struct{}), exited: make(chan error, 1)}
	go func() {
		waitErr := command.Wait()
		process.waitMu.Lock()
		process.waitErr = waitErr
		process.waitMu.Unlock()
		process.exited <- waitErr
		close(process.exited)
		close(process.done)
	}()
	return process, nil
}

func (r CommandRunner) Cleanup(ctx context.Context, binaryPath, socketPath, configPath, statePath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	args := append([]string(nil), r.ExtraArgs...)
	args = append(args,
		"--anixops-cleanup",
		"--anixops-socket", socketPath,
		"--anixops-config", configPath,
	)
	if statePath != "" {
		args = append(args, "--anixops-state", statePath)
	}
	output, err := exec.CommandContext(ctx, binaryPath, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("run plugin cleanup: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

type commandProcess struct {
	command   *exec.Cmd
	done      chan struct{}
	exited    chan error
	signal    sync.Once
	signalErr error
	waitMu    sync.RWMutex
	waitErr   error
	forced    bool
}

func (p *commandProcess) PID() int {
	if p == nil || p.command == nil || p.command.Process == nil {
		return 0
	}
	return p.command.Process.Pid
}

func (p *commandProcess) Exited() <-chan error {
	if p == nil {
		closed := make(chan error)
		close(closed)
		return closed
	}
	return p.exited
}

func (p *commandProcess) Stop(ctx context.Context) error {
	if p == nil || p.command == nil || p.command.Process == nil {
		return nil
	}
	p.signal.Do(func() { p.signalErr = p.command.Process.Signal(os.Interrupt) })
	if p.signalErr != nil && !errors.Is(p.signalErr, os.ErrProcessDone) {
		return p.signalErr
	}
	select {
	case <-p.done:
		return p.result()
	case <-ctx.Done():
		select {
		case <-p.done:
			return p.result()
		default:
		}
		p.waitMu.Lock()
		p.forced = true
		p.waitMu.Unlock()
		if err := p.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		select {
		case <-p.done:
			return nil
		case <-time.After(time.Second):
			return ctx.Err()
		}
	}
}

func (p *commandProcess) result() error {
	p.waitMu.RLock()
	defer p.waitMu.RUnlock()
	if p.forced {
		return nil
	}
	return p.waitErr
}

type GRPCHealthChecker struct {
	Service string
	Timeout time.Duration
}

func (h GRPCHealthChecker) Check(ctx context.Context, socketPath string) error {
	if runtime.GOOS == "windows" {
		return errors.New("plugin Unix-socket health checks are not supported on Windows")
	}
	timeout := h.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	connection, err := grpc.DialContext(dialCtx, "unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return fmt.Errorf("dial plugin health socket: %w", err)
	}
	defer connection.Close()
	client := healthpb.NewHealthClient(connection)
	var lastErr error
	for {
		response, err := client.Check(dialCtx, &healthpb.HealthCheckRequest{Service: h.Service})
		if err == nil && response.Status == healthpb.HealthCheckResponse_SERVING {
			return nil
		}
		if err != nil {
			lastErr = fmt.Errorf("check plugin health: %w", err)
		} else {
			lastErr = fmt.Errorf("plugin health state is %s", response.Status.String())
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-dialCtx.Done():
			timer.Stop()
			return errors.Join(lastErr, dialCtx.Err())
		case <-timer.C:
		}
	}
}

func removeSocket(path string) error {
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

func unixSocketListener(path string) (net.Listener, error) {
	if runtime.GOOS == "windows" {
		return nil, errors.New("Unix sockets are not supported on Windows")
	}
	if err := removeSocket(path); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = removeSocket(path)
		return nil, err
	}
	return listener, nil
}
