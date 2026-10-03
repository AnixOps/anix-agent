package machinetelemetry

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const DefaultClientTimeout = 2 * time.Second

// FetchSnapshot reads one bounded snapshot from a Supervisor-owned Unix
// socket. The caller controls the parent deadline; timeout only supplies a
// finite default for heartbeat paths that do not already have one.
func FetchSnapshot(ctx context.Context, socketPath string, timeout time.Duration) (Snapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if runtime.GOOS == "windows" {
		return Snapshot{}, errors.New("plugin telemetry Unix sockets are not supported on Windows")
	}
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" || !filepath.IsAbs(socketPath) {
		return Snapshot{}, errors.New("plugin telemetry socket must be an absolute path")
	}
	if timeout <= 0 {
		timeout = DefaultClientTimeout
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	connection, err := grpc.DialContext(
		dialCtx,
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return Snapshot{}, fmt.Errorf("dial plugin telemetry socket: %w", err)
	}
	defer connection.Close()
	snapshot, err := NewTelemetryClient(connection).Snapshot(dialCtx)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read plugin telemetry snapshot: %w", err)
	}
	return snapshot, nil
}

// FetchSystemdServices reads the latest systemd.services report from a
// Supervisor-owned Unix socket. ok is false when the plugin has none to
// give (collection off for the node, nothing collected yet, or a plugin
// before the collector); the caller then sends nothing.
func FetchSystemdServices(ctx context.Context, socketPath string, timeout time.Duration) (report ServicesReport, ok bool, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return ServicesReport{}, false, err
	}
	if runtime.GOOS == "windows" {
		return ServicesReport{}, false, errors.New("plugin telemetry Unix sockets are not supported on Windows")
	}
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" || !filepath.IsAbs(socketPath) {
		return ServicesReport{}, false, errors.New("plugin telemetry socket must be an absolute path")
	}
	if timeout <= 0 {
		timeout = DefaultClientTimeout
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	connection, err := grpc.DialContext(
		dialCtx,
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return ServicesReport{}, false, fmt.Errorf("dial plugin telemetry socket: %w", err)
	}
	defer connection.Close()
	report, ok, err = NewTelemetryClient(connection).SystemdServices(dialCtx)
	if err != nil {
		return ServicesReport{}, false, fmt.Errorf("read plugin systemd services report: %w", err)
	}
	return report, ok, nil
}
