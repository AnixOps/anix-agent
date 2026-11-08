package plugin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func TestGRPCHealthCheckerOverUnixSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket test")
	}
	socket := filepath.Join(t.TempDir(), "plugin.sock")
	listener, err := unixSocketListener(socket)
	require.NoError(t, err)
	server := grpc.NewServer()
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(server, healthServer)
	go server.Serve(listener)
	t.Cleanup(func() { server.Stop(); _ = listener.Close(); _ = removeSocket(socket) })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, (GRPCHealthChecker{}).Check(ctx, socket))
}

func TestRemoveSocketRefusesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-socket")
	require.NoError(t, os.WriteFile(path, []byte("data"), 0o600))
	require.ErrorContains(t, removeSocket(path), "non-socket")
}

func TestCommandRunnerProcessOutlivesStartupContext(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix process test")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "plugin")
	require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\ntrap 'exit 0' INT TERM\ntouch \"$0.ready\"\nwhile :; do sleep 1; done\n"), 0o750))

	startupCtx, cancelStartup := context.WithCancel(context.Background())
	process, err := (CommandRunner{}).Start(startupCtx, binary, filepath.Join(dir, "plugin.sock"), filepath.Join(dir, "config.json"))
	require.NoError(t, err)
	cancelStartup()
	// Stop sends SIGINT; wait until the script has installed its trap.
	require.Eventually(t, func() bool { _, err := os.Stat(binary + ".ready"); return err == nil }, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, syscall.Kill(process.PID(), 0), "cancelling startup must not kill the long-lived plugin")

	stopCtx, cancelStop := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelStop()
	require.NoError(t, process.Stop(stopCtx))
	require.NoError(t, process.Stop(stopCtx), "Stop must remain idempotent after Wait completion was observed")
}

func TestCommandRunnerReportsUnexpectedProcessExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix process test")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "plugin")
	require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\nexit 23\n"), 0o750))
	process, err := (CommandRunner{}).Start(context.Background(), binary, filepath.Join(dir, "plugin.sock"), filepath.Join(dir, "config.json"))
	require.NoError(t, err)
	watcher, ok := process.(ProcessExitWatcher)
	require.True(t, ok)
	select {
	case exitErr := <-watcher.Exited():
		require.Error(t, exitErr)
		require.ErrorContains(t, exitErr, "exit status 23")
	case <-time.After(2 * time.Second):
		t.Fatal("CommandRunner did not report process exit")
	}
}

func TestCommandRunnerStopReportsSuccessAfterForcedKill(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix process test")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "plugin")
	ready := filepath.Join(dir, "ready")
	script := fmt.Sprintf("#!/bin/sh\ntrap '' INT TERM\n: > %q\nwhile :; do sleep 1; done\n", ready)
	require.NoError(t, os.WriteFile(binary, []byte(script), 0o750))
	process, err := (CommandRunner{}).Start(context.Background(), binary, filepath.Join(dir, "plugin.sock"), filepath.Join(dir, "config.json"))
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		_, statErr := os.Stat(ready)
		return statErr == nil
	}, time.Second, 10*time.Millisecond)
	stopCtx, cancelStop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelStop()
	require.NoError(t, process.Stop(stopCtx), "a killed process is stopped successfully even when graceful shutdown timed out")
}

func TestCommandRunnerStopReportsPluginCleanupFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix process test")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "plugin")
	ready := filepath.Join(dir, "ready")
	script := fmt.Sprintf("#!/bin/sh\ntrap 'exit 17' INT TERM\n: > %q\nwhile :; do sleep 1; done\n", ready)
	require.NoError(t, os.WriteFile(binary, []byte(script), 0o750))
	process, err := (CommandRunner{}).Start(context.Background(), binary, filepath.Join(dir, "plugin.sock"), filepath.Join(dir, "config.json"))
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		_, statErr := os.Stat(ready)
		return statErr == nil
	}, time.Second, 10*time.Millisecond)
	stopCtx, cancelStop := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelStop()
	err = process.Stop(stopCtx)
	require.ErrorContains(t, err, "exit status 17")
}
