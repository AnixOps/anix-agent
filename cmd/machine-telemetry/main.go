package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/AnixOps/anix-agent/v4/plugin/machinetelemetry"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet(machinetelemetry.ID, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var socketPath string
	var configPath string
	var showVersion bool
	flags.StringVar(&socketPath, "anixops-socket", "", "private Unix socket supplied by the AnixOps Agent")
	flags.StringVar(&configPath, "anixops-config", "", "signed plugin configuration supplied by the AnixOps Agent")
	flags.BoolVar(&showVersion, "version", false, "print plugin version")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "machine-telemetry: positional arguments are not supported")
		return 2
	}
	if showVersion {
		fmt.Printf("%s %s\n", machinetelemetry.ID, machinetelemetry.Version)
		return 0
	}

	// The Agent names the node this instance serves; the systemd services
	// collector reads only that node's settings and stays off without it.
	nodeID, err := machinetelemetry.ParseNodeID(os.Getenv(machinetelemetry.NodeIDEnvironment))
	if err != nil {
		fmt.Fprintf(os.Stderr, "machine-telemetry: ignoring %s: %v; systemd services collection stays off\n", machinetelemetry.NodeIDEnvironment, err)
		nodeID = 0
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := machinetelemetry.Run(ctx, machinetelemetry.Options{
		SocketPath: socketPath,
		ConfigPath: configPath,
		NodeID:     nodeID,
		Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "machine-telemetry: "+format+"\n", args...)
		},
	}); err != nil {
		fmt.Fprintln(os.Stderr, "machine-telemetry:", err)
		return 1
	}
	return 0
}
