package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/AnixOps/anix-agent/v5/plugin/gostmesh"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet(gostmesh.ID, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var socketPath string
	var configPath string
	var statePath string
	var showVersion bool
	var cleanup bool
	var validate bool
	flags.StringVar(&socketPath, "anixops-socket", "", "private Unix socket supplied by the AnixOps Agent")
	flags.StringVar(&configPath, "anixops-config", "", "signed plugin configuration supplied by the AnixOps Agent")
	flags.StringVar(&statePath, "anixops-state", "", "private persistent runtime state supplied by the AnixOps Agent")
	flags.BoolVar(&showVersion, "version", false, "print plugin version")
	flags.BoolVar(&cleanup, "anixops-cleanup", false, "restore an interrupted plugin ownership journal and exit")
	flags.BoolVar(&validate, "anixops-validate", false, "validate the plugin configuration without starting the runtime")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "gost-mesh: positional arguments are not supported")
		return 2
	}
	modeCount := 0
	for _, enabled := range []bool{showVersion, cleanup, validate} {
		if enabled {
			modeCount++
		}
	}
	if modeCount > 1 {
		fmt.Fprintln(os.Stderr, "gost-mesh: --version, --anixops-cleanup, and --anixops-validate are mutually exclusive")
		return 2
	}
	if showVersion {
		fmt.Printf("%s %s (gost %s)\n", gostmesh.ID, gostmesh.Version, gostmesh.GOSTVersion)
		return 0
	}
	if validate {
		if _, err := gostmesh.LoadConfig(configPath); err != nil {
			fmt.Fprintln(os.Stderr, "gost-mesh validation:", err)
			return 1
		}
		return 0
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	options := gostmesh.Options{SocketPath: socketPath, ConfigPath: configPath, StatePath: statePath}
	if cleanup {
		if err := gostmesh.Cleanup(ctx, options); err != nil {
			fmt.Fprintln(os.Stderr, "gost-mesh cleanup:", err)
			return 1
		}
		return 0
	}
	if err := gostmesh.Run(ctx, options); err != nil {
		fmt.Fprintln(os.Stderr, "gost-mesh:", err)
		return 1
	}
	return 0
}
