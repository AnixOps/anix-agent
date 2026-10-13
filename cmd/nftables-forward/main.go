package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/AnixOps/anix-agent/v5/plugin/nftablesforward"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet(nftablesforward.ID, flag.ContinueOnError)
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
	flags.BoolVar(&validate, "anixops-validate", false, "validate the signed plugin configuration and exit")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "nftables-forward: positional arguments are not supported")
		return 2
	}
	if showVersion && (cleanup || validate) || cleanup && validate {
		fmt.Fprintln(os.Stderr, "nftables-forward: --version, --anixops-cleanup, and --anixops-validate are mutually exclusive")
		return 2
	}
	if showVersion {
		fmt.Printf("%s %s\n", nftablesforward.ID, nftablesforward.Version)
		return 0
	}
	if validate {
		if _, err := nftablesforward.LoadConfig(configPath); err != nil {
			fmt.Fprintln(os.Stderr, "nftables-forward validate:", err)
			return 1
		}
		return 0
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if cleanup {
		if err := nftablesforward.Cleanup(ctx, nftablesforward.Options{
			SocketPath: socketPath,
			ConfigPath: configPath,
			StatePath:  statePath,
		}); err != nil {
			fmt.Fprintln(os.Stderr, "nftables-forward cleanup:", err)
			return 1
		}
		return 0
	}
	if err := nftablesforward.Run(ctx, nftablesforward.Options{
		SocketPath: socketPath,
		ConfigPath: configPath,
		StatePath:  statePath,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "nftables-forward:", err)
		return 1
	}
	return 0
}
