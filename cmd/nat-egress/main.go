package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/AnixOps/anix-agent/v5/plugin/nategress"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet(nategress.ID, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var socketPath string
	var configPath string
	var statePath string
	var showVersion bool
	var cleanup bool
	flags.StringVar(&socketPath, "anixops-socket", "", "private Unix socket supplied by the AnixOps Agent")
	flags.StringVar(&configPath, "anixops-config", "", "signed plugin configuration supplied by the AnixOps Agent")
	flags.StringVar(&statePath, "anixops-state", "", "private persistent runtime state supplied by the AnixOps Agent")
	flags.BoolVar(&showVersion, "version", false, "print plugin version")
	flags.BoolVar(&cleanup, "anixops-cleanup", false, "restore an interrupted plugin ownership journal and exit")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "nat-egress: positional arguments are not supported")
		return 2
	}
	if showVersion {
		fmt.Printf("%s %s\n", nategress.ID, nategress.Version)
		return 0
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if cleanup {
		if err := nategress.Cleanup(ctx, nategress.Options{SocketPath: socketPath, StatePath: statePath}); err != nil {
			fmt.Fprintln(os.Stderr, "nat-egress cleanup:", err)
			return 1
		}
		return 0
	}
	if err := nategress.Run(ctx, nategress.Options{
		SocketPath: socketPath,
		ConfigPath: configPath,
		StatePath:  statePath,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "nat-egress:", err)
		return 1
	}
	return 0
}
