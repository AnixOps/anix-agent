package main

import (
	"os"

	"github.com/AnixOps/anix-agent/v5/cmd"
)

func main() {
	if err := cmd.Run(); err != nil {
		os.Exit(cmd.ExitCode(err))
	}
}
