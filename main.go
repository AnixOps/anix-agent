package main

import (
	"os"

	"github.com/AnixOps/anix-agent/v4/cmd"
)

func main() {
	if err := cmd.Run(); err != nil {
		os.Exit(1)
	}
}
