package cmd

import (
	"fmt"

	"github.com/AnixOps/anix-agent/v4/conf"
	"github.com/spf13/cobra"
)

var validateConfigCommand = cobra.Command{
	Use:   "validate-config",
	Short: "Validate the Agent configuration without starting runtimes",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		loaded := conf.New()
		if err := loaded.LoadFromPath(config); err != nil {
			return err
		}
		fmt.Printf("configuration preflight passed: %s\n", config)
		return nil
	},
}

func init() {
	command.AddCommand(&validateConfigCommand)
}
