package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is the release; release builds set it with
// -ldflags "-X github.com/AnixOps/anix-agent/v5/cmd.version=<tag>".
var version = "v5.0.10"

func init() {
	command.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", productName, version)
		},
	})
}
