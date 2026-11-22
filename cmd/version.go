package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is the release tag; release builds set it through -ldflags.
var version = "v5.0.8"

func init() {
	command.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(c *cobra.Command, _ []string) {
			fmt.Fprintln(c.OutOrStdout(), versionLine())
		},
	})
}

func versionLine() string {
	return productName + " " + version
}
