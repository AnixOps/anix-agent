package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/mesh"
)

// `anix-agent mesh takeover` and `anix-agent mesh restore` (docs/mesh.md):
// as root, stop the node's existing mesh program so the Agent's networks
// can start, and bring it back. The names come from the deployment, on the
// command line.

func init() {
	var spec panel.MeshTakeover
	meshCommand := &cobra.Command{Use: "mesh", Short: "Take the node's existing mesh program over, or give it back"}
	takeover := &cobra.Command{
		Use:   "takeover",
		Short: "Stop the existing mesh program (start at boot first, then the services and processes); its files stay",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if os.Geteuid() != 0 {
				return errors.New("mesh takeover needs root")
			}
			if err := (&panel.Mesh{Takeover: &spec}).Validate(); err != nil {
				return err
			}
			if spec.Empty() {
				return errors.New("name the program with --service or --process")
			}
			result := (&mesh.Takeover{}).Stop(&spec)
			if !result.Found {
				fmt.Fprintln(cmd.OutOrStdout(), "No existing mesh program runs.")
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Stopped: %s\nRestore with: anix-agent mesh restore\n", strings.Join(result.Stopped, ", "))
			}
			if result.Error != "" {
				return errors.New(result.Error)
			}
			return nil
		},
	}
	takeover.Flags().StringSliceVar(&spec.ServiceNames, "service", nil, "a systemd service of the program (repeatable)")
	takeover.Flags().StringSliceVar(&spec.ProcessNames, "process", nil, "a process name of the program (repeatable)")
	restore := &cobra.Command{
		Use:   "restore",
		Short: "Start the services the takeover stopped again; stop the node's mesh networks in the panel first",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if os.Geteuid() != 0 {
				return errors.New("mesh restore needs root")
			}
			restored, err := (&mesh.Takeover{}).Restore()
			if len(restored) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "Started: %s\n", strings.Join(restored, ", "))
			}
			return err
		},
	}
	meshCommand.AddCommand(takeover, restore)
	command.AddCommand(meshCommand)
}
