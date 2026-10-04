package cmd

import (
	"fmt"

	"github.com/AnixOps/anix-control/sdk/forward/driver/gost"
	"github.com/spf13/cobra"
)

// The installer's inputs for forward-capable nodes (forward-sdk.md
// sections 6.1, 6.2, 9 and 14; owner decisions H13 and H20): the gost unit
// the Agent manages, and the sysctl drop-in that lets the kernel forward.

// ForwardSysctlDropIn is /etc/sysctl.d/90-anixops-forward.conf: nftables
// DNAT forwards only when the kernel does. The installer writes it; the
// Agent only warns at start when forwarding is off.
const ForwardSysctlDropIn = `# Written by the AnixOps Agent installer for forwarding (nftables DNAT).
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
`

var forwardCommand = &cobra.Command{
	Use:    "forward",
	Short:  "Forwarding helpers for the installer",
	Hidden: true,
}

func init() {
	forwardCommand.AddCommand(&cobra.Command{
		Use:   "gost-unit",
		Short: "Print anixops-gost.service, the gost unit the Agent manages",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			unit, err := gost.UnitFile(gost.DefaultUnit())
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(unit)
			return err
		},
	}, &cobra.Command{
		Use:     "sysctl",
		Aliases: []string{"sysctl-dropin"},
		Short:   "Print the sysctl drop-in that lets the kernel forward (/etc/sysctl.d/90-anixops-forward.conf)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprint(cmd.OutOrStdout(), ForwardSysctlDropIn)
			return err
		},
	})
	command.AddCommand(forwardCommand)
}
