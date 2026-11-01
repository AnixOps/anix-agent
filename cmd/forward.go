package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// The installer's inputs for forward-capable nodes (forward-sdk.md
// sections 6.1, 6.2, 9 and 14): the sysctl drop-in that lets the kernel
// forward.

// ForwardSysctlDropIn is /etc/sysctl.d/90-anixops-forward.conf: nftables
// DNAT forwards only when the kernel does, and QUIC carriers (anx-server's
// --quic-sockbuf) want 8 MiB of UDP socket buffer,
// which an unprivileged process gets only up to net.core.rmem_max and
// wmem_max. The
// installer writes it; the Agent only warns at start when forwarding is off.
const ForwardSysctlDropIn = `# Written by the AnixOps Agent installer for forwarding (nftables DNAT, QUIC links).
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
`

var forwardCommand = &cobra.Command{
	Use:    "forward",
	Short:  "Forwarding helpers for the installer",
	Hidden: true,
}

func init() {
	forwardCommand.AddCommand(&cobra.Command{
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
