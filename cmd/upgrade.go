package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/upgrade"
	"github.com/spf13/cobra"
)

var (
	upgradeRequest   string
	upgradeLibDir    string
	upgradeSystemctl string
	upgradeUnit      string
)

// upgradeCommand groups the privileged updater's side of Control-pushed
// upgrades (upgrade.v1, O4).
var upgradeCommand = &cobra.Command{
	Use:   "upgrade",
	Short: "Apply Control-pushed Agent upgrades (run by anixops-agent-updater.service)",
}

// upgradeApplyCommand is the ExecStart of anixops-agent-updater.service, a
// root oneshot that anixops-agent-updater.path starts when the Agent hands
// off an upgrade or a rollback. It is not for operators: an Agent never
// upgrades on its own, Control pushes upgrades in batches.
var upgradeApplyCommand = &cobra.Command{
	Use:   "apply",
	Short: "Apply the upgrade request the Agent handed off (for anixops-agent-updater.service)",
	Long: `Consumes the request the Agent wrote (` + upgrade.DefaultDir + `/` + upgrade.RequestFile + `),
verifies the staged release again (size, SHA-256, the Ed25519 signature with
the official release key compiled into this binary), refuses a downgrade
other than a rollback to the kept release, checks the new binary's version,
keeps the installed binary as ` + upgrade.PrevBinary + `, swaps the new one in and
restarts ` + upgrade.AgentUnit + `. When the new Agent does not stay active for
30 seconds the previous binary is reinstated. ` + upgrade.GostUnit + ` is never
restarted. The outcome goes to ` + upgrade.ResultFile + ` next to the request.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if os.Geteuid() != 0 && upgradeLibDir == upgrade.DefaultLibDir {
			return fmt.Errorf("upgrade apply runs as root (anixops-agent-updater.service)")
		}
		applier := &upgrade.Applier{
			Request: upgradeRequest, LibDir: upgradeLibDir, Version: panel.Version,
			Systemctl: upgradeSystemctl, Unit: upgradeUnit,
		}
		result, err := applier.Apply(cmd.Context())
		if errors.Is(err, upgrade.ErrNoRequest) {
			fmt.Fprintln(cmd.OutOrStdout(), "no upgrade request")
			return nil
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s %s: %s\n", result.Action, result.TargetVersion, result.Outcome)
		return err
	},
}

func init() {
	upgradeApplyCommand.Flags().StringVar(&upgradeRequest, "request", upgrade.DefaultDir+"/"+upgrade.RequestFile, "the request the Agent handed off")
	upgradeApplyCommand.Flags().StringVar(&upgradeLibDir, "lib-dir", upgrade.DefaultLibDir, "the directory of the installed binaries")
	upgradeApplyCommand.Flags().StringVar(&upgradeSystemctl, "systemctl", "systemctl", "the systemctl binary")
	upgradeApplyCommand.Flags().StringVar(&upgradeUnit, "unit", upgrade.AgentUnit, "the Agent's unit")
	for _, name := range []string{"lib-dir", "systemctl", "unit"} {
		_ = upgradeApplyCommand.Flags().MarkHidden(name)
	}
	upgradeCommand.AddCommand(upgradeApplyCommand)
	command.AddCommand(upgradeCommand)
}
