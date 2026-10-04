package cmd

import (
	"fmt"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/AnixOps/anix-agent/v4/conf"
	"github.com/spf13/cobra"
)

var (
	migrateChown string
	migrateRoot  string
)

// migratePathsCommand is the installer's side of the move to the O1 layout:
// run as root before the Agent starts as anixops-agent, it copies every
// earlier default directory that exists to its new place when that place
// does not exist yet, owned by --chown. The earlier directories are left in
// place. The Agent itself migrates only what its own user can read, at
// start.
var migratePathsCommand = &cobra.Command{
	Use:   "migrate-paths",
	Short: "Copy the earlier default directories to the /var/lib/anixops-agent layout (for installers)",
	Long: `Copies, once, each earlier default directory of the Agent to its new place:

  /var/lib/anix-agent/pki     -> /var/lib/anixops-agent/pki
  /var/lib/anix-agent/stream  -> /var/lib/anixops-agent/stream
  /var/lib/anixops/plugins    -> /var/lib/anixops-agent/plugins

A directory is copied only when the old one exists and the new one does not;
the old one is never removed. With --chown the copies belong to that user
(and its primary group), as the sandboxed Agent needs.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		opts := conf.MigrateOptions{}
		if migrateChown != "" {
			account, err := user.Lookup(migrateChown)
			if err != nil {
				return fmt.Errorf("--chown: %w", err)
			}
			uid, err := strconv.Atoi(account.Uid)
			if err != nil {
				return fmt.Errorf("--chown: uid %q: %w", account.Uid, err)
			}
			gid, err := strconv.Atoi(account.Gid)
			if err != nil {
				return fmt.Errorf("--chown: gid %q: %w", account.Gid, err)
			}
			opts = conf.MigrateOptions{Chown: true, UID: uid, GID: gid}
		}
		out := cmd.OutOrStdout()
		var failed error
		for _, path := range conf.LegacyDefaultPaths {
			old, next := filepath.Join(migrateRoot, path.Old), filepath.Join(migrateRoot, path.New)
			outcome, err := conf.MigrateLegacyPath(old, next, opts)
			switch {
			case err != nil:
				fmt.Fprintf(out, "failed  %s: %s -> %s: %v\n", path.Name, path.Old, path.New, err)
				if failed == nil {
					failed = fmt.Errorf("could not copy %s to %s: %w", path.Old, path.New, err)
				}
			case outcome == conf.MigrationCopied:
				fmt.Fprintf(out, "copied  %s: %s -> %s (the old directory is left in place)\n", path.Name, path.Old, path.New)
			default:
				fmt.Fprintf(out, "kept    %s: %s\n", path.Name, path.New)
			}
		}
		return failed
	},
}

func init() {
	migratePathsCommand.Flags().StringVar(&migrateChown, "chown", "", "user that owns the copies (the Agent's user, anixops-agent)")
	migratePathsCommand.Flags().StringVar(&migrateRoot, "root", "", "prefix every path (installer tests)")
	_ = migratePathsCommand.Flags().MarkHidden("root")
	command.AddCommand(migratePathsCommand)
}
