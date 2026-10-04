package cmd

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/AnixOps/anix-agent/v4/common/exec"
	"github.com/spf13/cobra"
)

var (
	targetVersion string
	purgeConfig   bool
)

var releaseVersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)(\.[0-9]+)?)?$`)

var (
	updateCommand = cobra.Command{
		Use:   "update",
		Short: "Update AnixOps Agent",
		Run: func(_ *cobra.Command, _ []string) {
			if targetVersion != "" && !releaseVersionPattern.MatchString(targetVersion) {
				fmt.Println(Err("版本号格式无效: ", targetVersion))
				return
			}
			command := `tmp_file="$(mktemp)" && trap 'rm -f "${tmp_file}"' EXIT && curl -fsSL https://raw.githubusercontent.com/AnixOps/anix-agent/dev_new/scripts/install.sh -o "${tmp_file}" && bash "${tmp_file}"`
			if targetVersion != "" {
				command += " " + targetVersion
			}
			if _, err := exec.RunCommandByShell(command); err != nil {
				fmt.Println(Err("更新失败: ", err))
			}
		},
		Args: cobra.NoArgs,
	}
	uninstallCommand = cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall AnixOps Agent",
		Long: `Removes what the installers wrote: the anix-agent, anixops-gost and updater
(anixops-agent-updater.path and .service) units, the polkit rule, the binaries
in /usr/lib/anixops-agent and /usr/local/anixops-agent, and the commands linked
to them. The configuration and the node's identity and state stay, for a later
install, unless --purge is given.`,
		RunE:         uninstallHandle,
		SilenceUsage: true,
	}
)

func init() {
	updateCommand.PersistentFlags().StringVar(&targetVersion, "version", "", "update target version")
	uninstallCommand.Flags().BoolVar(&purgeConfig, "purge", false, "also remove the configuration (/etc/anixops/agent), the identity and state (/var/lib/anixops-agent, /var/lib/anixops-gost) and the sysctl drop-in")
	command.AddCommand(&updateCommand)
	command.AddCommand(&uninstallCommand)
}

// uninstallHandle removes the installers' units, binaries and links (see
// uninstall_linux.go for what that is); --purge also removes the
// configuration and the state, which are kept otherwise.
func uninstallHandle(cmd *cobra.Command, _ []string) error {
	if err := ensureRoot(); err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	var yes string
	fmt.Fprintln(out, Warn("确定要卸载 AnixOps Agent 吗?(y/N)"))
	_, _ = fmt.Fscan(cmd.InOrStdin(), &yes)
	if strings.ToLower(yes) != "y" {
		fmt.Fprintln(out, "已取消卸载")
		return nil
	}
	u := &uninstaller{root: uninstallRoot, purge: purgeConfig, systemctl: uninstallSystemctl}
	err := u.uninstall()
	u.report(out)
	if err != nil {
		return fmt.Errorf("卸载未完成: %w", err)
	}
	fmt.Fprintln(out, Ok("卸载成功"))
	return nil
}
