package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

// The service commands drive the systemd unit of the Agent.
func init() {
	for _, action := range []string{"start", "stop", "restart"} {
		command.AddCommand(&cobra.Command{
			Use:   action,
			Short: strings.ToUpper(action[:1]) + action[1:] + " the " + productName + " service",
			Args:  cobra.NoArgs,
			RunE: func(c *cobra.Command, _ []string) error {
				if out, err := exec.Command("systemctl", action, serviceName).CombinedOutput(); err != nil {
					return fmt.Errorf("systemctl %s: %w: %s", action, err, strings.TrimSpace(string(out)))
				}
				fmt.Fprintln(c.OutOrStdout(), Ok(productName+" "+action+": ok, run '"+cliName+" log' to follow the log"))
				return nil
			},
		})
	}
	command.AddCommand(&cobra.Command{
		Use:   "log",
		Short: "Follow the " + productName + " log",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return interactive("journalctl", "-u", serviceName, "-e", "--no-pager", "-f")
		},
	})

	var target string
	update := &cobra.Command{
		Use:   "update",
		Short: "Reinstall " + productName + " with the install script (latest release, or --version)",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if target != "" && !releaseTag.MatchString(target) {
				return fmt.Errorf("invalid version %q", target)
			}
			script := `f="$(mktemp)" && trap 'rm -f "$f"' EXIT && curl -fsSL ` + installScriptURL + ` -o "$f" && bash "$f" "$@"`
			args := []string{"-c", script, "install"}
			if target != "" {
				args = append(args, target)
			}
			return interactive("bash", args...)
		},
	}
	update.Flags().StringVar(&target, "version", "", "release tag to install, such as v5.0.8")
	command.AddCommand(update)
}

const installScriptURL = "https://raw.githubusercontent.com/AnixOps/anix-agent/main/scripts/install.sh"

var releaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)(\.[0-9]+(\.dev\.[0-9]+)?)?)?$`)

// interactive runs name on the caller's terminal.
func interactive(name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c.Run()
}
