package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

const installScriptURL = "https://raw.githubusercontent.com/AnixOps/anix-agent/main/scripts/install.sh"

var releaseVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)(\.[0-9]+(\.dev\.[0-9]+)?)?)?$`)

var updateVersion string

func init() {
	for _, action := range []struct{ name, short, done string }{
		{"start", "Start the service", "started"},
		{"stop", "Stop the service", "stopped"},
		{"restart", "Restart the service", "restarted"},
	} {
		command.AddCommand(&cobra.Command{
			Use:   action.name,
			Short: action.short,
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				out, err := exec.Command("systemctl", action.name, serviceName).CombinedOutput() // #nosec G204 -- fixed verbs and unit.
				if err != nil {
					return fmt.Errorf("systemctl %s %s: %w: %s", action.name, serviceName, err, strings.TrimSpace(string(out)))
				}
				fmt.Fprintln(cmd.OutOrStdout(), Ok(productName, " ", action.done, "; see its log with `", commandName, " log`"))
				return nil
			},
		})
	}
	command.AddCommand(&cobra.Command{
		Use:   "log",
		Short: "Follow the service's log",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return attached(exec.Command("journalctl", "-u", serviceName, "-e", "--no-pager", "-f"))
		},
	})
	update := &cobra.Command{
		Use:   "update",
		Short: "Update the Agent with the installer (the latest release, or --version)",
		Args:  cobra.NoArgs,
		RunE:  updateHandle,
	}
	update.Flags().StringVar(&updateVersion, "version", "", "release to install, vX.Y.Z (default: the latest)")
	command.AddCommand(update)
}

// updateHandle downloads the installer and runs it.
func updateHandle(_ *cobra.Command, _ []string) error {
	if updateVersion != "" && !releaseVersion.MatchString(updateVersion) {
		return fmt.Errorf("--version %q is not a release version (vX.Y.Z, optionally -alpha, -beta or -rc)", updateVersion)
	}
	script, err := os.CreateTemp("", "anix-agent-install-*.sh")
	if err != nil {
		return err
	}
	defer os.Remove(script.Name())
	err = download(installScriptURL, script)
	if closeErr := script.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("download the installer: %w", err)
	}
	args := []string{script.Name()}
	if updateVersion != "" {
		args = append(args, updateVersion)
	}
	return attached(exec.Command("bash", args...)) // #nosec G204 -- our installer and a checked version.
}

func download(url string, to io.Writer) error {
	response, err := http.Get(url) // #nosec G107 -- a constant URL.
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, response.Status)
	}
	_, err = io.Copy(to, response.Body)
	return err
}

// attached runs c on the terminal.
func attached(c *exec.Cmd) error {
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c.Run()
}
