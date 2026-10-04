package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// uninstall is tested against a temporary root and a recording systemctl
// only: uninstallRoot prefixes every path and uninstallSystemctl is the
// fake. These tests never run the command on the host's paths or systemd.

// systemctlLog records the fake systemctl's calls.
type systemctlLog struct {
	mu    sync.Mutex
	calls []string
	// fail makes the call fail when it returns an error for it.
	fail func(args []string) error
}

func (l *systemctlLog) run(args ...string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, strings.Join(args, " "))
	if l.fail != nil {
		return l.fail(args)
	}
	return nil
}

// useUninstallRoot points uninstall at a new temporary root with a fake
// systemctl, and restores the command afterwards.
func useUninstallRoot(t *testing.T) (string, *systemctlLog) {
	t.Helper()
	root := t.TempDir()
	log := &systemctlLog{}
	uninstallRoot, uninstallSystemctl = root, log.run
	t.Cleanup(func() {
		uninstallRoot, uninstallSystemctl = "", hostSystemctl
		purgeConfig = false
	})
	return root, log
}

func writeTree(t *testing.T, root, logical, content string) {
	t.Helper()
	path := filepath.Join(root, logical)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

// linkTree makes a symbolic link the way the installers do: the target is
// written as the host path, never carrying the temporary root.
func linkTree(t *testing.T, root, logical, target string) {
	t.Helper()
	path := filepath.Join(root, logical)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.Symlink(target, path))
}

func present(root, logical string) bool {
	_, err := os.Lstat(filepath.Join(root, logical))
	return err == nil
}

func requirePresent(t *testing.T, root string, logicals ...string) {
	t.Helper()
	for _, logical := range logicals {
		require.True(t, present(root, logical), "%s was removed", logical)
	}
}

func requireAbsent(t *testing.T, root string, logicals ...string) {
	t.Helper()
	for _, logical := range logicals {
		require.False(t, present(root, logical), "%s is still there", logical)
	}
}

// uninstallCommandRun runs `anix-agent uninstall` answering its prompt with
// input.
func uninstallCommandRun(t *testing.T, input string, purge bool) (out string, err error) {
	t.Helper()
	require.NotEmpty(t, uninstallRoot, "use useUninstallRoot: the command must never run on the host's paths")
	found, _, findErr := command.Find([]string{"uninstall"})
	require.NoError(t, findErr)
	purgeConfig = purge
	var buffer strings.Builder
	found.SetIn(strings.NewReader(input))
	found.SetOut(&buffer)
	t.Cleanup(func() { found.SetIn(nil); found.SetOut(nil) })
	err = found.RunE(found, nil)
	return buffer.String(), err
}

// o1Units are the units the O1 installer writes (anix-control
// internal/agentinstall/install.sh).
var o1Units = []string{
	"anixops-agent-updater.path", "anixops-agent-updater.service", "anix-agent.service", "anixops-gost.service",
}

// installO1 writes what the O1 installer writes (and what a running Agent
// adds below the state directory), plus things that are not the Agent's.
func installO1(t *testing.T, root string) {
	t.Helper()
	for _, unit := range o1Units {
		writeTree(t, root, "/etc/systemd/system/"+unit, "# Written by the AnixOps installer\n[Unit]\n")
	}
	writeTree(t, root, "/etc/polkit-1/rules.d/50-anixops-agent.rules", "// Written by the AnixOps installer\n")
	for _, name := range []string{"anix-agent", "gost", "anix-agent.prev", "anix-agent.prev.json", ".release-version"} {
		writeTree(t, root, "/usr/lib/anixops-agent/"+name, name)
	}
	linkTree(t, root, "/usr/local/bin/anix-agent", "/usr/lib/anixops-agent/anix-agent")
	writeTree(t, root, "/etc/anixops/agent/config.json", "{}")
	for _, name := range []string{"pki/proxy-12/identity.pem", "stream/state.json", "forward/state.json", "plugins/p/data", "upgrade/result.json", "enroll.credential"} {
		writeTree(t, root, "/var/lib/anixops-agent/"+name, name)
	}
	writeTree(t, root, "/var/lib/anixops-gost/gost.json", "{}")
	writeTree(t, root, "/etc/sysctl.d/90-anixops-forward.conf", "net.ipv4.ip_forward = 1\n")
	writeTree(t, root, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nanixops-agent:x:998:998::/var/lib/anixops-agent:/usr/sbin/nologin\nanixops-gost:x:997:997::/nonexistent:/usr/sbin/nologin\n")
}

// bystanders are files near the Agent's that no uninstall may touch.
var bystanders = []string{
	"/etc/systemd/system/other.service",
	"/etc/systemd/system/multi-user.target.wants/other.service",
	"/etc/polkit-1/rules.d/50-other.rules",
	"/usr/lib/anixops-agent-extra/file",
	"/usr/lib/other/file",
	"/usr/local/bin/other",
	"/usr/local/anixops-agent-extra/file",
	"/var/lib/anixops-agent-extra/file",
	"/var/lib/anix-agent/pki/old/identity.pem",
	"/etc/sysctl.d/99-other.conf",
}

func writeBystanders(t *testing.T, root string) {
	t.Helper()
	for _, logical := range bystanders {
		writeTree(t, root, logical, "bystander")
	}
}

func TestUninstallRemovesTheO1Layout(t *testing.T) {
	root, log := useUninstallRoot(t)
	installO1(t, root)
	writeBystanders(t, root)

	out, err := uninstallCommandRun(t, "y\n", false)
	require.NoError(t, err, out)

	// Exactly the installer's units, binaries and link are gone.
	requireAbsent(t, root,
		"/etc/systemd/system/anixops-agent-updater.path", "/etc/systemd/system/anixops-agent-updater.service",
		"/etc/systemd/system/anix-agent.service", "/etc/systemd/system/anixops-gost.service",
		"/etc/polkit-1/rules.d/50-anixops-agent.rules",
		"/usr/lib/anixops-agent", "/usr/local/bin/anix-agent")
	// The identity, configuration and state stay for a later install, with
	// gost's directory and the sysctl drop-in.
	requirePresent(t, root,
		"/etc/anixops/agent/config.json",
		"/var/lib/anixops-agent/pki/proxy-12/identity.pem", "/var/lib/anixops-agent/stream/state.json",
		"/var/lib/anixops-agent/forward/state.json", "/var/lib/anixops-agent/plugins/p/data",
		"/var/lib/anixops-gost/gost.json", "/etc/sysctl.d/90-anixops-forward.conf", "/etc/passwd")
	requirePresent(t, root, bystanders...)

	// The updater first, then the Agent, then gost; systemd reloads after.
	require.Equal(t, []string{
		"disable --now anixops-agent-updater.path",
		"disable --now anixops-agent-updater.service",
		"disable --now anix-agent.service",
		"disable --now anixops-gost.service",
		"daemon-reload",
		"reset-failed anixops-agent-updater.path anixops-agent-updater.service anix-agent.service anixops-gost.service",
	}, log.calls)

	require.Contains(t, out, "/usr/lib/anixops-agent")
	require.Contains(t, out, "anixops-agent-updater.path")
	require.Contains(t, out, "已保留")
	require.Contains(t, out, "/etc/anixops/agent and /var/lib/anixops-agent")
	require.Contains(t, out, "the users anixops-agent, anixops-gost")
	require.Contains(t, out, "inet anixops_fwd")
	require.Contains(t, out, "卸载成功")

	// A second run finds nothing to remove and changes nothing.
	log.calls = nil
	out, err = uninstallCommandRun(t, "y\n", false)
	require.NoError(t, err, out)
	require.Contains(t, out, "未发现已安装")
	requirePresent(t, root, "/etc/anixops/agent/config.json", "/var/lib/anixops-agent/pki/proxy-12/identity.pem")
	requirePresent(t, root, bystanders...)
	for _, call := range log.calls {
		require.NotContains(t, call, "disable", "no unit is left to disable")
	}
}

func TestUninstallPurgeRemovesConfigurationAndState(t *testing.T) {
	root, _ := useUninstallRoot(t)
	installO1(t, root)
	writeBystanders(t, root)

	out, err := uninstallCommandRun(t, "y\n", true)
	require.NoError(t, err, out)

	requireAbsent(t, root,
		"/etc/systemd/system/anixops-agent-updater.path", "/etc/systemd/system/anix-agent.service",
		"/usr/lib/anixops-agent", "/usr/local/bin/anix-agent",
		"/etc/anixops", // the directory goes with the configuration when it is empty
		"/var/lib/anixops-agent", "/var/lib/anixops-gost", "/etc/sysctl.d/90-anixops-forward.conf")
	requirePresent(t, root, bystanders...)
	requirePresent(t, root, "/etc/passwd")
	// Not the installer's, so not removed: the accounts, the kernel's
	// forwarding objects and the earlier release's directory.
	require.Contains(t, out, "the users anixops-agent, anixops-gost")
	require.Contains(t, out, "inet anixops_fwd")
	require.Contains(t, out, "/var/lib/anix-agent/pki")
	require.NotContains(t, out, "/etc/anixops/agent and /var/lib/anixops-agent: ")
}

func TestUninstallPurgeKeepsAnEtcAnixopsThatHoldsOtherFiles(t *testing.T) {
	root, _ := useUninstallRoot(t)
	installO1(t, root)
	writeTree(t, root, "/etc/anixops/other-product/config", "x")

	out, err := uninstallCommandRun(t, "y\n", true)
	require.NoError(t, err, out)
	requireAbsent(t, root, "/etc/anixops/agent")
	requirePresent(t, root, "/etc/anixops/other-product/config")
}

func TestUninstallRemovesTheRootLayout(t *testing.T) {
	root, log := useUninstallRoot(t)
	// scripts/install.sh: the unit, the V2bX.service link, the program
	// directory, the manager script and the compatibility links; the
	// release's gost lands in /usr/lib/anixops-agent; ANIXOPS_FORWARD=1 adds
	// gost's unit and the sysctl drop-in.
	writeTree(t, root, "/etc/systemd/system/anix-agent.service", "[Service]\nUser=root\n")
	linkTree(t, root, "/etc/systemd/system/V2bX.service", "anix-agent.service")
	writeTree(t, root, "/etc/systemd/system/anixops-gost.service", "[Service]\n")
	for _, name := range []string{"anix-agent", ".release-version", "backups/anix-agent.1", "data/credential.json"} {
		writeTree(t, root, "/usr/local/anixops-agent/"+name, name)
	}
	manager, err := os.ReadFile("../scripts/anix-agent.sh")
	require.NoError(t, err)
	writeTree(t, root, "/usr/bin/anix-agent", string(manager))
	require.NoError(t, os.Chmod(filepath.Join(root, "/usr/bin/anix-agent"), 0o755))
	for _, link := range []string{"/usr/local/bin/anix-agent", "/usr/bin/v2bx-anixops", "/usr/local/bin/v2bx-anixops", "/usr/bin/V2bX", "/usr/local/bin/V2bX"} {
		linkTree(t, root, link, "/usr/bin/anix-agent")
	}
	writeTree(t, root, "/usr/lib/anixops-agent/gost", "gost")
	writeTree(t, root, "/etc/anixops/agent/config.json", "{}")
	writeTree(t, root, "/var/lib/anixops-agent/credential.json.enc", "credential")
	writeBystanders(t, root)

	out, err := uninstallCommandRun(t, "y\n", false)
	require.NoError(t, err, out)

	requireAbsent(t, root,
		"/etc/systemd/system/anix-agent.service", "/etc/systemd/system/V2bX.service", "/etc/systemd/system/anixops-gost.service",
		"/usr/local/anixops-agent", "/usr/bin/anix-agent", "/usr/lib/anixops-agent",
		"/usr/local/bin/anix-agent", "/usr/bin/v2bx-anixops", "/usr/local/bin/v2bx-anixops", "/usr/bin/V2bX", "/usr/local/bin/V2bX")
	requirePresent(t, root, "/etc/anixops/agent/config.json", "/var/lib/anixops-agent/credential.json.enc")
	requirePresent(t, root, bystanders...)
	require.Equal(t, []string{
		"disable --now anix-agent.service",
		"disable --now anixops-gost.service",
		"daemon-reload",
		"reset-failed anixops-agent-updater.path anixops-agent-updater.service anix-agent.service anixops-gost.service",
	}, log.calls)
}

// The manager script's markers must stay in scripts/anix-agent.sh: they are
// how uninstall tells it from another program called anix-agent.
func TestManagerScriptMarkersAreInTheManagerScript(t *testing.T) {
	manager, err := os.ReadFile("../scripts/anix-agent.sh")
	require.NoError(t, err)
	head := string(manager[:min(len(manager), 4096)])
	require.True(t, strings.HasPrefix(head, "#!"))
	for _, marker := range managerScriptMarkers {
		require.Contains(t, head, marker)
	}
}

func TestUninstallLeavesWhatTheInstallersDidNotWrite(t *testing.T) {
	root, _ := useUninstallRoot(t)
	// Commands that carry the Agent's names but are not the installers'.
	linkTree(t, root, "/usr/local/bin/anix-agent", "/opt/other/anix-agent")
	writeTree(t, root, "/usr/bin/anix-agent", "#!/bin/sh\necho some other program\n")
	writeTree(t, root, "/usr/bin/V2bX", "#!/bin/sh\necho the old binary\n")
	linkTree(t, root, "/usr/local/bin/V2bX", "/opt/other/V2bX")
	linkTree(t, root, "/etc/systemd/system/V2bX.service", "/etc/systemd/system/other.service")
	// The O1 link must point at the installed binary of this layout.
	linkTree(t, root, "/usr/bin/v2bx-anixops", "/usr/lib/anixops-agent/anix-agent")
	writeBystanders(t, root)

	out, err := uninstallCommandRun(t, "y\n", false)
	require.NoError(t, err, out)

	requirePresent(t, root,
		"/usr/local/bin/anix-agent", "/usr/bin/anix-agent", "/usr/bin/V2bX", "/usr/local/bin/V2bX",
		"/etc/systemd/system/V2bX.service", "/usr/bin/v2bx-anixops")
	requirePresent(t, root, bystanders...)
	require.Contains(t, out, "/usr/local/bin/anix-agent: a link to /opt/other/anix-agent, not the installer's")
	require.Contains(t, out, "/usr/bin/anix-agent: not the AnixOps Agent's manager script")
	require.Contains(t, out, "/usr/bin/V2bX: not a link the installer made")
	require.Contains(t, out, "未发现已安装")
}

func TestUninstallCancelledChangesNothing(t *testing.T) {
	root, log := useUninstallRoot(t)
	installO1(t, root)

	for _, answer := range []string{"n\n", "\n", ""} {
		out, err := uninstallCommandRun(t, answer, true)
		require.NoError(t, err, out)
		require.Contains(t, out, "已取消卸载")
	}
	requirePresent(t, root, "/usr/lib/anixops-agent/anix-agent", "/etc/systemd/system/anix-agent.service",
		"/etc/anixops/agent/config.json", "/var/lib/anixops-agent/pki/proxy-12/identity.pem")
	require.Empty(t, log.calls)
}

func TestUninstallKeepsGoingWhenSystemctlFails(t *testing.T) {
	root, log := useUninstallRoot(t)
	installO1(t, root)
	log.fail = func([]string) error { return errors.New("Failed to connect to bus") }

	out, err := uninstallCommandRun(t, "y\n", false)
	// systemd cannot be asked (a container, a chroot): the files go anyway,
	// and the reload that did not happen is reported.
	require.NoError(t, err, out)
	requireAbsent(t, root, "/etc/systemd/system/anix-agent.service", "/usr/lib/anixops-agent", "/usr/local/bin/anix-agent")
	require.Contains(t, out, "systemctl daemon-reload failed")
}

func TestUninstallReportsWhatItCouldNotRemoveAndRemovesTheRest(t *testing.T) {
	root, _ := useUninstallRoot(t)
	installO1(t, root)
	// Not a directory: not what the installer created.
	require.NoError(t, os.RemoveAll(filepath.Join(root, "/usr/lib/anixops-agent")))
	writeTree(t, root, "/usr/lib/anixops-agent", "a file")

	out, err := uninstallCommandRun(t, "y\n", false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "/usr/lib/anixops-agent is not a directory")
	requirePresent(t, root, "/usr/lib/anixops-agent")
	requireAbsent(t, root, "/etc/systemd/system/anix-agent.service", "/etc/systemd/system/anixops-agent-updater.path", "/usr/local/bin/anix-agent")
	require.NotContains(t, out, "卸载成功")
}
