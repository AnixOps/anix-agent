package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/AnixOps/anix-agent/v4/conf"
	"github.com/AnixOps/anix-agent/v4/upgrade"
)

// What the installers write, and so what uninstall removes. Two installers
// exist, and a host may have either:
//
//   - the O1 installer of AnixOps Control (anix-control
//     internal/agentinstall/install.sh): the Agent as the user anixops-agent
//     from /usr/lib/anixops-agent, with the updater units, the polkit rule
//     and, for a forward node, anixops-gost.service;
//   - scripts/install.sh, the root layout: /usr/local/anixops-agent, the
//     manager script /usr/bin/anix-agent with its compatibility links, and
//     anixops-gost.service when ANIXOPS_FORWARD=1.
//
// Every path is removed only when it is provably the installer's: a unit,
// directory or rule by its product-specific name, a link only when it points
// where the installer pointed it, the manager script only when it is the
// script of this repository. Nothing else on the host is touched.
const (
	systemdUnitDir = "/etc/systemd/system"
	// updaterServiceUnit is the root oneshot the updater path unit starts
	// (upgrade.UpdaterPathUnit).
	updaterServiceUnit = "anixops-agent-updater.service"
	legacyUnitLink     = "V2bX.service"

	polkitRule = "/etc/polkit-1/rules.d/50-anixops-agent.rules"

	// agentBinaryLink is the command the O1 installer links to
	// upgrade.DefaultLibDir/anix-agent.
	agentBinaryLink = "/usr/local/bin/anix-agent"
	// managerScript is the root installer's management script (and the
	// target of its compatibility links).
	managerScript = "/usr/bin/anix-agent"
	// rootInstallDir is the root installer's program directory.
	rootInstallDir = "/usr/local/anixops-agent"

	gostStateDir = "/var/lib/anixops-gost"
	sysctlDropIn = "/etc/sysctl.d/90-anixops-forward.conf"

	agentAccount = "anixops-agent"
	gostAccount  = "anixops-gost"
)

// legacyCommandLinks are the root installer's compatibility links to the
// manager script (the V2bX era names).
var legacyCommandLinks = []string{
	"/usr/bin/v2bx-anixops", "/usr/local/bin/v2bx-anixops",
	"/usr/bin/V2bX", "/usr/local/bin/V2bX",
}

// uninstallUnits are the units the installers write, in the order they are
// stopped: the updater first, so that nothing replaces the Agent meanwhile,
// then the Agent, so that it cannot apply its state again, then gost.
var uninstallUnits = []string{upgrade.UpdaterPathUnit, updaterServiceUnit, upgrade.AgentUnit, upgrade.GostUnit}

// errNoSystemctl is the host systemctl runner's answer on a host without
// systemd: there is nothing to stop.
var errNoSystemctl = errors.New("systemctl is not installed")

var (
	// uninstallRoot prefixes every path uninstall touches and
	// uninstallSystemctl runs systemctl; tests replace both, with a
	// temporary directory and a fake. The command never sets them.
	uninstallRoot      string
	uninstallSystemctl = hostSystemctl
)

func hostSystemctl(args ...string) error {
	path, err := osexec.LookPath("systemctl")
	if err != nil {
		return errNoSystemctl
	}
	return osexec.Command(path, args...).Run() // #nosec G204 -- the arguments are fixed unit names and verbs.
}

// uninstaller removes what the installers wrote below root ("" is the host).
type uninstaller struct {
	root      string
	purge     bool
	systemctl func(args ...string) error

	removed []string
	kept    []string
	notes   []string
	errs    []error
}

func (u *uninstaller) path(logical string) string { return filepath.Join(u.root, logical) }

func (u *uninstaller) exists(logical string) bool {
	_, err := os.Lstat(u.path(logical))
	return err == nil
}

func (u *uninstaller) ctl(args ...string) error {
	if u.systemctl == nil {
		return errNoSystemctl
	}
	return u.systemctl(args...)
}

// uninstall removes the installers' units, binaries and links; with purge it
// also removes the configuration and the state, which are kept otherwise so
// that a later install finds the node's identity.
func (u *uninstaller) uninstall() error {
	forwarding := u.exists(filepath.Join(systemdUnitDir, upgrade.GostUnit)) || u.exists(sysctlDropIn) ||
		u.exists(filepath.Join(conf.DefaultStateRoot, "forward")) || u.exists(gostStateDir)

	u.removeUnits()
	u.removeFile(polkitRule)
	// The units are gone: systemd forgets them (and any failed state).
	if err := u.ctl("daemon-reload"); err != nil && !errors.Is(err, errNoSystemctl) {
		u.notes = append(u.notes, "systemctl daemon-reload failed: run it by hand")
	}
	// reset-failed answers an error for a unit systemd never loaded.
	_ = u.ctl(append([]string{"reset-failed"}, uninstallUnits...)...)

	u.removeCommands()
	u.removeTree(upgrade.DefaultLibDir)
	u.removeTree(rootInstallDir)

	configDir := filepath.Dir(defaultConfigPath)
	if u.purge {
		u.removeTree(configDir)
		// The parent /etc/anixops goes only when nothing else is in it.
		if os.Remove(u.path(filepath.Dir(configDir))) == nil {
			u.removed = append(u.removed, filepath.Dir(configDir))
		}
		u.removeTree(conf.DefaultStateRoot)
		u.removeTree(gostStateDir)
		u.removeFile(sysctlDropIn)
	} else {
		u.keep(configDir+" and "+conf.DefaultStateRoot+": the configuration and the node's identity and state, for a later install (--purge removes them)",
			u.exists(configDir) || u.exists(conf.DefaultStateRoot))
		u.keep(gostStateDir+" and "+sysctlDropIn, u.exists(gostStateDir) || u.exists(sysctlDropIn))
	}
	// What is neither files nor units of the installers stays: the accounts
	// and the kernel objects the forward drivers created at run time.
	var accounts []string
	for _, name := range []string{agentAccount, gostAccount} {
		if u.hasAccount(name) {
			accounts = append(accounts, name)
		}
	}
	if len(accounts) > 0 {
		u.keep(fmt.Sprintf("the users %s: remove them with userdel (and groupdel) when they are not needed", strings.Join(accounts, ", ")), true)
	}
	u.keep("the forwarding rules in the nftables table inet anixops_fwd and the tc root qdiscs af00: stay in the kernel until a reboot; "+
		"AnixOps Control's install.sh uninstall --purge removes them (only when they carry the drivers' marks)", forwarding)
	// Earlier Agent releases kept their state elsewhere; the Agent copies it
	// to the current layout and leaves the old directory in place.
	for _, legacy := range conf.LegacyDefaultPaths {
		u.keep(legacy.Old+": the state of an earlier release, never removed by the Agent; remove it by hand", u.exists(legacy.Old))
	}
	return errors.Join(u.errs...)
}

// keep records something that stays, when it exists.
func (u *uninstaller) keep(what string, exists bool) {
	if exists {
		u.kept = append(u.kept, what)
	}
}

// removeUnits disables, stops and removes the installers' units that exist,
// and the V2bX.service link of the root layout.
func (u *uninstaller) removeUnits() {
	for _, unit := range uninstallUnits {
		logical := filepath.Join(systemdUnitDir, unit)
		if !u.exists(logical) {
			continue
		}
		// A unit that cannot be stopped is removed all the same.
		_ = u.ctl("disable", "--now", unit)
		u.removeFile(logical)
	}
	u.removeLink(filepath.Join(systemdUnitDir, legacyUnitLink), filepath.Join(systemdUnitDir, upgrade.AgentUnit))
}

// removeCommands removes the commands the installers put on the path.
func (u *uninstaller) removeCommands() {
	// The O1 installer links agentBinaryLink to the installed binary; the
	// root installer links it, and the V2bX era names, to the manager script.
	u.removeLink(agentBinaryLink, managerScript, filepath.Join(upgrade.DefaultLibDir, upgrade.BinaryName))
	for _, link := range legacyCommandLinks {
		u.removeLink(link, managerScript)
	}
	u.removeManagerScript()
}

// removeFile removes a file or link that exists, and records it.
func (u *uninstaller) removeFile(logical string) {
	info, err := os.Lstat(u.path(logical))
	if err != nil {
		return
	}
	if info.IsDir() {
		u.errs = append(u.errs, fmt.Errorf("%s is a directory, not the file the installer wrote; left in place", logical))
		return
	}
	if err := os.Remove(u.path(logical)); err != nil {
		u.errs = append(u.errs, fmt.Errorf("remove %s: %w", logical, err))
		return
	}
	u.removed = append(u.removed, logical)
}

// removeTree removes a directory the installers created, with everything in
// it, when it exists.
func (u *uninstaller) removeTree(logical string) {
	info, err := os.Lstat(u.path(logical))
	if err != nil {
		return
	}
	if !info.IsDir() {
		u.errs = append(u.errs, fmt.Errorf("%s is not a directory, not what the installer created; left in place", logical))
		return
	}
	if err := os.RemoveAll(u.path(logical)); err != nil {
		u.errs = append(u.errs, fmt.Errorf("remove %s: %w", logical, err))
		return
	}
	u.removed = append(u.removed, logical)
}

// removeLink removes the symbolic link at logical when it points at one of
// targets (absolute paths), the way the installer made it. The target is
// compared as written, as the installers' own scripts do, never resolved: a
// link to anything else, a file or a directory is not the installer's and
// stays.
func (u *uninstaller) removeLink(logical string, targets ...string) {
	info, err := os.Lstat(u.path(logical))
	if err != nil {
		return
	}
	if info.Mode()&os.ModeSymlink == 0 {
		u.kept = append(u.kept, fmt.Sprintf("%s: not a link the installer made", logical))
		return
	}
	target, err := os.Readlink(u.path(logical))
	if err != nil {
		return
	}
	if !filepath.IsAbs(target) {
		// A relative link (V2bX.service -> anix-agent.service) is relative
		// to its own directory.
		target = filepath.Join(filepath.Dir(logical), target)
	}
	target = filepath.Clean(target)
	if !slices.Contains(targets, target) {
		u.kept = append(u.kept, fmt.Sprintf("%s: a link to %s, not the installer's", logical, target))
		return
	}
	if err := os.Remove(u.path(logical)); err != nil {
		u.errs = append(u.errs, fmt.Errorf("remove %s: %w", logical, err))
		return
	}
	u.removed = append(u.removed, logical)
}

// managerScriptMarkers are lines of scripts/anix-agent.sh, the manager
// script the root installer installs as /usr/bin/anix-agent.
var managerScriptMarkers = []string{`PRODUCT_NAME="AnixOps Agent"`, `CMD_NAME="anix-agent"`}

// removeManagerScript removes the root installer's manager script, but not
// another program that has its name.
func (u *uninstaller) removeManagerScript() {
	info, err := os.Lstat(u.path(managerScript))
	if err != nil {
		return
	}
	if !info.Mode().IsRegular() || !u.isManagerScript(managerScript) {
		u.kept = append(u.kept, fmt.Sprintf("%s: not the AnixOps Agent's manager script", managerScript))
		return
	}
	u.removeFile(managerScript)
}

// isManagerScript tells whether the file is scripts/anix-agent.sh.
func (u *uninstaller) isManagerScript(logical string) bool {
	file, err := os.Open(u.path(logical))
	if err != nil {
		return false
	}
	defer file.Close()
	head, err := io.ReadAll(io.LimitReader(file, 4096))
	if err != nil || !bytes.HasPrefix(head, []byte("#!")) {
		return false
	}
	for _, marker := range managerScriptMarkers {
		if !bytes.Contains(head, []byte(marker)) {
			return false
		}
	}
	return true
}

// hasAccount tells whether /etc/passwd lists the user.
func (u *uninstaller) hasAccount(name string) bool {
	passwd, err := os.ReadFile(u.path("/etc/passwd"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(passwd), "\n") {
		if strings.HasPrefix(line, name+":") {
			return true
		}
	}
	return false
}

// report prints what was removed and what stays.
func (u *uninstaller) report(out io.Writer) {
	if len(u.removed) == 0 {
		fmt.Fprintln(out, "已移除: 无 (未发现已安装的 AnixOps Agent)")
	} else {
		fmt.Fprintln(out, "已移除:")
		for _, item := range u.removed {
			fmt.Fprintf(out, "  - %s\n", item)
		}
	}
	if len(u.kept) > 0 {
		fmt.Fprintln(out, "已保留:")
		for _, item := range u.kept {
			fmt.Fprintf(out, "  - %s\n", item)
		}
	}
	for _, note := range u.notes {
		fmt.Fprintln(out, Warn(note))
	}
}

// ensureRoot refuses to change the host as anyone but root.
func ensureRoot() error {
	if uninstallRoot == "" && os.Geteuid() != 0 {
		return errors.New("uninstall changes systemd units and system directories: run it as root (sudo anix-agent uninstall)")
	}
	return nil
}
