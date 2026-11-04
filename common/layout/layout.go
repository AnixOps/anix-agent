// Package layout is the Agent's installed layout. The installer may give
// the Agent a neutral install name (install.sh --name <name>): the binary
// is then /usr/lib/<name>/<name>, its kernel /usr/lib/<name>/core, and its
// directories, units and service account are all called <name>, so nothing
// on the host names AnixOps or a protocol. The Agent reads the name from
// where its binary is; the default name keeps the original layout.
package layout

import (
	"os"
	"path/filepath"
)

// DefaultName is the install name of the original layout.
const DefaultName = "anixops-agent"

// Name is the install name: the directory of the running binary below
// /usr/lib, DefaultName anywhere else.
var Name = name()

func name() string {
	exe, err := os.Executable()
	if err != nil {
		return DefaultName
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	if dir := filepath.Dir(exe); filepath.Dir(dir) == "/usr/lib" {
		return filepath.Base(dir)
	}
	return DefaultName
}

// pick is original under the default name and neutral under any other.
func pick(original, neutral string) string {
	if Name == DefaultName {
		return original
	}
	return neutral
}

// The layout of Name.
var (
	LibDir     = "/usr/lib/" + Name
	StateDir   = "/var/lib/" + Name
	RuntimeDir = "/run/" + Name
	ConfigDir  = pick("/etc/anixops/agent", "/etc/"+Name)
	// Binary is the Agent binary in LibDir; Service its unit's name.
	Binary  = pick("anix-agent", Name)
	Service = pick("anix-agent", Name)
	// Updater is the privileged updater's unit name (.path, .service).
	Updater = Name + "-updater"
	// Kernel and KernelServer are anx-node and anx-server in LibDir.
	Kernel       = pick("anx-node", "core")
	KernelServer = pick("anx-server", "core-server")
	PolkitRule   = "/etc/polkit-1/rules.d/50-" + Name + ".rules"
	SysctlDropIn = pick("/etc/sysctl.d/90-anixops-forward.conf", "/etc/sysctl.d/90-"+Name+".conf")
)
