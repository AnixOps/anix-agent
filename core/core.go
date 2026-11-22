// Package core runs nodes on the compiled-in cores (anixcore, wireguard).
package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/AnixOps/anix-agent/v5/conf"
)

// Factory builds a core from its configuration.
type Factory func(*conf.CoreConfig) (Core, error)

// factories are the compiled-in cores by type; each registers in init.
var factories = map[string]Factory{}

// Register makes the core type t available to configurations.
func Register(t string, f Factory) {
	factories[t] = f
}

var errNoCore = errors.New("no core to run")

// NewForConfig builds the configuration's cores: one core as itself,
// several behind a Selector. Without any configured core but with nodes,
// every compiled-in core runs behind a Selector (DefaultCoreConfigs), which
// picks the core by each node's protocol.
func NewForConfig(configs []conf.CoreConfig, nodes int) (Core, error) {
	if len(configs) == 0 && nodes > 0 {
		defaults, err := DefaultCoreConfigs()
		if err != nil {
			return nil, err
		}
		if len(defaults) == 0 {
			return nil, errNoCore
		}
		return newSelector(defaults)
	}
	switch len(configs) {
	case 0:
		return nil, errNoCore
	case 1:
		f, ok := factories[configs[0].Type]
		if !ok {
			return nil, fmt.Errorf("unknown core type %q", configs[0].Type)
		}
		return f(&configs[0])
	}
	return newSelector(configs)
}

// defaultCorePreference orders the compiled-in cores of a configuration
// that lists none: a protocol more than one core serves runs on the first.
// anixcore, our own kernel, comes first once its binary is installed
// (anixcoreBinary); until then it is left out.
var defaultCorePreference = []string{"anixcore", "wireguard"}

// anixcoreBinary finds the binary the default anixcore core runs: the
// anx-node that Agent upgrades install (conf.InstalledAnxNodePath), which
// also carries ANX-Line, or else the anixcore binary of the default
// configuration on PATH. ok is false when neither is there.
var anixcoreBinary = func() (path string, anxLine bool, ok bool) {
	if info, err := os.Stat(conf.InstalledAnxNodePath); err == nil && info.Mode().IsRegular() {
		return conf.InstalledAnxNodePath, true, true
	}
	if _, err := exec.LookPath(conf.NewAnixcoreConfig().BinaryPath); err == nil {
		return conf.NewAnixcoreConfig().BinaryPath, false, true
	}
	return "", false, false
}

// DefaultCoreConfigs are the cores of a node whose configuration comes from
// Control's stream (the O1 installer writes "Cores": []): every compiled-in
// core with its defaults, in defaultCorePreference order then by name, so
// each node of the stream's configuration runs on the core that serves its
// protocol.
func DefaultCoreConfigs() ([]conf.CoreConfig, error) {
	anixcorePath, anxLine, installed := anixcoreBinary()
	names := make([]string, 0, len(factories))
	for name := range factories {
		// A compiled-in anixcore without its binary would fail to start.
		if name != "anixcore" || installed {
			names = append(names, name)
		}
	}
	rank := func(name string) int {
		if i := slices.Index(defaultCorePreference, name); i >= 0 {
			return i
		}
		return len(defaultCorePreference)
	}
	slices.SortFunc(names, func(a, b string) int {
		if d := rank(a) - rank(b); d != 0 {
			return d
		}
		return strings.Compare(a, b)
	})
	configs := make([]conf.CoreConfig, len(names))
	for i, name := range names {
		fields := map[string]any{"Type": name}
		if name == "anixcore" {
			fields["BinaryPath"], fields["AnxLine"] = anixcorePath, anxLine
		}
		// Through JSON, so that each core's settings get their defaults.
		document, err := json.Marshal(fields)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(document, &configs[i]); err != nil {
			return nil, fmt.Errorf("default %s core: %w", name, err)
		}
	}
	return configs, nil
}
