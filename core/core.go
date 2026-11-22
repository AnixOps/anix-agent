// Package core holds the registry of proxy cores and the selector that
// runs several of them as one.
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

// factories maps a core type to its factory.
var factories = map[string]Factory{}

// Register makes a core type available; cores call it from init.
func Register(t string, f Factory) {
	factories[t] = f
}

// defaultCorePreference orders the cores run without configured ones.
var defaultCorePreference = []string{"anixcore", "wireguard"}

// anixcoreBinary finds the anixcore binary: the installed anx-node (run
// with ANX-Line) or else anixcore on PATH.
var anixcoreBinary = func() (path string, anxLine bool, ok bool) {
	if info, err := os.Stat(conf.InstalledAnxNodePath); err == nil && info.Mode().IsRegular() {
		return conf.InstalledAnxNodePath, true, true
	}
	path, err := exec.LookPath(conf.NewAnixcoreConfig().BinaryPath)
	return path, false, err == nil
}

// NewForConfig builds the core for configs; nodes is the number of
// configured nodes.
func NewForConfig(configs []conf.CoreConfig, nodes int) (Core, error) {
	switch {
	case len(configs) == 0 && nodes > 0:
		defaults, err := DefaultCoreConfigs()
		if err != nil {
			return nil, err
		}
		if len(defaults) == 0 {
			return nil, errors.New("no core is available")
		}
		return newSelector(defaults)
	case len(configs) == 0:
		return nil, errors.New("no core is configured")
	case len(configs) == 1:
		return newCore(&configs[0])
	}
	return newSelector(configs)
}

// newCore builds one core with its registered factory.
func newCore(config *conf.CoreConfig) (Core, error) {
	f, ok := factories[config.Type]
	if !ok {
		return nil, fmt.Errorf("unknown core type: %s", config.Type)
	}
	return f(config)
}

// DefaultCoreConfigs configures every registered core with its defaults,
// in order of preference. anixcore is left out without its binary.
func DefaultCoreConfigs() ([]conf.CoreConfig, error) {
	names := make([]string, 0, len(factories))
	for name := range factories {
		names = append(names, name)
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
	var configs []conf.CoreConfig
	for _, name := range names {
		object := map[string]any{"Type": name}
		if name == "anixcore" {
			path, anxLine, ok := anixcoreBinary()
			if !ok {
				continue
			}
			object["BinaryPath"], object["AnxLine"] = path, anxLine
		}
		data, err := json.Marshal(object)
		if err != nil {
			return nil, err
		}
		var config conf.CoreConfig
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("default %s config: %w", name, err)
		}
		configs = append(configs, config)
	}
	return configs, nil
}
