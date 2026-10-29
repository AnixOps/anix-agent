package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"sort"

	"github.com/AnixOps/anix-agent/v5/conf"
)

var (
	cores = map[string]func(c *conf.CoreConfig) (Core, error){}
)

func NewCore(c []conf.CoreConfig) (Core, error) {
	if len(c) == 0 {
		return nil, errors.New("no have vail core")
	}
	// multi core
	if len(c) > 1 {
		return NewSelector(c)
	}
	// one core
	if f, ok := cores[c[0].Type]; ok {
		return f(&c[0])
	} else {
		return nil, errors.New("unknown core type")
	}
}

func RegisterCore(t string, f func(c *conf.CoreConfig) (Core, error)) {
	cores[t] = f
}

func RegisteredCore() []string {
	cs := make([]string, 0, len(cores))
	for k := range cores {
		cs = append(cs, k)
	}
	return cs
}

// defaultCorePreference orders the compiled-in cores of a configuration
// that lists none: a protocol more than one core serves runs on the first.
// anixcore, our own kernel, comes first once its binary is installed
// (anixcoreBinary); until then it is left out.
var defaultCorePreference = []string{"anixcore", "xray", "sing", "hysteria2", "wireguard"}

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
// core with its defaults, in defaultCorePreference order, so each node of
// the stream's configuration runs on the core that serves its protocol.
func DefaultCoreConfigs() ([]conf.CoreConfig, error) {
	names := RegisteredCore()
	preference := defaultCorePreference
	anixcorePath, anxLine, installed := anixcoreBinary()
	if !installed {
		// A compiled-in anixcore without its binary would fail to start.
		preference = preference[1:]
		names = slices.DeleteFunc(names, func(name string) bool { return name == "anixcore" })
	}
	rank := func(name string) int {
		for i, preferred := range preference {
			if preferred == name {
				return i
			}
		}
		return len(preference)
	}
	sort.Slice(names, func(i, j int) bool {
		if rank(names[i]) != rank(names[j]) {
			return rank(names[i]) < rank(names[j])
		}
		return names[i] < names[j]
	})
	configs := make([]conf.CoreConfig, 0, len(names))
	for _, name := range names {
		var config conf.CoreConfig
		fields := map[string]any{"Type": name}
		if name == "anixcore" {
			fields["BinaryPath"] = anixcorePath
			fields["AnxLine"] = anxLine
		}
		document, err := json.Marshal(fields)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(document, &config); err != nil {
			return nil, fmt.Errorf("default %s core: %w", name, err)
		}
		configs = append(configs, config)
	}
	return configs, nil
}

// NewForConfig builds the configuration's core. Without any configured
// core but with nodes, every compiled-in core runs behind a Selector
// (DefaultCoreConfigs), which picks the core by each node's protocol.
func NewForConfig(cores []conf.CoreConfig, nodes int) (Core, error) {
	if len(cores) > 0 || nodes == 0 {
		return NewCore(cores)
	}
	defaults, err := DefaultCoreConfigs()
	if err != nil {
		return nil, err
	}
	if len(defaults) == 0 {
		return nil, errors.New("no have vail core")
	}
	return NewSelector(defaults)
}
