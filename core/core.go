package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/AnixOps/anix-agent/v4/conf"
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
var defaultCorePreference = []string{"xray", "sing", "hysteria2", "wireguard"}

// DefaultCoreConfigs are the cores of a node whose configuration comes from
// Control's stream (the O1 installer writes "Cores": []): every compiled-in
// core with its defaults, in defaultCorePreference order, so each node of
// the stream's configuration runs on the core that serves its protocol.
func DefaultCoreConfigs() ([]conf.CoreConfig, error) {
	names := RegisteredCore()
	rank := func(name string) int {
		for i, preferred := range defaultCorePreference {
			if preferred == name {
				return i
			}
		}
		return len(defaultCorePreference)
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
		document, err := json.Marshal(map[string]string{"Type": name})
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
