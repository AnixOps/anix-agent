package machinetelemetry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"

	"github.com/AnixOps/anix-control/sdk/telemetry/systemdreport"
)

// The per-node systemd services settings live in the machine-telemetry
// Agent installation configuration under ServicesConfigKey:
//
//	{
//	  "interval_seconds": 30,
//	  "systemd_services": {
//	    "nodes": {
//	      "12": {"enabled": true, "include": ["nginx*.service"], "exclude": ["*-debug.service"]}
//	    }
//	  }
//	}
//
// Control pushes the whole document to every node of the package; the
// plugin reads only the entry of its own node id. A node without an entry,
// or with enabled false, collects nothing.
//
// TODO(systemd panel): replace this adapter with systemdreport.ParseConfig,
// systemdreport.Config and systemdreport.NodeConfig once anix-control #163
// (sdk/telemetry/systemdreport/config.go) is merged, and bump the SDK
// pseudo-version. The parser below is a verbatim port of that file; the
// tests in services_config_test.go are ported from its config_test.go.
const (
	ServicesConfigKey     = "systemd_services"
	MaxServicesNodes      = 4096
	MaxServicesGlobs      = 32
	MaxServicesGlobLength = systemdreport.MaxNameLength
)

// ErrInvalidServicesConfig wraps every reason the services settings are refused.
var ErrInvalidServicesConfig = errors.New("invalid systemd_services configuration")

var (
	servicesGlobPattern   = regexp.MustCompile(`^[A-Za-z0-9:_.\\@*?\[\]^-]+$`)
	servicesNodeIDPattern = regexp.MustCompile(`^[1-9][0-9]{0,9}$`)
)

// ServicesConfig is the services settings of every node.
type ServicesConfig struct {
	Nodes map[string]ServicesNodeConfig `json:"nodes"`
}

// ServicesNodeConfig is one node's services settings.
type ServicesNodeConfig struct {
	Enabled bool     `json:"enabled"`
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

// Node returns the settings of a node: off when it has no entry.
func (c ServicesConfig) Node(nodeID uint64) ServicesNodeConfig {
	return c.Nodes[strconv.FormatUint(nodeID, 10)]
}

// Selected applies the fixed rules (systemdreport.Collectable) and the
// node's include and exclude globs to a unit name.
func (n ServicesNodeConfig) Selected(name string) bool {
	return systemdreport.Selected(name, n.Include, n.Exclude)
}

func validServicesGlob(glob string) bool {
	if glob == "" || len(glob) > MaxServicesGlobLength || !servicesGlobPattern.MatchString(glob) {
		return false
	}
	_, err := path.Match(glob, "")
	return err == nil
}

// ParseServicesConfig reads the services settings from the whole plugin
// configuration document, with the rules of systemdreport.ParseConfig.
func ParseServicesConfig(document []byte) (ServicesConfig, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(document, &fields); err != nil || fields == nil {
		return ServicesConfig{}, fmt.Errorf("%w: the configuration is not a JSON object", ErrInvalidServicesConfig)
	}
	raw, ok := fields[ServicesConfigKey]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return ServicesConfig{Nodes: map[string]ServicesNodeConfig{}}, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config ServicesConfig
	if err := decoder.Decode(&config); err != nil {
		return ServicesConfig{}, fmt.Errorf("%w: %v", ErrInvalidServicesConfig, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ServicesConfig{}, fmt.Errorf("%w: trailing data", ErrInvalidServicesConfig)
	}
	if config.Nodes == nil {
		config.Nodes = map[string]ServicesNodeConfig{}
	}
	if len(config.Nodes) > MaxServicesNodes {
		return ServicesConfig{}, fmt.Errorf("%w: more than %d nodes", ErrInvalidServicesConfig, MaxServicesNodes)
	}
	for nodeID, node := range config.Nodes {
		if !servicesNodeIDPattern.MatchString(nodeID) {
			return ServicesConfig{}, fmt.Errorf("%w: node %q is not a node id", ErrInvalidServicesConfig, nodeID)
		}
		if parsed, err := strconv.ParseUint(nodeID, 10, 32); err != nil || parsed == 0 {
			return ServicesConfig{}, fmt.Errorf("%w: node %q is not a node id", ErrInvalidServicesConfig, nodeID)
		}
		for list, globs := range map[string][]string{"include": node.Include, "exclude": node.Exclude} {
			if len(globs) > MaxServicesGlobs {
				return ServicesConfig{}, fmt.Errorf("%w: node %s: more than %d %s globs", ErrInvalidServicesConfig, nodeID, MaxServicesGlobs, list)
			}
			for _, glob := range globs {
				if !validServicesGlob(glob) {
					return ServicesConfig{}, fmt.Errorf("%w: node %s: %s glob %q is malformed", ErrInvalidServicesConfig, nodeID, list, glob)
				}
			}
		}
	}
	return config, nil
}

// ParseNodeID reads the node id the Agent hands the plugin (decimal, 1 to
// 4294967295, no leading zeros). An empty value means no node id.
func ParseNodeID(value string) (uint64, error) {
	if value == "" {
		return 0, nil
	}
	if !servicesNodeIDPattern.MatchString(value) {
		return 0, fmt.Errorf("node id %q is not a decimal node id", value)
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || parsed == 0 {
		return 0, fmt.Errorf("node id %q is out of range", value)
	}
	return parsed, nil
}
