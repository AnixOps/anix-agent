package machinetelemetry

import (
	"fmt"
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
// or with enabled false, collects nothing. The parser is the SDK's
// systemdreport.ParseConfig, the one Control validates the configuration
// with when it is saved.
const (
	ServicesConfigKey     = systemdreport.ConfigKey
	MaxServicesNodes      = systemdreport.MaxConfigNodes
	MaxServicesGlobs      = systemdreport.MaxGlobs
	MaxServicesGlobLength = systemdreport.MaxGlobLength
)

// ErrInvalidServicesConfig wraps every reason the services settings are refused.
var ErrInvalidServicesConfig = systemdreport.ErrInvalidConfig

var servicesNodeIDPattern = regexp.MustCompile(`^[1-9][0-9]{0,9}$`)

// ServicesConfig is the services settings of every node.
type ServicesConfig = systemdreport.Config

// ServicesNodeConfig is one node's services settings.
type ServicesNodeConfig = systemdreport.NodeConfig

// ParseServicesConfig reads the services settings from the whole plugin
// configuration document (systemdreport.ParseConfig).
func ParseServicesConfig(document []byte) (ServicesConfig, error) {
	return systemdreport.ParseConfig(document)
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
