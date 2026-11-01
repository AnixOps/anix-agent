package conf

import (
	"encoding/json"
	"os"
)

type CoreConfig struct {
	Type            string           `json:"Type"`
	Name            string           `json:"Name"`
	WireGuardConfig *WireGuardConfig `json:"-"`
	AnixcoreConfig  *AnixcoreConfig  `json:"-"`
}

type _CoreConfig CoreConfig

func (c *CoreConfig) UnmarshalJSON(b []byte) error {
	err := json.Unmarshal(b, (*_CoreConfig)(c))
	if err != nil {
		return err
	}
	switch c.Type {
	// The third-party cores are gone: a configuration that still lists
	// one runs on anixcore: the anx-node Agent upgrades install when it is
	// there, like a configuration without cores, else anixcore on PATH.
	case "xray", "sing", "hysteria2":
		c.Type = "anixcore"
		c.AnixcoreConfig = NewAnixcoreConfig()
		if installedAnxNode() {
			c.AnixcoreConfig.BinaryPath = InstalledAnxNodePath
			c.AnixcoreConfig.AnxLine = true
		}
		return nil
	case "wireguard":
		c.WireGuardConfig = NewWireGuardConfig()
		return json.Unmarshal(b, c.WireGuardConfig)
	case "anixcore":
		c.AnixcoreConfig = NewAnixcoreConfig()
		return json.Unmarshal(b, c.AnixcoreConfig)
	}
	return nil
}

// installedAnxNode tells whether an Agent upgrade installed anx-node
// (InstalledAnxNodePath); a variable for the tests.
var installedAnxNode = func() bool {
	info, err := os.Stat(InstalledAnxNodePath)
	return err == nil && info.Mode().IsRegular()
}
