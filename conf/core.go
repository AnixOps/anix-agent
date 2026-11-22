package conf

import (
	"encoding/json"
	"os"
)

// CoreConfig is one entry of Cores. Its settings are members of the same
// object, decoded into the config of its Type.
type CoreConfig struct {
	Type            string           `json:"Type"`
	Name            string           `json:"Name"`
	WireGuardConfig *WireGuardConfig `json:"-"`
	AnixcoreConfig  *AnixcoreConfig  `json:"-"`
}

// installedAnxNode tells whether InstalledAnxNodePath is a regular file.
var installedAnxNode = func() bool {
	info, err := os.Stat(InstalledAnxNodePath)
	return err == nil && info.Mode().IsRegular()
}

type coreConfig CoreConfig

func (c *CoreConfig) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, (*coreConfig)(c)); err != nil {
		return err
	}
	switch c.Type {
	case "anixcore":
		c.AnixcoreConfig = NewAnixcoreConfig()
		return json.Unmarshal(data, c.AnixcoreConfig)
	case "wireguard":
		c.WireGuardConfig = NewWireGuardConfig()
		return json.Unmarshal(data, c.WireGuardConfig)
	case "xray", "sing", "hysteria2":
		// Retired cores run on anixcore, as anx-node when it is installed.
		c.Type = "anixcore"
		c.AnixcoreConfig = NewAnixcoreConfig()
		if installedAnxNode() {
			c.AnixcoreConfig.BinaryPath = InstalledAnxNodePath
			c.AnixcoreConfig.AnxLine = true
		}
	}
	return nil
}
