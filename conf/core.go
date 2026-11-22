package conf

import (
	"encoding/json"
	"os"
)

// CoreConfig is one entry of "Cores": its Type picks the settings it
// carries (anixcore or wireguard).
type CoreConfig struct {
	Type            string           `json:"Type"`
	Name            string           `json:"Name"`
	WireGuardConfig *WireGuardConfig `json:"-"`
	AnixcoreConfig  *AnixcoreConfig  `json:"-"`
}

func (c *CoreConfig) UnmarshalJSON(data []byte) error {
	type plain CoreConfig
	if err := json.Unmarshal(data, (*plain)(c)); err != nil {
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
		// The third-party cores are gone: a configuration that still lists
		// one runs on anixcore: the anx-node Agent upgrades install when it
		// is there, like a configuration without cores, else anixcore on PATH.
		c.Type = "anixcore"
		c.AnixcoreConfig = NewAnixcoreConfig()
		if installedAnxNode() {
			c.AnixcoreConfig.BinaryPath = InstalledAnxNodePath
			c.AnixcoreConfig.AnxLine = true
		}
	}
	return nil
}

// installedAnxNode tells whether an Agent upgrade installed anx-node
// (InstalledAnxNodePath); a variable for the tests.
var installedAnxNode = func() bool {
	info, err := os.Stat(InstalledAnxNodePath)
	return err == nil && info.Mode().IsRegular()
}
