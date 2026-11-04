package conf

import "github.com/AnixOps/anix-agent/v5/common/layout"

type WireGuardConfig struct {
	RuntimeDir                    string `json:"RuntimeDir"`
	WGPath                        string `json:"WGPath"`
	IPPath                        string `json:"IPPath"`
	TCPath                        string `json:"TCPath"`
	OnlineHandshakeTimeoutSeconds int64  `json:"OnlineHandshakeTimeoutSeconds"`
}

func NewWireGuardConfig() *WireGuardConfig {
	return &WireGuardConfig{
		RuntimeDir:                    layout.ConfigDir + "/wireguard",
		WGPath:                        "wg",
		IPPath:                        "ip",
		TCPath:                        "tc",
		OnlineHandshakeTimeoutSeconds: 180,
	}
}
