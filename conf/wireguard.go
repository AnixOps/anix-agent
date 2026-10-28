package conf

type WireGuardConfig struct {
	RuntimeDir                    string `json:"RuntimeDir"`
	WGPath                        string `json:"WGPath"`
	IPPath                        string `json:"IPPath"`
	TCPath                        string `json:"TCPath"`
	OnlineHandshakeTimeoutSeconds int64  `json:"OnlineHandshakeTimeoutSeconds"`
}

func NewWireGuardConfig() *WireGuardConfig {
	return &WireGuardConfig{
		RuntimeDir:                    "/etc/anixops/agent/wireguard",
		WGPath:                        "wg",
		IPPath:                        "ip",
		TCPath:                        "tc",
		OnlineHandshakeTimeoutSeconds: 180,
	}
}
