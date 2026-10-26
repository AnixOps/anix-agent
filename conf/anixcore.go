package conf

// AnixcoreConfig drives the AnixOps node kernel (`anixcore`, from
// networkcore_anixops) through its local management API.
type AnixcoreConfig struct {
	// BinaryPath is the anixcore executable the core starts.
	BinaryPath string `json:"BinaryPath"`
	// RuntimeDir holds the generated anixcore config file.
	RuntimeDir string `json:"RuntimeDir"`
	// ApiAddress and ApiToken, when both are set, point at an anixcore that
	// runs on its own (for example under systemd): the core connects to it
	// instead of starting one.
	ApiAddress string `json:"ApiAddress"`
	ApiToken   string `json:"ApiToken"`
	// AllowPrivateTargets lets clients reach loopback and private addresses.
	AllowPrivateTargets bool `json:"AllowPrivateTargets"`
	// StartTimeoutSeconds bounds the wait for a started anixcore's API.
	StartTimeoutSeconds int64 `json:"StartTimeoutSeconds"`
	// RestartDelaySeconds is the pause before restarting an anixcore that
	// exited; its nodes and users are added again.
	RestartDelaySeconds int64 `json:"RestartDelaySeconds"`
}

func NewAnixcoreConfig() *AnixcoreConfig {
	return &AnixcoreConfig{
		BinaryPath:          "anixcore",
		RuntimeDir:          "/etc/anixops/agent/anixcore",
		StartTimeoutSeconds: 10,
		RestartDelaySeconds: 3,
	}
}
