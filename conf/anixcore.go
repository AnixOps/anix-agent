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
	// AnxLine says BinaryPath is anx-node: the core then runs the dialing
	// ends of the network model's anx_line transports as anx-node's
	// ANX-Line links. A started anx-node gets its ANX-Line management API
	// on a loopback port; one that runs on its own (ApiAddress) names it in
	// AnxLineApiAddress (its `anx_line.mgmt_listen`).
	AnxLine           bool   `json:"AnxLine"`
	AnxLineApiAddress string `json:"AnxLineApiAddress"`
}

// InstalledAnxNodePath is where Agent upgrades install anx-node, the
// release of our kernel with ANX (upgrade.DefaultLibDir +
// upgrade.KernelBinary). A configuration without cores runs it as the
// anixcore core with AnxLine when it is there.
const InstalledAnxNodePath = "/usr/lib/anixops-agent/anx-node"

func NewAnixcoreConfig() *AnixcoreConfig {
	return &AnixcoreConfig{
		BinaryPath:          "anixcore",
		RuntimeDir:          "/etc/anixops/agent/anixcore",
		StartTimeoutSeconds: 10,
		RestartDelaySeconds: 3,
	}
}
