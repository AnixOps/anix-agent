package conf

// AnixcoreConfig drives the AnixOps node kernel (`anixcore`, from
// networkcore_anixops) through its local management API.
type AnixcoreConfig struct {
	// BinaryPath is the anixcore executable the core starts.
	BinaryPath string `json:"BinaryPath"`
	// RuntimeDir holds the generated anixcore config file. It defaults
	// below the unit's RuntimeDirectory: /etc/anixops/agent is read only
	// under ProtectSystem=strict.
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
	// AnxLineApiTLS is the client certificate for an AnxLineApiAddress
	// served with mTLS (anx-node `anx_line.mgmt_tls`, required off
	// loopback). A started anx-node needs none: the core makes a one-off
	// bundle when the binary supports it.
	AnxLineApiTLS *ManagementTLSConfig `json:"AnxLineApiTLS"`
}

// ManagementTLSConfig is the Agent's side of an mTLS management API (anx
// spec §7): its client certificate and key, the CA the server's
// certificate chains to, and optionally the name to check it against (the
// dialed host otherwise).
type ManagementTLSConfig struct {
	CertFile   string `json:"CertFile"`
	KeyFile    string `json:"KeyFile"`
	CAFile     string `json:"CAFile"`
	ServerName string `json:"ServerName"`
}

// InstalledAnxNodePath is where Agent upgrades install anx-node, the
// release of our kernel with ANX (upgrade.DefaultLibDir +
// upgrade.KernelBinary). A configuration without cores runs it as the
// anixcore core with AnxLine when it is there.
const InstalledAnxNodePath = "/usr/lib/anixops-agent/anx-node"

// InstalledAnxServerPath is where Agent upgrades install anx-server from
// the same release (upgrade.DefaultLibDir + upgrade.ServerBinary); the
// Agent runs it for the accepting anx_line ends, before one on PATH.
const InstalledAnxServerPath = "/usr/lib/anixops-agent/anx-server"

func NewAnixcoreConfig() *AnixcoreConfig {
	return &AnixcoreConfig{
		BinaryPath:          "anixcore",
		RuntimeDir:          DefaultRuntimeRoot + "/anixcore",
		StartTimeoutSeconds: 10,
		RestartDelaySeconds: 3,
	}
}
