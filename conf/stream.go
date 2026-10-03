package conf

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Agent stream data-plane modes (AgentStream.DataPlane).
const (
	// AgentStreamDataPlaneAuto moves the node's data onto the Agent control
	// stream when Control serves it (HelloAck.server_capabilities), and
	// keeps the legacy transports otherwise. The default.
	AgentStreamDataPlaneAuto = "auto"
	// AgentStreamDataPlaneOff keeps the data on the legacy transports; the
	// stream carries operations only. A rollback switch: Control 4.2
	// (agent_control.mtls: required) refuses the legacy Agent channels.
	AgentStreamDataPlaneOff = "off"
)

// DefaultAgentStreamStateDir is where the data-plane state lives.
const DefaultAgentStreamStateDir = "/var/lib/anix-agent/stream"

// AgentStreamConfig is the data plane of the Agent control stream
// (AgentControlEnabled): the node's configuration from Control's
// ConfigSnapshot (config.v1) instead of UniProxy, the v2board gRPC services
// and the WebSocket.
type AgentStreamConfig struct {
	// DataPlane is "auto" (default) or "off".
	DataPlane string `json:"DataPlane"`
	// StateDir keeps what the stream delivered, per node
	// (StateDir/proxy-<NodeID>), so a restart while Control is unreachable
	// runs the last applied configuration; an absolute path, default
	// /var/lib/anix-agent/stream.
	StateDir string `json:"StateDir"`
}

// DataPlaneMode is DataPlane, defaulted and lowercased.
func (c AgentStreamConfig) DataPlaneMode() string {
	if mode := strings.ToLower(strings.TrimSpace(c.DataPlane)); mode != "" {
		return mode
	}
	return AgentStreamDataPlaneAuto
}

// Dir is StateDir, defaulted.
func (c AgentStreamConfig) Dir() string {
	if dir := strings.TrimSpace(c.StateDir); dir != "" {
		return filepath.Clean(dir)
	}
	return DefaultAgentStreamStateDir
}

// Validate checks the settings.
func (c AgentStreamConfig) Validate() error {
	switch c.DataPlaneMode() {
	case AgentStreamDataPlaneAuto, AgentStreamDataPlaneOff:
	default:
		return fmt.Errorf("AgentStream.DataPlane must be %q or %q, not %q", AgentStreamDataPlaneAuto, AgentStreamDataPlaneOff, c.DataPlane)
	}
	if dir := strings.TrimSpace(c.StateDir); dir != "" && !filepath.IsAbs(dir) {
		return fmt.Errorf("AgentStream.StateDir %q must be an absolute path", c.StateDir)
	}
	return nil
}
