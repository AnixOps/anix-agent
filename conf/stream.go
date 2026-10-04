package conf

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
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
const DefaultAgentStreamStateDir = "/var/lib/anixops-agent/stream"

// AgentStreamConfig is the data plane of the Agent control stream
// (AgentControlEnabled): the node's configuration (config.v1) and users
// (users.v1) from Control, and its traffic, online IPs, logs and status
// (reports.v1) and plugin package reports (package-reports.v1) to Control,
// instead of UniProxy, the v2board gRPC services and the WebSocket.
type AgentStreamConfig struct {
	// DataPlane is "auto" (default) or "off".
	DataPlane string `json:"DataPlane"`
	// StateDir keeps what the stream delivered and the report spool, per
	// node (StateDir/proxy-<NodeID>), so a restart while Control is
	// unreachable runs the last applied configuration and users and still
	// delivers its reports; an absolute path, default
	// /var/lib/anixops-agent/stream.
	StateDir string `json:"StateDir"`
	// SpoolMaxMB bounds the traffic report spool (default 64 MiB);
	// LogSpoolMaxMB the log spool (default 16 MiB). The oldest batches are
	// dropped (and counted) when a new one does not fit.
	SpoolMaxMB    int `json:"SpoolMaxMB"`
	LogSpoolMaxMB int `json:"LogSpoolMaxMB"`
	// SpoolMaxAgeHours drops spooled batches older than it (default 72, at
	// most 144: Control remembers a batch id for 7 days, and a batch resent
	// after that would count twice).
	SpoolMaxAgeHours int `json:"SpoolMaxAgeHours"`
}

// Spool bounds of AgentStream, defaulted.
const (
	DefaultAgentStreamSpoolMaxMB    = 64
	DefaultAgentStreamLogSpoolMaxMB = 16
	DefaultAgentStreamSpoolMaxAge   = 72
	MaxAgentStreamSpoolMaxAge       = 144
)

// SpoolBytes is the traffic spool bound in bytes.
func (c AgentStreamConfig) SpoolBytes() int64 {
	if c.SpoolMaxMB > 0 {
		return int64(c.SpoolMaxMB) << 20
	}
	return DefaultAgentStreamSpoolMaxMB << 20
}

// LogSpoolBytes is the log spool bound in bytes.
func (c AgentStreamConfig) LogSpoolBytes() int64 {
	if c.LogSpoolMaxMB > 0 {
		return int64(c.LogSpoolMaxMB) << 20
	}
	return DefaultAgentStreamLogSpoolMaxMB << 20
}

// SpoolMaxAge is the spool's age bound.
func (c AgentStreamConfig) SpoolMaxAge() time.Duration {
	if c.SpoolMaxAgeHours > 0 {
		return time.Duration(c.SpoolMaxAgeHours) * time.Hour
	}
	return DefaultAgentStreamSpoolMaxAge * time.Hour
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
	if c.SpoolMaxMB < 0 || c.LogSpoolMaxMB < 0 || c.SpoolMaxMB > 4096 || c.LogSpoolMaxMB > 4096 {
		return fmt.Errorf("AgentStream.SpoolMaxMB and LogSpoolMaxMB must be within 0 (default) and 4096")
	}
	if c.SpoolMaxAgeHours < 0 || c.SpoolMaxAgeHours > MaxAgentStreamSpoolMaxAge {
		return fmt.Errorf("AgentStream.SpoolMaxAgeHours must be within 0 (default %d) and %d: Control remembers a report batch for 7 days", DefaultAgentStreamSpoolMaxAge, MaxAgentStreamSpoolMaxAge)
	}
	return nil
}
