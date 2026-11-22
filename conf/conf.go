// Package conf is the Agent's configuration file.
package conf

import (
	"encoding/json/v2"
	"fmt"
	"os"

	"github.com/AnixOps/anix-agent/v5/anxline"
	"github.com/AnixOps/anix-agent/v5/anxserver"
)

// Conf is config.json.
type Conf struct {
	Environment string       `json:"Environment"`
	LogConfig   LogConfig    `json:"Log"`
	CoresConfig []CoreConfig `json:"Cores"`
	NodeConfig  []NodeConfig `json:"Nodes"`
	// Forward turns on the forward component (forward.go).
	Forward *ForwardConfig `json:"Forward"`
	// AnxLine is the host side of ANX-Line links: fake-TCP RST rules and
	// MPTCP path switching (anxline).
	AnxLine *anxline.Config `json:"AnxLine"`
	// AnxKeyRotation rotates the anx-server key periodically and reports
	// each new public key to Control once every process serves it. Off by
	// default; needs an anx-server with rotate-key.
	AnxKeyRotation *anxserver.RotationConfig `json:"AnxKeyRotation"`
}

// LogConfig is the log level (debug, info, warn, error) and an optional
// file to append to instead of stdout.
type LogConfig struct {
	Level  string `json:"Level"`
	Output string `json:"Output"`
}

func New() *Conf {
	return &Conf{Environment: "development", LogConfig: LogConfig{Level: "info"}}
}

// LoadFromPath reads the file into p and validates it. The file may carry
// comments and trailing commas (see stripJSONComments).
func (p *Conf) LoadFromPath(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(stripJSONComments(data), p); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	for _, check := range []func() error{
		p.normalizeAgentNodes,
		p.validateAgentIdentities,
		p.validateNodeCredentials,
		p.Forward.Validate,
		p.AnxLine.Validate,
		p.AnxKeyRotation.Validate,
		p.ValidateForProduction,
	} {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}
