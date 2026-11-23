package conf

import (
	jsonv2 "encoding/json/v2"
	"fmt"
	"os"

	"github.com/AnixOps/anix-agent/v5/anxserver"
)

// Conf is the Agent's config.json.
type Conf struct {
	// Environment is development (default), test, staging or production.
	Environment    string                    `json:"Environment"`
	LogConfig      LogConfig                 `json:"Log"`
	CoresConfig    []CoreConfig              `json:"Cores"`
	NodeConfig     []NodeConfig              `json:"Nodes"`
	Forward        *ForwardConfig            `json:"Forward"`
	AnxKeyRotation *anxserver.RotationConfig `json:"AnxKeyRotation"`
}

// New returns the defaults.
func New() *Conf {
	return &Conf{
		Environment: "development",
		LogConfig:   LogConfig{Level: "info"},
	}
}

// LoadFromPath reads, decodes and validates the file at path.
func (p *Conf) LoadFromPath(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %s: %w", path, err)
	}
	if err := jsonv2.Unmarshal(stripJSONC(data), p); err != nil {
		return fmt.Errorf("decode config %s: %w", path, err)
	}
	for _, check := range []func() error{
		p.normalizeAgentNodes,
		p.validateAgentIdentities,
		p.validateNodeCredentials,
		p.Forward.Validate,
		p.AnxKeyRotation.Validate,
		p.ValidateForProduction,
	} {
		if err := check(); err != nil {
			return fmt.Errorf("config %s: %w", path, err)
		}
	}
	return nil
}
