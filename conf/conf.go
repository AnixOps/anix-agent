package conf

import (
	"fmt"
	"io"
	"os"

	"github.com/AnixOps/anix-agent/v4/common/json5"

	"encoding/json/v2"
)

type Conf struct {
	Environment string       `json:"Environment"`
	LogConfig   LogConfig    `json:"Log"`
	CoresConfig []CoreConfig `json:"Cores"`
	NodeConfig  []NodeConfig `json:"Nodes"`
}

func New() *Conf {
	return &Conf{
		Environment: "development",
		LogConfig: LogConfig{
			Level:  "info",
			Output: "",
		},
	}
}

func (p *Conf) LoadFromPath(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open config file error: %s", err)
	}
	defer f.Close()

	reader := json5.NewTrimNodeReader(f)
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("read config file error: %s", err)
	}

	err = json.Unmarshal(data, p)
	if err != nil {
		return fmt.Errorf("unmarshal config error: %s", err)
	}
	if err = p.ValidateForProduction(); err != nil {
		return err
	}

	return nil
}
