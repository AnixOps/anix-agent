package cmd

import (
	"fmt"

	"github.com/AnixOps/anix-agent/v5/common/exec"
	"github.com/AnixOps/anix-agent/v5/common/layout"
)

const (
	red         = "\033[0;31m"
	green       = "\033[0;32m"
	yellow      = "\033[0;33m"
	plain       = "\033[0m"
	cliName     = "anix-agent"
	productName = "AnixOps Agent"
)

var (
	serviceName       = layout.Service + ".service"
	defaultConfigPath = layout.ConfigDir + "/config.json"
)

func checkRunning() (bool, error) {
	_, err := exec.RunCommandByShell("systemctl is-active --quiet " + serviceName)
	return err == nil, nil
}

func Err(msg ...any) string {
	return red + fmt.Sprint(msg...) + plain
}

func Ok(msg ...any) string {
	return green + fmt.Sprint(msg...) + plain
}

func Warn(msg ...any) string {
	return yellow + fmt.Sprint(msg...) + plain
}
