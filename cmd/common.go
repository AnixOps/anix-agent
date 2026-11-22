package cmd

import (
	"fmt"

	"github.com/AnixOps/anix-agent/v5/common/layout"
)

const (
	cliName     = "anix-agent"
	productName = "AnixOps Agent"
)

var (
	serviceName       = layout.Service + ".service"
	defaultConfigPath = layout.ConfigDir + "/config.json"
)

// colored wraps msg in an ANSI color for terminal output.
func colored(color string, msg []any) string {
	return "\x1b[" + color + "m" + fmt.Sprint(msg...) + "\x1b[0m"
}

func Err(msg ...any) string  { return colored("31", msg) }
func Ok(msg ...any) string   { return colored("32", msg) }
func Warn(msg ...any) string { return colored("33", msg) }
