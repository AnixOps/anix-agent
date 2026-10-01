package cmd

import (
	"os"
	"time"

	"github.com/AnixOps/anix-agent/v4/api/panel"
	_ "github.com/AnixOps/anix-agent/v4/core/imports"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// LocalTimeFormatter 自定义格式化器，使用本地时间
type LocalTimeFormatter struct {
	log.TextFormatter
}

func (f *LocalTimeFormatter) Format(entry *log.Entry) ([]byte, error) {
	entry.Time = entry.Time.Local()
	return f.TextFormatter.Format(entry)
}

var command = &cobra.Command{
	Use:   cliName,
	Short: productName + " - multi-protocol proxy node agent",
	Long: `AnixOps Agent is a multi-protocol proxy node agent that supports
	VMess, VLESS, Trojan, Shadowsocks, Hysteria, Hysteria2, TUIC, and AnyTLS protocols.

	Usage:
	  anix-agent -c config.json           Run with specified config file
	  anix-agent server -c config.json    Run with specified config file
	  anix-agent server                   Run with default config file
	  anix-agent version                  Show version information`,
	// 直接运行 anix-agent 或 anix-agent -c xxx 时执行 server 命令
	RunE: serverHandle,
}

func init() {
	// 设置日志使用本地时间
	log.SetFormatter(&LocalTimeFormatter{
		TextFormatter: log.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.DateTime,
		},
	})

	// 添加全局 config 参数到根命令
	command.PersistentFlags().StringVarP(&config, "config", "c", getDefaultConfigPath(), "config file path")
	command.PersistentFlags().BoolVarP(&watch, "watch", "w", true, "watch file path change")
	command.PersistentFlags().BoolVarP(&reRegister, "re-register", "r", false, "force re-register node (delete existing credentials)")
}

func Run() error {
	panel.Version = version

	// 检查是否是子命令（server, version 等）
	if len(os.Args) > 1 {
		firstArg := os.Args[1]
		// 如果第一个参数不是以 - 开头，且是已知的子命令，正常执行
		if firstArg != "-c" && firstArg != "--config" &&
			firstArg != "-w" && firstArg != "--watch" &&
			firstArg != "-h" && firstArg != "--help" &&
			!isSubCommand(firstArg) {
			// 未知参数，显示帮助
		}
	}

	err := command.Execute()
	if err != nil {
		log.WithField("err", err).Error("Execute command failed")
	}
	return err
}

// isSubCommand 检查是否是已知的子命令
func isSubCommand(arg string) bool {
	for _, cmd := range command.Commands() {
		if cmd.Name() == arg {
			return true
		}
	}
	return false
}
