package cmd

import (
	"errors"
	"os"
	"regexp"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	_ "github.com/AnixOps/anix-agent/v5/core/imports"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// LocalTimeFormatter 自定义格式化器，使用本地时间
type LocalTimeFormatter struct {
	log.TextFormatter
}

// nodeTagPattern is a node's tag, "[<api host>]-<protocol>:<id>"; the log
// writes it as "node-<id>" so the journal names no protocol or Control host.
var nodeTagPattern = regexp.MustCompile(`\[[^\]\s]+\]-[a-z0-9]+:([0-9]+)`)

func (f *LocalTimeFormatter) Format(entry *log.Entry) ([]byte, error) {
	entry.Time = entry.Time.Local()
	line, err := f.TextFormatter.Format(entry)
	return nodeTagPattern.ReplaceAll(line, []byte("node-$1")), err
}

var command = &cobra.Command{
	Use:   cliName,
	Short: productName + " node agent",
	Long: `AnixOps Agent runs a node for AnixOps Control.

	Usage:
	  anix-agent -c config.json           Run with specified config file
	  anix-agent server -c config.json    Run with specified config file
	  anix-agent server                   Run with default config file
	  anix-agent join --control <url> --grpc <host:port> --token-file <file>
	                                      Join this machine to Control as a node
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
	var exit *exitError
	if err != nil && !errors.As(err, &exit) {
		// A command with its own exit status printed its error.
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
