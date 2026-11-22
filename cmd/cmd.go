// Package cmd is the anix-agent command line.
package cmd

import (
	"errors"
	"regexp"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	_ "github.com/AnixOps/anix-agent/v5/core/imports"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// The bare command runs the agent like "server" does, so that
// "anix-agent -c config.json" keeps working.
var command = &cobra.Command{
	Use:   cliName,
	Short: productName + " node agent",
	Long: `AnixOps Agent runs a node for AnixOps Control.

  anix-agent server [-c config.json]   Run the agent (default config: ` + defaultConfigPath + `)
  anix-agent -c config.json            Same as server
  anix-agent join --control <url> --grpc <host:port> --token-file <file>
                                       Join this machine to Control as a node
  anix-agent version                   Print the version`,
	RunE: serverHandle,
}

func init() {
	log.SetFormatter(&logFormatter{TextFormatter: log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.DateTime,
	}})
}

// nodeTag matches a node's tag, "[<api host>]-<protocol>:<id>"; the log
// writes it as "node-<id>" so the journal names no protocol or Control host.
var nodeTag = regexp.MustCompile(`\[[^\]\s]+\]-[a-z0-9]+:([0-9]+)`)

// logFormatter writes local times and hides node tags.
type logFormatter struct {
	log.TextFormatter
}

func (f *logFormatter) Format(entry *log.Entry) ([]byte, error) {
	entry.Time = entry.Time.Local()
	line, err := f.TextFormatter.Format(entry)
	return nodeTag.ReplaceAll(line, []byte("node-$1")), err
}

// Run executes the command line; ExitCode maps its error to an exit status.
func Run() error {
	panel.Version = version
	err := command.Execute()
	var exit *exitError
	if err != nil && !errors.As(err, &exit) {
		// A command with its own exit status has printed its error.
		log.WithError(err).Error("Command failed")
	}
	return err
}
