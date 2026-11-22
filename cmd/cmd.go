// Package cmd is the anix-agent command line.
package cmd

import (
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	_ "github.com/AnixOps/anix-agent/v5/core/imports"
)

var (
	config string
	watch  bool
)

var command = &cobra.Command{
	Use:   commandName,
	Short: productName + ": runs the nodes AnixOps Control assigns to this machine",
	Long: productName + ` runs the nodes AnixOps Control assigns to this machine.
Without a command it runs the server.

  ` + commandName + ` server -c ` + defaultConfigPath + `
      run the Agent (what the service runs)
  ` + commandName + ` join --control <url> --grpc <host:port> --token-file <file>
      join this machine to Control as a node
  ` + commandName + ` version
      print the version`,
	RunE: serverHandle,
	// Run logs the error; usage is in --help.
	SilenceErrors: true,
	SilenceUsage:  true,
}

func init() {
	flags := command.PersistentFlags()
	flags.StringVarP(&config, "config", "c", defaultConfigPath, "configuration file")
	flags.BoolVarP(&watch, "watch", "w", true, "reload when the configuration file changes")
}

// Run runs the command line.
func Run() error {
	log.SetFormatter(&logFormatter{TextFormatter: log.TextFormatter{FullTimestamp: true, TimestampFormat: time.DateTime}})
	panel.Version = version
	err := command.Execute()
	var exit *exitError
	if err != nil && !errors.As(err, &exit) {
		log.Error(err)
	}
	return err
}
