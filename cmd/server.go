package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/AnixOps/anix-agent/v5/anxline"
	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/common/hosttune"
	"github.com/AnixOps/anix-agent/v5/conf"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	"github.com/AnixOps/anix-agent/v5/forward"
	"github.com/AnixOps/anix-agent/v5/node"
	"github.com/AnixOps/anix-agent/v5/upgrade"
)

func init() {
	command.AddCommand(&cobra.Command{
		Use:   "server",
		Short: "Run the " + productName,
		Args:  cobra.NoArgs,
		RunE:  serverHandle,
	})
}

func serverHandle(_ *cobra.Command, _ []string) error {
	return runServer(config, watch)
}

// runServer runs the Agent from the configuration at path until SIGINT or
// SIGTERM.
func runServer(path string, watchConfig bool) error {
	log.Infof("%s %s", productName, version)
	c := conf.New()
	if err := c.LoadFromPath(path); err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	applyLogConfig(c.LogConfig)
	migrateLegacyPaths(c)
	tuneHostTCP()
	upgrade.Shared(panel.Version).LogLastResult()

	var component *forward.Component
	proxyNodeID := 0
	if c.Forward.Enabled() {
		var err error
		component, proxyNodeID, err = node.NewForwardComponent(c.Forward, c.NodeConfig)
		if err != nil {
			return fmt.Errorf("start forwarding: %w", err)
		}
		defer component.Close()
		if c.Forward.ForwardNodeOnly() {
			forwardNode, err := node.StartForward(c.Forward, component)
			if err != nil {
				return fmt.Errorf("start the forward node: %w", err)
			}
			defer forwardNode.Close()
			if len(c.CoresConfig) == 0 && len(c.NodeConfig) == 0 {
				waitForSignal()
				return nil
			}
		}
	}

	if c.AnxLine.Enabled() {
		manager, err := anxline.Start(*c.AnxLine, anxline.Options{})
		if err != nil {
			return fmt.Errorf("start ANX-Line: %w", err)
		}
		defer manager.Close()
	}

	if c.AnxKeyRotation.Enabled() {
		if rotator := node.KeyRotator(*c.AnxKeyRotation); rotator != nil {
			rotator.Start()
			defer rotator.Close()
		} else {
			log.Warn("AnxKeyRotation is on, but this host has no anx-server: no key to rotate")
		}
	}

	nodes := node.New()
	if c.Forward.Enabled() && !c.Forward.ForwardNodeOnly() {
		nodes.SetForward(component, proxyNodeID)
	}
	var (
		mu      sync.Mutex
		core    vCore.Core
		stopped bool
	)
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		stopped = true
		nodes.Close()
		if core != nil {
			if err := core.Close(); err != nil {
				log.WithError(err).Error("close core")
			}
		}
	}()
	core, err := startCore(c)
	if err != nil {
		return err
	}
	if err := nodes.Start(c.NodeConfig, core); err != nil {
		return fmt.Errorf("start nodes: %w", err)
	}

	if watchConfig {
		reload := func() {
			mu.Lock()
			defer mu.Unlock()
			if stopped {
				return
			}
			log.Info("configuration changed, reloading")
			migrateLegacyPaths(c)
			nodes.Close()
			if err := core.Close(); err != nil {
				log.WithError(err).Error("close core, reload stopped")
				return
			}
			core = nil
			next, err := startCore(c)
			if err != nil {
				log.WithError(err).Error("reload")
				return
			}
			core = next
			if err := nodes.Start(c.NodeConfig, core); err != nil {
				log.WithError(err).Error("reload: start nodes")
			}
			runtime.GC()
		}
		if err := c.Watch(path, reload); err != nil {
			return fmt.Errorf("watch config: %w", err)
		}
	}
	waitForSignal()
	return nil
}

// startCore builds and starts the configured core.
func startCore(c *conf.Conf) (vCore.Core, error) {
	core, err := vCore.NewForConfig(c.CoresConfig, len(c.NodeConfig))
	if err != nil {
		return nil, fmt.Errorf("build core: %w", err)
	}
	if err := core.Start(); err != nil {
		return nil, fmt.Errorf("start core: %w", err)
	}
	return core, nil
}

func waitForSignal() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
	signal.Stop(signals)
}

// applyLogConfig sets the log level and output of the Log section.
func applyLogConfig(c conf.LogConfig) {
	if level, err := log.ParseLevel(c.Level); err == nil {
		log.SetLevel(level)
	}
	if c.Output == "" {
		return
	}
	file, err := os.OpenFile(c.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.WithError(err).Error("open log output, logging to stdout")
		return
	}
	log.SetOutput(file)
}

// migrateLegacyPaths moves the earlier default directories the
// configuration uses to the current layout, as far as the Agent's user can.
func migrateLegacyPaths(c *conf.Conf) {
	for _, report := range c.MigrateLegacyDefaults(conf.MigrateOptions{}) {
		entry := log.WithFields(log.Fields{"what": report.Path.Name, "from": report.Path.Old, "to": report.Path.New})
		if report.Err != nil {
			entry.WithError(report.Err).Warn("could not copy the earlier default directory, still using it: run `" + commandName + " migrate-paths` as root")
			continue
		}
		entry.Info("copied the earlier default directory; it is no longer used")
	}
}

// tuneHostTCP applies the host TCP settings on Linux, unless
// ANIXOPS_TCP_TUNE=0.
func tuneHostTCP() {
	if runtime.GOOS != "linux" || os.Getenv("ANIXOPS_TCP_TUNE") == "0" {
		return
	}
	changed, err := hosttune.ApplyTCP("/proc/sys")
	if len(changed) > 0 {
		log.WithField("changed", strings.Join(changed, " ")).Info("tuned host TCP")
	}
	if err != nil {
		log.WithError(err).Warn("tune host TCP")
	}
}
