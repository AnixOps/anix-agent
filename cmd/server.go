package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/AnixOps/anix-agent/v5/anxline"
	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/common/hosttune"
	"github.com/AnixOps/anix-agent/v5/conf"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	"github.com/AnixOps/anix-agent/v5/forward"
	"github.com/AnixOps/anix-agent/v5/node"
	"github.com/AnixOps/anix-agent/v5/upgrade"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	config string
	watch  bool
)

func init() {
	flags := command.PersistentFlags()
	flags.StringVarP(&config, "config", "c", defaultConfigPath, "config file path")
	flags.BoolVarP(&watch, "watch", "w", true, "reload when the config file changes")
	command.AddCommand(&cobra.Command{
		Use:   "server",
		Short: "Run " + productName,
		Args:  cobra.NoArgs,
		RunE:  serverHandle,
	})
}

func serverHandle(_ *cobra.Command, _ []string) error {
	log.Info(versionLine())
	c := conf.New()
	if err := c.LoadFromPath(config); err != nil {
		return fmt.Errorf("load config %s: %w", config, err)
	}
	setupLog(c.LogConfig)
	migrateLegacyPaths(c)
	tuneHostTCP()
	// The outcome of the last Control-pushed upgrade, which restarted us.
	upgrade.Shared(panel.Version).LogLastResult()

	// Forwarding (F3b): the drivers are probed and the persisted state is
	// re-applied before any control stream connects.
	var forwardComponent *forward.Component
	forwardProxyNode := 0
	if c.Forward.Enabled() {
		var err error
		forwardComponent, forwardProxyNode, err = node.NewForwardComponent(c.Forward, c.NodeConfig)
		if err != nil {
			return fmt.Errorf("start forwarding: %w", err)
		}
		defer forwardComponent.Close()
		if c.Forward.ForwardNodeOnly() {
			forwardNode, err := node.StartForward(c.Forward, forwardComponent)
			if err != nil {
				return fmt.Errorf("start the forward node: %w", err)
			}
			defer forwardNode.Close()
			log.Info("Forward node started")
			if len(c.CoresConfig) == 0 && len(c.NodeConfig) == 0 {
				// A forward node only: no proxy core to run.
				waitForExitSignal()
				return nil
			}
		}
	}

	// ANX-Line host support (fake-TCP RST rules, MPTCP path switching).
	if c.AnxLine.Enabled() {
		anxLine, err := anxline.Start(*c.AnxLine, anxline.Options{})
		if err != nil {
			return fmt.Errorf("start ANX-Line host support: %w", err)
		}
		defer anxLine.Close()
	}

	// Periodic anx-server key rotation (off by default).
	if c.AnxKeyRotation.Enabled() {
		if rotator := node.KeyRotator(*c.AnxKeyRotation); rotator != nil {
			rotator.Start()
			defer rotator.Close()
			log.Info("anx-server key rotation started")
		} else {
			log.Warn("AnxKeyRotation is on but this host has no anx-server: nothing to rotate")
		}
	}

	plane := &dataPlane{nodes: node.New()}
	if forwardComponent != nil && !c.Forward.ForwardNodeOnly() {
		plane.nodes.SetForward(forwardComponent, forwardProxyNode)
	}
	defer plane.close()
	if err := plane.start(c); err != nil {
		return err
	}
	if watch {
		// Watch loads the changed file into c before it calls back.
		if err := c.Watch(config, func() { plane.reload(c) }); err != nil {
			return fmt.Errorf("start config watcher: %w", err)
		}
	}
	waitForExitSignal()
	return nil
}

// setupLog applies the configured log level and output file.
func setupLog(c conf.LogConfig) {
	if level, err := log.ParseLevel(c.Level); err == nil {
		log.SetLevel(level)
	}
	if c.Output == "" {
		return
	}
	f, err := os.OpenFile(c.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.WithError(err).Error("Open log file failed, logging to stdout")
		return
	}
	log.SetOutput(f)
}

// dataPlane is the running core and the nodes on it; a config reload
// replaces both.
type dataPlane struct {
	mu    sync.Mutex
	core  vCore.Core
	nodes *node.Node
}

func (d *dataPlane) start(c *conf.Conf) error {
	core, err := vCore.NewForConfig(c.CoresConfig, len(c.NodeConfig))
	if err != nil {
		return fmt.Errorf("create core: %w", err)
	}
	if err := core.Start(); err != nil {
		return fmt.Errorf("start core: %w", err)
	}
	d.core = core
	log.Info("Core ", core.Type(), " started")
	if err := d.nodes.Start(c.NodeConfig, core); err != nil {
		return fmt.Errorf("start nodes: %w", err)
	}
	log.Info("Nodes started")
	return nil
}

func (d *dataPlane) reload(c *conf.Conf) {
	d.mu.Lock()
	defer d.mu.Unlock()
	migrateLegacyPaths(c)
	d.nodes.Close()
	if err := d.core.Close(); err != nil {
		log.WithError(err).Error("Reload: close core failed")
		return
	}
	d.core = nil
	if err := d.start(c); err != nil {
		log.WithError(err).Error("Reload failed")
		return
	}
	runtime.GC()
}

func (d *dataPlane) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.core != nil {
		_ = d.core.Close()
	}
}

// migrateLegacyPaths moves the earlier default directories the
// configuration uses to the O1 layout (conf.LegacyDefaultPaths), once, as
// the Agent's own user. A copy that fails leaves the Agent on the old
// directory; an installer running as root migrates with
// "anix-agent migrate-paths --chown anixops-agent" instead.
func migrateLegacyPaths(c *conf.Conf) {
	for _, report := range c.MigrateLegacyDefaults(conf.MigrateOptions{}) {
		fields := log.Fields{"what": report.Path.Name, "from": report.Path.Old, "to": report.Path.New}
		if report.Err != nil {
			log.WithFields(fields).WithError(report.Err).
				Warn("Could not copy the earlier default directory to the new layout; using the earlier directory (run 'anix-agent migrate-paths' as root)")
			continue
		}
		log.WithFields(fields).Info("Copied the earlier default directory to the new layout; the earlier directory is left in place and no longer used")
	}
}

// waitForExitSignal blocks until SIGINT or SIGTERM.
func waitForExitSignal() {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
}

// tuneHostTCP applies hosttune's TCP settings on Linux unless
// ANIXOPS_TCP_TUNE=0; a failure is only logged.
func tuneHostTCP() {
	if runtime.GOOS != "linux" || os.Getenv("ANIXOPS_TCP_TUNE") == "0" {
		return
	}
	changed, err := hosttune.ApplyTCP("/proc/sys")
	if len(changed) > 0 {
		log.WithField("changed", strings.Join(changed, " ")).Info("Applied host TCP settings")
	}
	if err != nil {
		log.WithField("err", err).Warn("Apply host TCP settings failed")
	}
}
