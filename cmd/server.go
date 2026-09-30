package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/AnixOps/anix-agent/v4/conf"
	vCore "github.com/AnixOps/anix-agent/v4/core"
	"github.com/AnixOps/anix-agent/v4/limiter"
	"github.com/AnixOps/anix-agent/v4/node"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	config     string
	watch      bool
	reRegister bool
)

var serverCommand = cobra.Command{
	Use:   "server",
	Short: "Run AnixOps Agent",
	RunE:  serverHandle,
	Args:  cobra.NoArgs,
}

func init() {
	serverCommand.PersistentFlags().
		StringVarP(&config, "config", "c",
			getDefaultConfigPath(), "config file path")
	serverCommand.PersistentFlags().
		BoolVarP(&watch, "watch", "w",
			true, "watch file path change")
	serverCommand.PersistentFlags().
		BoolVarP(&reRegister, "re-register", "r",
			false, "force re-register node (delete existing credentials)")
	command.AddCommand(&serverCommand)
}

// getDefaultConfigPath 根据操作系统返回默认配置文件路径
func getDefaultConfigPath() string {
	if runtime.GOOS == "windows" {
		// Windows: 使用可执行文件所在目录或当前目录
		exe, err := os.Executable()
		if err == nil {
			configPath := filepath.Join(filepath.Dir(exe), "config.json")
			if _, err := os.Stat(configPath); err == nil {
				return configPath
			}
		}
		// 尝试当前目录
		if _, err := os.Stat("config.json"); err == nil {
			return "config.json"
		}
		return "config.json"
	}
	// Linux/macOS 使用 AnixOps Agent 的标准配置目录。
	return defaultConfigPath
}

func serverHandle(_ *cobra.Command, _ []string) error {
	showVersion()

	// 检查配置文件是否存在
	if _, err := os.Stat(config); os.IsNotExist(err) {
		log.WithField("path", config).Error("Config file not found")
		log.Info("Usage: anix-agent server -c /path/to/config.json")
		log.Info("       anix-agent -c /path/to/config.json")
		if runtime.GOOS == "windows" {
			log.Info("On Windows, you can place config.json in the same directory as the executable")
		} else {
			log.Info("On Linux/macOS, the default config path is " + defaultConfigPath)
		}
		return fmt.Errorf("config file not found: %s", config)
	}

	log.WithField("config", config).Info("Loading config file")
	c := conf.New()
	err := c.LoadFromPath(config)
	if err != nil {
		log.WithField("err", err).Error("Load config file failed")
		return fmt.Errorf("load config file: %w", err)
	}
	switch c.LogConfig.Level {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	}
	if c.LogConfig.Output != "" {
		f, err := os.OpenFile(c.LogConfig.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.WithField("err", err).Error("Open log file failed, using stdout instead")
		}
		log.SetOutput(f)
	}
	limiter.Init()
	log.Info("Start AnixOps Agent...")
	vc, err := vCore.NewCore(c.CoresConfig)
	if err != nil {
		log.WithField("err", err).Error("new core failed")
		return fmt.Errorf("create core: %w", err)
	}
	err = vc.Start()
	if err != nil {
		log.WithField("err", err).Error("Start core failed")
		return fmt.Errorf("start core: %w", err)
	}
	defer vc.Close()
	log.Info("Core ", vc.Type(), " started")

	// 如果指定了重新注册，设置所有节点的 ForceReRegister 标志
	if reRegister {
		log.Info("Force re-register mode enabled")
		for i := range c.NodeConfig {
			c.NodeConfig[i].ApiConfig.ForceReRegister = true
		}
	}

	nodes := node.New()
	err = nodes.Start(c.NodeConfig, vc)
	if err != nil {
		log.WithField("err", err).Error("Run nodes failed")
		return fmt.Errorf("start nodes: %w", err)
	}
	log.Info("Nodes started")
	xdns := os.Getenv("XRAY_DNS_PATH")
	sdns := os.Getenv("SING_DNS_PATH")
	if watch {
		err = c.Watch(config, xdns, sdns, func() {
			nodes.Close()
			err = vc.Close()
			if err != nil {
				log.WithField("err", err).Error("Restart node failed")
				return
			}
			vc, err = vCore.NewCore(c.CoresConfig)
			if err != nil {
				log.WithField("err", err).Error("New core failed")
				return
			}
			err = vc.Start()
			if err != nil {
				log.WithField("err", err).Error("Start core failed")
				return
			}
			log.Info("Core ", vc.Type(), " restarted")
			err = nodes.Start(c.NodeConfig, vc)
			if err != nil {
				log.WithField("err", err).Error("Run nodes failed")
				return
			}
			log.Info("Nodes restarted")
			runtime.GC()
		})
		if err != nil {
			log.WithField("err", err).Error("start watch failed")
			return fmt.Errorf("start config watcher: %w", err)
		}
	}
	// clear memory
	runtime.GC()
	// wait exit signal
	{
		osSignals := make(chan os.Signal, 1)
		signal.Notify(osSignals, syscall.SIGINT, syscall.SIGTERM)
		<-osSignals
	}
	return nil
}
