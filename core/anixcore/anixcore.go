// Package anixcore drives the AnixOps node kernel, `anixcore` from
// networkcore_anixops, as an agent core. The core runs `anixcore run` with
// a generated config (or connects to one already running) and maps the core
// interface onto anixcore's local management API: one anixcore inbound per
// node tag, panel users by id, traffic slices and online IPs read back.
package anixcore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	log "github.com/sirupsen/logrus"
)

const coreType = "anixcore"

var (
	_ vCore.Core                 = (*Core)(nil)
	_ vCore.OnlineDeviceProvider = (*Core)(nil)
)

func init() {
	vCore.RegisterCore(coreType, New)
}

// node is what the core keeps per tag so a restarted anixcore can be given
// its nodes and users again.
type node struct {
	info    *panel.NodeInfo
	inbound map[string]any
	users   map[string]apiUser
	// created is false while a Shadowsocks node waits for its first users:
	// anixcore picks the multi-user mode when the inbound is created.
	created bool
	// ingress is the network-model ingress the inbound joins, "" for none.
	ingress string
}

type Core struct {
	config *conf.AnixcoreConfig

	mu     sync.Mutex
	client *client
	nodes  map[string]*node
	// egress is the last configuration ApplyEgress sent, nil for none.
	egress *panel.EgressConfig
	// network is the last plan ApplyNetwork sent, nil for none, and
	// ingresses its user ingresses by listen port.
	network   json.RawMessage
	ingresses map[int]string

	process *exec.Cmd
	stop    chan struct{}
	exited  chan struct{}
}

func New(c *conf.CoreConfig) (vCore.Core, error) {
	config := c.AnixcoreConfig
	if config == nil {
		config = conf.NewAnixcoreConfig()
	}
	return &Core{config: config, nodes: make(map[string]*node)}, nil
}

func (c *Core) Type() string {
	return coreType
}

func (c *Core) Protocols() []string {
	return []string{"shadowsocks", "trojan", "vless", "vmess", "hysteria2", "tuic", "iwan"}
}

func (c *Core) Start() error {
	if c.config.ApiAddress != "" && c.config.ApiToken != "" {
		c.client = newClient(c.config.ApiAddress, c.config.ApiToken)
		return c.waitReady()
	}
	if c.config.ApiAddress != "" || c.config.ApiToken != "" {
		return errors.New("anixcore: ApiAddress and ApiToken go together")
	}
	c.stop = make(chan struct{})
	return c.launch()
}

// launch starts an anixcore process with a fresh token and API port.
func (c *Core) launch() error {
	address, err := freeLoopbackAddress()
	if err != nil {
		return err
	}
	token, err := randomToken()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.config.RuntimeDir, 0o700); err != nil {
		return fmt.Errorf("anixcore runtime dir: %w", err)
	}
	path := filepath.Join(c.config.RuntimeDir, "anixcore.json")
	document, err := json.Marshal(map[string]any{
		"management":            map[string]any{"listen": address, "token": token},
		"allow_private_targets": c.config.AllowPrivateTargets,
	})
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, document, 0o600); err != nil {
		return fmt.Errorf("write anixcore config: %w", err)
	}
	process := exec.Command(c.config.BinaryPath, "run", "-c", path)
	process.Stdout = os.Stdout
	process.Stderr = os.Stderr
	if err := process.Start(); err != nil {
		return fmt.Errorf("start anixcore: %w", err)
	}
	exited := make(chan struct{})
	c.mu.Lock()
	c.client = newClient(address, token)
	c.process = process
	c.exited = exited
	c.mu.Unlock()
	go func() {
		err := process.Wait()
		close(exited)
		c.supervise(err)
	}()
	if err := c.waitReady(); err != nil {
		_ = process.Process.Kill()
		return err
	}
	return nil
}

// supervise restarts an anixcore that exited on its own and gives it its
// nodes and users again.
func (c *Core) supervise(exitErr error) {
	select {
	case <-c.stop:
		return
	default:
	}
	log.WithField("core", coreType).WithError(exitErr).Error("anixcore exited; restarting")
	for {
		delay := time.Duration(c.config.RestartDelaySeconds) * time.Second
		select {
		case <-c.stop:
			return
		case <-time.After(delay):
		}
		if err := c.launch(); err != nil {
			log.WithField("core", coreType).WithError(err).Error("restart anixcore")
			continue
		}
		if err := c.replay(); err != nil {
			log.WithField("core", coreType).WithError(err).Error("restore anixcore nodes")
		}
		return
	}
}

// replay adds the network plan, every known node with its users, and the
// egress routes to a fresh anixcore.
func (c *Core) replay() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var failed error
	if c.network != nil {
		if _, err := c.putNetwork(c.network); err != nil {
			failed = errors.Join(failed, err)
		}
	}
	for tag, n := range c.nodes {
		n.created = false
		if err := c.create(tag, n); err != nil {
			failed = errors.Join(failed, fmt.Errorf("%s: %w", tag, err))
		}
	}
	if c.egress != nil {
		if err := c.putEgress(c.egress); err != nil {
			failed = errors.Join(failed, err)
		}
	}
	return failed
}

func (c *Core) waitReady() error {
	timeout := time.Duration(c.config.StartTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := c.client.status(ctx)
		cancel()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("anixcore api is not ready: %w", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (c *Core) Close() error {
	if c.stop != nil {
		select {
		case <-c.stop:
		default:
			close(c.stop)
		}
	}
	c.mu.Lock()
	process, exited := c.process, c.exited
	c.process = nil
	c.mu.Unlock()
	if process == nil {
		return nil
	}
	_ = process.Process.Signal(os.Interrupt)
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		_ = process.Process.Kill()
		<-exited
	}
	return nil
}

func (c *Core) AddNode(tag string, info *panel.NodeInfo, options *conf.Options) error {
	inbound, err := inboundConfig(tag, info, options)
	if err != nil {
		return fmt.Errorf("anixcore node %s: %w", tag, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.nodes[tag]; exists {
		return fmt.Errorf("anixcore node %s already exists", tag)
	}
	n := &node{info: info, inbound: inbound, users: make(map[string]apiUser)}
	n.ingress = c.ingressOf(n)
	if info.Type != "shadowsocks" {
		if err := c.create(tag, n); err != nil {
			return fmt.Errorf("anixcore node %s: %w", tag, err)
		}
	}
	c.nodes[tag] = n
	return nil
}

// create adds n's inbound with its current users. A Shadowsocks node
// without users waits for them.
func (c *Core) create(tag string, n *node) error {
	if n.info.Type == "shadowsocks" && len(n.users) == 0 {
		return nil
	}
	inbound := make(map[string]any, len(n.inbound)+2)
	for key, value := range n.inbound {
		inbound[key] = value
	}
	if n.ingress != "" {
		inbound["ingress"] = n.ingress
	}
	users := make([]apiUser, 0, len(n.users))
	for _, user := range n.users {
		users = append(users, user)
	}
	inbound["users"] = users
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	if err := c.client.addInbound(ctx, inbound); err != nil {
		return err
	}
	n.created = true
	return nil
}

func (c *Core) DelNode(tag string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.nodes[tag]
	if !ok {
		return nil
	}
	delete(c.nodes, tag)
	if !n.created {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	if err := c.client.removeInbound(ctx, tag); err != nil && !isStatus(err, 404) {
		return fmt.Errorf("anixcore node %s: %w", tag, err)
	}
	return nil
}

func freeLoopbackAddress() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("pick anixcore api port: %w", err)
	}
	defer listener.Close()
	return listener.Addr().String(), nil
}

func randomToken() (string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	return hex.EncodeToString(token), nil
}
