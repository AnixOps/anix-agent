// wireguard-relay-integration starts one real V2bX WireGuard relay role for
// the privileged GitHub Actions network-namespace acceptance test.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	"github.com/AnixOps/anix-agent/v5/core/wireguard"
)

type options struct {
	role              string
	tag               string
	runtimeDir        string
	readyFile         string
	gostPath          string
	cidr              string
	serverAddress     string
	serverPort        int
	serverPrivateKey  string
	peerPublicKey     string
	peerPresharedKey  string
	peerIP            string
	tunnelType        string
	wssPath           string
	wssServerName     string
	wssCAFile         string
	wssCertFile       string
	wssKeyFile        string
	relayServer       string
	relayServerPort   int
	tunPort           int
	tunName           string
	entryTunAddress   string
	exitTunAddress    string
	outboundInterface string
	networkPaths      networkPathFlags
}

type networkPathFlags []panel.WireGuardNetworkPath

func (paths *networkPathFlags) String() string {
	return fmt.Sprint([]panel.WireGuardNetworkPath(*paths))
}

func (paths *networkPathFlags) Set(value string) error {
	parts := strings.Split(value, ",")
	if len(parts) != 5 {
		return errors.New("network path must be name,interface,source,gateway,priority")
	}
	priority, err := strconv.Atoi(parts[4])
	if err != nil {
		return fmt.Errorf("network path priority: %w", err)
	}
	*paths = append(*paths, panel.WireGuardNetworkPath{
		Name: parts[0], Interface: parts[1], Source: parts[2], Gateway: parts[3], Priority: priority,
	})
	return nil
}

func main() {
	var opts options
	flag.StringVar(&opts.role, "role", "", "relay role: entry or exit")
	flag.StringVar(&opts.tag, "tag", "wireguard-integration", "AnixOps Agent node tag")
	flag.StringVar(&opts.runtimeDir, "runtime-dir", "", "private directory for generated WireGuard config")
	flag.StringVar(&opts.readyFile, "ready-file", "", "path written after the relay role is ready")
	flag.StringVar(&opts.gostPath, "gost-path", "gost", "path to the GOST v3 executable")
	flag.StringVar(&opts.cidr, "cidr", "10.66.0.0/24", "WireGuard peer CIDR")
	flag.StringVar(&opts.serverAddress, "server-address", "10.66.0.1/24", "entry WireGuard interface address")
	flag.IntVar(&opts.serverPort, "server-port", 51820, "entry WireGuard UDP port")
	flag.StringVar(&opts.serverPrivateKey, "server-private-key", "", "WireGuard server private key")
	flag.StringVar(&opts.peerPublicKey, "peer-public-key", "", "WireGuard client public key for entry role")
	flag.StringVar(&opts.peerPresharedKey, "peer-preshared-key", "", "WireGuard client preshared key for entry role")
	flag.StringVar(&opts.peerIP, "peer-ip", "10.66.0.2", "WireGuard client peer address for entry role")
	flag.StringVar(&opts.tunnelType, "tunnel-type", "quic", "GOST relay transport: quic or wss")
	flag.StringVar(&opts.wssPath, "wss-path", "/ws", "WSS relay path")
	flag.StringVar(&opts.wssServerName, "wss-server-name", "", "WSS TLS server name for entry verification")
	flag.StringVar(&opts.wssCAFile, "wss-ca-file", "", "WSS CA certificate path for entry verification")
	flag.StringVar(&opts.wssCertFile, "wss-cert-file", "", "WSS certificate path for exit listener")
	flag.StringVar(&opts.wssKeyFile, "wss-key-file", "", "WSS private key path for exit listener")
	flag.StringVar(&opts.relayServer, "relay-server", "", "exit relay address reachable from the entry role")
	flag.IntVar(&opts.relayServerPort, "relay-server-port", 18443, "GOST relay listener port")
	flag.IntVar(&opts.tunPort, "tun-port", 18421, "GOST TUN port")
	flag.StringVar(&opts.tunName, "tun-name", "", "GOST TUN interface name")
	flag.StringVar(&opts.entryTunAddress, "entry-tun-address", "172.31.66.2/24", "entry GOST TUN address")
	flag.StringVar(&opts.exitTunAddress, "exit-tun-address", "172.31.66.1/24", "exit GOST TUN address")
	flag.StringVar(&opts.outboundInterface, "outbound-interface", "", "exit public-egress interface for NAT")
	flag.Var(&opts.networkPaths, "network-path", "entry failover path: name,interface,source,gateway,priority (repeatable)")
	flag.Parse()

	if err := run(opts); err != nil {
		fmt.Fprintln(os.Stderr, "wireguard relay integration:", err)
		os.Exit(1)
	}
}

func run(opts options) error {
	opts.role = strings.ToLower(strings.TrimSpace(opts.role))
	if opts.role != "entry" && opts.role != "exit" {
		return errors.New("--role must be entry or exit")
	}
	opts.tunnelType = strings.ToLower(strings.TrimSpace(opts.tunnelType))
	if opts.tunnelType != "quic" && opts.tunnelType != "wss" {
		return errors.New("--tunnel-type must be quic or wss")
	}
	if opts.tunnelType == "wss" {
		if strings.TrimSpace(opts.wssPath) == "" || !strings.HasPrefix(opts.wssPath, "/") {
			return errors.New("WSS --wss-path must start with /")
		}
		if opts.role == "entry" && (strings.TrimSpace(opts.wssServerName) == "" || strings.TrimSpace(opts.wssCAFile) == "") {
			return errors.New("WSS entry requires --wss-server-name and --wss-ca-file")
		}
		if opts.role == "exit" && (strings.TrimSpace(opts.wssCertFile) == "" || strings.TrimSpace(opts.wssKeyFile) == "") {
			return errors.New("WSS exit requires --wss-cert-file and --wss-key-file")
		}
	}
	if strings.TrimSpace(opts.runtimeDir) == "" || strings.TrimSpace(opts.readyFile) == "" {
		return errors.New("--runtime-dir and --ready-file are required")
	}
	if opts.role == "entry" && strings.TrimSpace(opts.serverPrivateKey) == "" {
		return errors.New("--server-private-key is required")
	}
	if opts.role == "entry" {
		if strings.TrimSpace(opts.peerPublicKey) == "" || strings.TrimSpace(opts.relayServer) == "" {
			return errors.New("entry role requires --peer-public-key and --relay-server")
		}
	}
	if opts.role == "exit" && strings.TrimSpace(opts.outboundInterface) == "" {
		return errors.New("exit role requires --outbound-interface")
	}

	cfg := conf.NewWireGuardConfig()
	cfg.RuntimeDir = opts.runtimeDir
	cfg.GostPath = opts.gostPath
	runtime, err := wireguard.New(&conf.CoreConfig{Type: "wireguard", WireGuardConfig: cfg})
	if err != nil {
		return fmt.Errorf("create WireGuard core: %w", err)
	}

	node := buildNode(opts)
	if err := runtime.AddNode(opts.tag, node, &conf.Options{}); err != nil {
		return fmt.Errorf("apply %s role: %w", opts.role, err)
	}
	defer runtime.Close()

	if opts.role == "entry" {
		_, err := runtime.AddUsers(&vCore.AddUsersParams{
			Tag:      opts.tag,
			NodeInfo: node,
			Users: []panel.UserInfo{{
				Id:                    1,
				Uuid:                  "wireguard-integration-peer",
				WireGuardPeerIP:       opts.peerIP,
				WireGuardPublicKey:    opts.peerPublicKey,
				WireGuardPresharedKey: opts.peerPresharedKey,
			}},
		})
		if err != nil {
			return fmt.Errorf("apply entry peer: %w", err)
		}
	}

	if err := os.MkdirAll(filepath.Dir(opts.readyFile), 0700); err != nil {
		return fmt.Errorf("create readiness directory: %w", err)
	}
	if err := os.WriteFile(opts.readyFile, []byte(opts.role+"\n"), 0600); err != nil {
		return fmt.Errorf("write readiness file: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	return nil
}

func buildNode(opts options) *panel.NodeInfo {
	common := panel.CommonNode{
		Host:       opts.relayServer,
		ServerPort: opts.serverPort,
		ServerName: opts.relayServer,
	}
	networkPolicy := panel.WireGuardNetworkPolicy{}
	if len(opts.networkPaths) > 0 {
		networkPolicy = panel.WireGuardNetworkPolicy{
			Version: 1, Strategy: "failover", Paths: opts.networkPaths,
			HealthCheck: panel.WireGuardHealthCheck{
				IntervalSeconds: 1, TimeoutSeconds: 1, FailureThreshold: 1,
				RecoveryThreshold: 1, FailbackDelaySeconds: 30,
			},
		}
	}
	return &panel.NodeInfo{
		Id:       1,
		Type:     "wireguard",
		Security: panel.None,
		Common:   &common,
		WireGuard: &panel.WireGuardNode{
			CommonNode:       common,
			CIDR:             opts.cidr,
			ServerAddress:    opts.serverAddress,
			ServerPrivateKey: opts.serverPrivateKey,
			MTU:              1280,
			AllowedIPs:       []string{"0.0.0.0/0"},
			TunnelType:       opts.tunnelType,
			Relay: panel.WireGuardRelay{
				Backend:         "gost",
				Mode:            "relay+" + opts.tunnelType,
				Role:            opts.role,
				WSSPath:         opts.wssPath,
				WSSSecure:       opts.tunnelType == "wss" && opts.role == "entry",
				WSSServerName:   valueForEntry(opts.role, opts.wssServerName),
				WSSCAFile:       valueForEntry(opts.role, opts.wssCAFile),
				WSSCertFile:     valueForExit(opts.role, opts.wssCertFile),
				WSSKeyFile:      valueForExit(opts.role, opts.wssKeyFile),
				ExitNAT:         opts.role == "exit",
				Server:          opts.relayServer,
				ServerPort:      opts.relayServerPort,
				TunName:         opts.tunName,
				TunPort:         opts.tunPort,
				EntryTunAddress: opts.entryTunAddress,
				ExitTunAddress:  opts.exitTunAddress,
				OutboundIface:   opts.outboundInterface,
				NetworkPolicy:   networkPolicy,
			},
		},
	}
}

func valueForEntry(role, value string) string {
	if role == "entry" {
		return value
	}
	return ""
}

func valueForExit(role, value string) string {
	if role == "exit" {
		return value
	}
	return ""
}
