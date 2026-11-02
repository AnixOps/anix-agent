package forward

import (
	"context"
	"os"
	"strings"

	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	log "github.com/sirupsen/logrus"
)

// Settings locate what the Agent cleans up at start.
type Settings struct {
	Nftables NftablesSettings
}

// NftablesSettings locate the nft and tc the Agent ran the removed nftables
// driver with: RetireNftables deletes the table and qdisc it left.
type NftablesSettings struct {
	// NFT and TC are the binaries; empty runs nft and tc from PATH.
	NFT, TC string
}

// retiredEngines are the forward engines the Agent had drivers for. Every
// one was removed: routes run on the network model (anx-node). The Hello
// lists them as unavailable so Control never plans a hop on them.
var retiredEngines = []struct {
	engine forwardv1.Engine
	reason string
}{
	{forwardv1.Engine_ENGINE_NFTABLES, "removed: nftables routes run on the network model"},
	{forwardv1.Engine_ENGINE_GOST, "removed: gost routes run on the network model"},
	{forwardv1.Engine_ENGINE_ANIXOPS, "removed: anixops relay routes run on the network model"},
}

// removedEngineMessage is the hop error of a hop on engine: no driver runs
// it on the Agent.
func removedEngineMessage(engine forwardv1.Engine) string {
	return "no driver for engine " + engine.String() + ": the Agent runs forwarding on the network model"
}

// Prepare cleans up after the removed nftables driver and checks the
// kernel's forwarding sysctls, once at start. It changes nothing else.
func Prepare(ctx context.Context, settings Settings) {
	RetireNftables(ctx, settings.Nftables)
	checkIPForwarding(log.WithField("component", "forward"))
}

// checkIPForwarding warns when the kernel does not forward: a forwarding
// relay needs net.ipv4.ip_forward (and IPv6 forwarding for v6 routes). The
// installer writes the sysctl drop-in /etc/sysctl.d/90-anixops-forward.conf
// on forward-capable nodes; the Agent only checks, it never changes a
// host-wide setting by itself.
func checkIPForwarding(logger *log.Entry) {
	for path, name := range map[string]string{
		"/proc/sys/net/ipv4/ip_forward":          "net.ipv4.ip_forward",
		"/proc/sys/net/ipv6/conf/all/forwarding": "net.ipv6.conf.all.forwarding",
	} {
		data, err := os.ReadFile(path) // #nosec G304 -- fixed paths
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(data)) != "1" {
			logger.WithField("sysctl", name).Warn("The kernel does not forward packets; relaying needs it: as root, run 'anix-agent forward sysctl-dropin > /etc/sysctl.d/90-anixops-forward.conf && sysctl --system'")
		}
	}
}
