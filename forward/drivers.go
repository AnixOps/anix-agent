package forward

import (
	"context"
	"os"
	"strings"

	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"github.com/AnixOps/anix-control/sdk/forward/driver"
	"github.com/AnixOps/anix-control/sdk/forward/leastconn"
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

// Drivers is what BuildDrivers found on the host: everything Options needs
// besides the node, the state directory and the version.
type Drivers struct {
	Registry    *driver.Registry
	Unavailable []*forwardv1.EngineCapabilities
	Retired     *Retired
	Sources     map[forwardv1.Engine]leastconn.Source
}

// BuildDrivers probes the host once (anixops.Probe), at start,
// and registers each engine the host can run. An engine it cannot run is
// listed in Unavailable with the reason, so Control knows before planning.
// The probes change nothing on the host.
func BuildDrivers(ctx context.Context, settings Settings) (*Drivers, error) {
	out := &Drivers{Registry: driver.NewRegistry(), Retired: NewRetired(), Sources: map[forwardv1.Engine]leastconn.Source{}}
	logger := log.WithField("component", "forward")
	unavailable := func(engine forwardv1.Engine, reason string) {
		out.Unavailable = append(out.Unavailable, &forwardv1.EngineCapabilities{Engine: engine, UnavailableReason: reason})
		logger.WithFields(log.Fields{"engine": engine.String(), "reason": reason}).Warn("Forward engine unavailable on this host")
	}

	RetireNftables(ctx, settings.Nftables)
	unavailable(forwardv1.Engine_ENGINE_NFTABLES, "removed: nftables routes run on the network model")

	unavailable(forwardv1.Engine_ENGINE_GOST, "removed: gost routes run on the network model")

	unavailable(forwardv1.Engine_ENGINE_ANIXOPS, "removed: anixops relay routes run on the network model")

	checkIPForwarding(logger)
	return out, nil
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
