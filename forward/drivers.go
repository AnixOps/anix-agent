package forward

import (
	"context"
	"fmt"
	"os"
	"strings"

	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"github.com/AnixOps/anix-control/sdk/forward/driver"
	"github.com/AnixOps/anix-control/sdk/forward/driver/gost"
	"github.com/AnixOps/anix-control/sdk/forward/driver/nftables"
	"github.com/AnixOps/anix-control/sdk/forward/leastconn"
	log "github.com/sirupsen/logrus"
)

// Settings choose and configure the drivers (forward-sdk.md section 6;
// owner decisions H13 and H20).
type Settings struct {
	Nftables NftablesSettings
	Gost     GostSettings
}

// NftablesSettings configure the nftables driver. The Agent needs
// CAP_NET_ADMIN (H13): it runs as root today, or as a dedicated user with
// that ambient capability.
type NftablesSettings struct {
	// Disable leaves the engine out: its hops are reported as unsupported.
	Disable bool
	// NFT and TC are the binaries; empty runs nft and tc from PATH.
	NFT, TC string
	// MarkMask is the connection mark bits the driver owns; 0 is
	// nftables.DefaultMarkMask (0x0fff0000). Change it on hosts where
	// Docker, WireGuard or policy routing use those bits.
	MarkMask uint32
	// LimitInterfaces are the egress interfaces that carry rate-limited
	// hops (tc HTB): both directions of a forwarded connection leave the
	// node through them. Without one the probe turns bandwidth limits off
	// and Control does not plan bandwidth-limited nftables hops here.
	LimitInterfaces []string
	// MSSClampInterfaces are encapsulating egress interfaces (WireGuard,
	// GRE) on which forwarded SYNs get their MSS clamped.
	MSSClampInterfaces []string
}

// GostSettings configure the gost driver (H20): the pinned gost the
// Agent's package ships, run as anixops-gost.service.
type GostSettings struct {
	Disable bool
	// Binary is gost; empty is gost.DefaultBinary.
	Binary string
	// SS and Systemctl are the binaries; empty runs them from PATH.
	SS, Systemctl string
	// Unit is the systemd unit; empty is anixops-gost.service.
	Unit string
	// Dir and RuntimeDir default to gost.DefaultDir and
	// gost.DefaultRuntimeDir.
	Dir, RuntimeDir string
	// LinkCert, LinkKey and LinkCA are the node's forward link certificate,
	// its key and the link CA, readable by gost (H28). Empty uses the
	// defaults under Dir/tls; while the files are missing gost carries RAW
	// links only.
	LinkCert, LinkKey, LinkCA string
}

// Drivers is what BuildDrivers found on the host: everything Options needs
// besides the node, the state directory and the version.
type Drivers struct {
	Registry         *driver.Registry
	Unavailable      []*forwardv1.EngineCapabilities
	Retired          *Retired
	Sources          map[forwardv1.Engine]leastconn.Source
	LinkCertificates bool
}

// BuildDrivers probes the host once (nftables.Probe, gost.Probe), at start,
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
	logReport := func(engine forwardv1.Engine, missing, warnings []string) {
		for _, m := range missing {
			logger.WithFields(log.Fields{"engine": engine.String(), "feature": m}).Info("Forward engine feature unavailable")
		}
		for _, w := range warnings {
			logger.WithFields(log.Fields{"engine": engine.String()}).Warn(w)
		}
	}

	if settings.Nftables.Disable {
		unavailable(forwardv1.Engine_ENGINE_NFTABLES, "disabled in the Agent configuration")
	} else {
		runner := nftables.ExecRunner{NFT: settings.Nftables.NFT, TC: settings.Nftables.TC}
		base := nftables.DefaultConfig()
		if settings.Nftables.MarkMask != 0 {
			base.MarkMask = settings.Nftables.MarkMask
		}
		base.LimitInterfaces = settings.Nftables.LimitInterfaces
		base.MSSClampInterfaces = settings.Nftables.MSSClampInterfaces
		cfg, rep, err := nftables.Probe(ctx, runner, base)
		if err != nil {
			return nil, fmt.Errorf("forward: probe nftables: %w", err)
		}
		if rep != nil {
			logReport(forwardv1.Engine_ENGINE_NFTABLES, rep.Missing, rep.Warnings)
		}
		if cfg.Version == "" {
			unavailable(forwardv1.Engine_ENGINE_NFTABLES, cfg.Unavailable)
		} else {
			d, err := nftables.New(cfg, nftables.WithRunner(runner), nftables.WithRetiredCounters(out.Retired.Add))
			if err != nil {
				return nil, fmt.Errorf("forward: nftables driver: %w", err)
			}
			if err := out.Registry.Register(d); err != nil {
				return nil, err
			}
			if src := newConntrackSource(cfg.MarkMask); src != nil {
				out.Sources[forwardv1.Engine_ENGINE_NFTABLES] = src
			}
		}
	}

	if settings.Gost.Disable {
		unavailable(forwardv1.Engine_ENGINE_GOST, "disabled in the Agent configuration")
	} else {
		runner := gost.ExecRunner{Gost: settings.Gost.Binary, SS: settings.Gost.SS, Systemctl: settings.Gost.Systemctl}
		if runner.Gost == "" {
			runner.Gost = gost.DefaultBinary
		}
		sup := gost.SystemdSupervisor{Runner: runner, Unit: settings.Gost.Unit}
		base := gost.DefaultConfig()
		if settings.Gost.Dir != "" {
			base.Dir = settings.Gost.Dir
			base.LinkCert, base.LinkKey, base.LinkCA = base.Dir+"/tls/link.crt", base.Dir+"/tls/link.key", base.Dir+"/tls/link-ca.crt"
		}
		if settings.Gost.RuntimeDir != "" {
			base.RuntimeDir = settings.Gost.RuntimeDir
		}
		if settings.Gost.LinkCert != "" || settings.Gost.LinkKey != "" || settings.Gost.LinkCA != "" {
			base.LinkCert, base.LinkKey, base.LinkCA = settings.Gost.LinkCert, settings.Gost.LinkKey, settings.Gost.LinkCA
		}
		cfg, rep, err := gost.Probe(ctx, runner, sup, base)
		if err != nil {
			return nil, fmt.Errorf("forward: probe gost: %w", err)
		}
		if rep != nil {
			logReport(forwardv1.Engine_ENGINE_GOST, rep.Missing, rep.Warnings)
		}
		if cfg.Version == "" {
			unavailable(forwardv1.Engine_ENGINE_GOST, cfg.Unavailable)
		} else {
			d, err := gost.New(cfg, gost.WithRunner(runner), gost.WithSupervisor(sup), gost.WithRetiredCounters(out.Retired.Add))
			if err != nil {
				return nil, fmt.Errorf("forward: gost driver: %w", err)
			}
			if err := out.Registry.Register(d); err != nil {
				return nil, err
			}
			out.LinkCertificates = cfg.LinkCert != ""
		}
	}
	checkIPForwarding(logger)
	return out, nil
}

// checkIPForwarding warns when the kernel does not forward: nftables DNAT
// needs net.ipv4.ip_forward (and IPv6 forwarding for v6 routes). The
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
			logger.WithField("sysctl", name).Warn("The kernel does not forward packets; nftables forwarding needs it (install the sysctl drop-in /etc/sysctl.d/90-anixops-forward.conf)")
		}
	}
}
