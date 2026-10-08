package forward

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"github.com/AnixOps/anix-control/sdk/forward/driver"
	"github.com/AnixOps/anix-control/sdk/forward/driver/anixops"
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
	AnixOps  AnixOpsSettings
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
	// ManualLinkCertificates leaves the link files to the operator: the
	// Agent does not ask Control for them (H28).
	ManualLinkCertificates bool
}

// AnixOpsSettings configure the experimental anixops driver (H22): the
// Agent's anixops-relay, run as anixops-relay.service. It is a v4.2
// prototype, off by default.
type AnixOpsSettings struct {
	// Enable registers the driver (Forward.AnixOps.Enable); without
	// it the engine is listed as unavailable and the planner refuses the
	// node for anixops hops.
	Enable bool
	// Binary is anixops-relay; empty is anixops.DefaultBinary.
	Binary string
	// Systemctl is the binary; empty runs it from PATH.
	Systemctl string
	// Dir and RuntimeDir default to anixops.DefaultDir and
	// anixops.DefaultRuntimeDir.
	Dir, RuntimeDir string
	// ManualLinkCertificates leaves the relay's copy of the link files to the
	// operator: the Agent does not write them.
	ManualLinkCertificates bool
}

// linkConsumer is a driver that reads the node's link certificate files from a
// directory of its own.
type linkConsumer struct {
	dir, group string
	// enabled is whether the driver was built with the certificate.
	enabled    bool
	setEnabled func(enabled bool) error
	reload     func(ctx context.Context) error
}

// Drivers is what BuildDrivers found on the host: everything Options needs
// besides the node, the state directory and the version.
type Drivers struct {
	Registry         *driver.Registry
	Unavailable      []*forwardv1.EngineCapabilities
	Retired          *Retired
	Sources          map[forwardv1.Engine]leastconn.Source
	LinkCertificates bool
	// Links keeps the drivers' link certificate from Control (H28): the
	// gost driver's directory first, the anixops relay's as a mirror of it
	// (or on its own on a node without gost); nil when neither wants it.
	Links *LinkOptions
}

// BuildDrivers probes the host once (nftables.Probe, gost.Probe), at start,
// and registers each engine the host can run. An engine it cannot run is
// listed in Unavailable with the reason, so Control knows before planning.
// The probes change nothing on the host.
func BuildDrivers(ctx context.Context, settings Settings) (*Drivers, error) {
	out := &Drivers{Registry: driver.NewRegistry(), Retired: NewRetired(), Sources: map[forwardv1.Engine]leastconn.Source{}}
	var consumers []linkConsumer
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
			// The probe drops the link paths while the files are missing;
			// the component switches them on once the link certificate
			// arrives (H28).
			withLinks := cfg
			withLinks.LinkCert, withLinks.LinkKey, withLinks.LinkCA = base.LinkCert, base.LinkKey, base.LinkCA
			withoutLinks := cfg
			withoutLinks.LinkCert, withoutLinks.LinkKey, withoutLinks.LinkCA = "", "", ""
			build := func(links bool) (*gost.Driver, error) {
				c := withoutLinks
				if links {
					c = withLinks
				}
				return gost.New(c, gost.WithRunner(runner), gost.WithSupervisor(sup), gost.WithRetiredCounters(out.Retired.Add))
			}
			d, err := newGostDriver(cfg.LinkCert != "", build)
			if err != nil {
				return nil, fmt.Errorf("forward: gost driver: %w", err)
			}
			if err := out.Registry.Register(d); err != nil {
				return nil, err
			}
			if !settings.Gost.ManualLinkCertificates && base.LinkCert != "" {
				consumers = append(consumers, linkConsumer{
					dir:        filepath.Dir(base.LinkCert),
					group:      gost.DefaultUser,
					enabled:    cfg.LinkCert != "",
					setEnabled: d.setLinks,
					reload: func(ctx context.Context) error {
						st, err := sup.Status(ctx)
						if err != nil || !st.Running {
							// gost reads the files when it starts.
							return err
						}
						return sup.Reload(ctx)
					},
				})
			}
		}
	}

	if !settings.AnixOps.Enable {
		unavailable(forwardv1.Engine_ENGINE_ANIXOPS, "experimental: not enabled in the Agent configuration (Forward.AnixOps.Enable)")
	} else {
		runner := anixops.ExecRunner{Relay: settings.AnixOps.Binary, Systemctl: settings.AnixOps.Systemctl}
		if runner.Relay == "" {
			runner.Relay = anixops.DefaultBinary
		}
		sup := anixops.SystemdSupervisor{Runner: runner}
		base := anixops.DefaultConfig()
		if settings.AnixOps.Dir != "" {
			base.Dir = settings.AnixOps.Dir
			base.LinkCert, base.LinkKey, base.LinkCA = base.Dir+"/tls/link.crt", base.Dir+"/tls/link.key", base.Dir+"/tls/link-ca.crt"
		}
		if settings.AnixOps.RuntimeDir != "" {
			base.RuntimeDir = settings.AnixOps.RuntimeDir
		}
		cfg, rep, err := anixops.Probe(ctx, runner, sup, base)
		if err != nil {
			return nil, fmt.Errorf("forward: probe anixops: %w", err)
		}
		if rep != nil {
			logReport(forwardv1.Engine_ENGINE_ANIXOPS, rep.Missing, rep.Warnings)
		}
		if cfg.Version == "" {
			unavailable(forwardv1.Engine_ENGINE_ANIXOPS, cfg.Unavailable)
		} else {
			// The probe drops the link paths and the encrypted carriers while
			// the files are missing; the component switches them on once the
			// link certificate arrives (H28).
			withLinks := cfg
			withLinks.LinkCert, withLinks.LinkKey, withLinks.LinkCA = base.LinkCert, base.LinkKey, base.LinkCA
			withLinks.Carriers = anixops.DefaultConfig().Carriers
			withoutLinks := cfg
			withoutLinks.LinkCert, withoutLinks.LinkKey, withoutLinks.LinkCA = "", "", ""
			withoutLinks.Carriers = []forwardv1.AnixOpsCarrier{forwardv1.AnixOpsCarrier_ANIXOPS_CARRIER_PLAIN}
			build := func(links bool) (*anixops.Driver, error) {
				c := withoutLinks
				if links {
					c = withLinks
				}
				return anixops.New(c, anixops.WithRunner(runner), anixops.WithSupervisor(sup), anixops.WithRetiredCounters(out.Retired.Add))
			}
			haveLinks := cfg.LinkCert != ""
			d, err := newAnixOpsDriver(haveLinks, build)
			if err != nil {
				return nil, fmt.Errorf("forward: anixops driver: %w", err)
			}
			if err := out.Registry.Register(d); err != nil {
				return nil, err
			}
			if !settings.AnixOps.ManualLinkCertificates && base.LinkCert != "" {
				consumers = append(consumers, linkConsumer{
					dir:        filepath.Dir(base.LinkCert),
					group:      anixops.DefaultUser,
					enabled:    haveLinks,
					setEnabled: d.setLinks,
					// The relay swaps the certificate it presents and drops
					// only the carriers whose peer is no longer trusted.
					reload: d.ReloadCredentials,
				})
			}
		}
	}

	// The first consumer keeps the link certificate (gost's directory when
	// gost wants it); the others get a copy of every file.
	if len(consumers) > 0 {
		first := consumers[0]
		out.LinkCertificates = first.enabled
		out.Links = &LinkOptions{Dir: first.dir, Group: first.group, SetEnabled: first.setEnabled, Reload: first.reload}
		for _, m := range consumers[1:] {
			out.Links.Mirrors = append(out.Links.Mirrors, LinkMirror{Dir: m.dir, Group: m.group, Enabled: m.enabled, SetEnabled: m.setEnabled, Reload: m.reload})
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
			logger.WithField("sysctl", name).Warn("The kernel does not forward packets; nftables forwarding needs it: as root, run 'anix-agent forward sysctl-dropin > /etc/sysctl.d/90-anixops-forward.conf && sysctl --system'")
		}
	}
}
