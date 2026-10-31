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

// NftablesSettings locate the nft and tc the Agent ran the removed nftables
// driver with: RetireNftables deletes the table and qdisc it left.
type NftablesSettings struct {
	// NFT and TC are the binaries; empty runs nft and tc from PATH.
	NFT, TC string
}

// GostSettings locate the gost the Agent ran before gost was removed (the
// network model replaced it): RetireGost stops its unit and clears its
// directory.
type GostSettings struct {
	// Dir is gost's directory; empty is DefaultGostDir.
	Dir string
	// Unit is gost's systemd unit; empty is DefaultGostUnit.
	Unit string
	// Systemctl is the binary; empty runs it from PATH.
	Systemctl string
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
	// Links keeps the drivers' link certificate from Control (H28) in the
	// anixops relay's directory; nil when it does not want it.
	Links *LinkOptions
}

// BuildDrivers probes the host once (anixops.Probe), at start,
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

	RetireNftables(ctx, settings.Nftables)
	unavailable(forwardv1.Engine_ENGINE_NFTABLES, "removed: nftables routes run on the network model")

	RetireGost(ctx, settings.Gost)
	unavailable(forwardv1.Engine_ENGINE_GOST, "removed: gost routes run on the network model")

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

	// The first consumer keeps the link certificate; the others get a copy
	// of every file.
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
