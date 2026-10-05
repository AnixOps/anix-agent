package forward

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"github.com/AnixOps/anix-control/sdk/forward/driver/anixops"
)

// fakeRelayHost writes stand-ins for anixops-relay and systemctl into a short
// temporary directory (the control socket path must fit a unix socket).
func fakeRelayHost(t *testing.T) (binary, systemctl, dir, runtime string) {
	t.Helper()
	root, err := os.MkdirTemp("", "ar")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	binary = filepath.Join(root, "anixops-relay")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\necho 'anixops-relay 4.2.0-test wire=0'\n"), 0o755); err != nil { // #nosec G306 -- a test script
		t.Fatal(err)
	}
	systemctl = filepath.Join(root, "systemctl")
	script := "#!/bin/sh\ncase \"$*\" in\n*LoadState*) echo 'LoadState=loaded'; echo 'Description=AnixOps forward relay (" + anixops.OwnerMark + ")';;\n*) echo 'ActiveState=inactive';;\nesac\n"
	if err := os.WriteFile(systemctl, []byte(script), 0o755); err != nil { // #nosec G306 -- a test script
		t.Fatal(err)
	}
	return binary, systemctl, filepath.Join(root, "lib"), filepath.Join(root, "run")
}

func TestBuildDriversAnixOps(t *testing.T) {
	binary, systemctl, dir, runtime := fakeRelayHost(t)
	settings := func(mod func(*AnixOpsSettings)) Settings {
		s := Settings{
			Nftables: NftablesSettings{Disable: true},
			Gost:     GostSettings{Disable: true},
			AnixOps:  AnixOpsSettings{Enable: true, Binary: binary, Systemctl: systemctl, Dir: dir, RuntimeDir: runtime},
		}
		if mod != nil {
			mod(&s.AnixOps)
		}
		return s
	}

	t.Run("off by default: listed as unavailable, no driver", func(t *testing.T) {
		d, err := BuildDrivers(t.Context(), Settings{Nftables: NftablesSettings{Disable: true}, Gost: GostSettings{Disable: true}})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := d.Registry.Get(forwardv1.Engine_ENGINE_ANIXOPS); ok {
			t.Fatal("the experimental engine is registered without its flag")
		}
		found := false
		for _, u := range d.Unavailable {
			if u.GetEngine() == forwardv1.Engine_ENGINE_ANIXOPS {
				found = true
				if u.GetUnavailableReason() == "" {
					t.Fatal("no reason")
				}
			}
		}
		if !found {
			t.Fatal("the engine is not listed as unavailable")
		}
		if d.Links != nil {
			t.Fatal("link certificates without a driver that reads them")
		}
	})

	t.Run("enabled without link files: PLAIN only", func(t *testing.T) {
		d, err := BuildDrivers(t.Context(), settings(nil))
		if err != nil {
			t.Fatal(err)
		}
		drv, ok := d.Registry.Get(forwardv1.Engine_ENGINE_ANIXOPS)
		if !ok {
			t.Fatalf("not registered; unavailable: %v", d.Unavailable)
		}
		caps, err := drv.Capabilities(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if !caps.GetAvailable() || caps.GetVersion() != "anixops-relay 4.2.0-test" || caps.GetProxyProtocol() {
			t.Fatalf("capabilities %v", caps)
		}
		if !slices.Equal(caps.GetCarriers(), []forwardv1.AnixOpsCarrier{forwardv1.AnixOpsCarrier_ANIXOPS_CARRIER_PLAIN}) {
			t.Fatalf("carriers %v, want PLAIN only without the link certificate", caps.GetCarriers())
		}
		if d.LinkCertificates || d.Links == nil || d.Links.Dir != filepath.Join(dir, "tls") || d.Links.Group != anixops.DefaultUser || len(d.Links.Mirrors) != 0 {
			t.Fatalf("links %+v (certificates %v)", d.Links, d.LinkCertificates)
		}
		// The component switches the encrypted carriers on once the files
		// are there: the driver behind the switch is rebuilt with them.
		ad := drv.(*anixopsDriver)
		if err := ad.setLinks(true); err != nil {
			t.Fatal(err)
		}
		caps, _ = drv.Capabilities(t.Context())
		if len(caps.GetCarriers()) != 3 {
			t.Fatalf("carriers after the switch %v", caps.GetCarriers())
		}
		if err := ad.setLinks(false); err != nil {
			t.Fatal(err)
		}
		caps, _ = drv.Capabilities(t.Context())
		if len(caps.GetCarriers()) != 1 {
			t.Fatalf("carriers after switching back %v", caps.GetCarriers())
		}
	})

	t.Run("enabled with link files: every carrier", func(t *testing.T) {
		if err := os.MkdirAll(filepath.Join(dir, "tls"), 0o750); err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"link.crt", "link.key", "link-ca.crt"} {
			if err := os.WriteFile(filepath.Join(dir, "tls", n), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		d, err := BuildDrivers(t.Context(), settings(nil))
		if err != nil {
			t.Fatal(err)
		}
		drv, _ := d.Registry.Get(forwardv1.Engine_ENGINE_ANIXOPS)
		caps, _ := drv.Capabilities(t.Context())
		if len(caps.GetCarriers()) != 3 || !d.LinkCertificates {
			t.Fatalf("carriers %v, certificates %v", caps.GetCarriers(), d.LinkCertificates)
		}
	})

	t.Run("manual link certificates leave the copy to the operator", func(t *testing.T) {
		d, err := BuildDrivers(t.Context(), settings(func(a *AnixOpsSettings) { a.ManualLinkCertificates = true }))
		if err != nil {
			t.Fatal(err)
		}
		if d.Links != nil {
			t.Fatal("the Agent manages link files it was told to leave alone")
		}
	})

	t.Run("a host without the relay: unavailable with the reason", func(t *testing.T) {
		d, err := BuildDrivers(t.Context(), settings(func(a *AnixOpsSettings) { a.Binary = filepath.Join(dir, "no-such-relay") }))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := d.Registry.Get(forwardv1.Engine_ENGINE_ANIXOPS); ok {
			t.Fatal("registered without the relay")
		}
		for _, u := range d.Unavailable {
			if u.GetEngine() == forwardv1.Engine_ENGINE_ANIXOPS && u.GetUnavailableReason() != "" {
				return
			}
		}
		t.Fatalf("not listed with a reason: %v", d.Unavailable)
	})
}

func TestUDPOnlyLinksAreNotHealthChecked(t *testing.T) {
	for name, tr := range map[string]*forwardv1.LinkTransport{
		"gost quic":      {Security: forwardv1.LinkSecurity_LINK_SECURITY_QUIC},
		"anixops quic":   {Security: forwardv1.LinkSecurity_LINK_SECURITY_ANIXOPS, Carrier: forwardv1.AnixOpsCarrier_ANIXOPS_CARRIER_QUIC},
		"anixops quic 2": {Security: forwardv1.LinkSecurity_LINK_SECURITY_ANIXOPS, Mux: true, Carrier: forwardv1.AnixOpsCarrier_ANIXOPS_CARRIER_QUIC},
	} {
		if !udpOnly(tr) {
			t.Errorf("%s is checked with a TCP connect", name)
		}
	}
	for name, tr := range map[string]*forwardv1.LinkTransport{
		"raw":            {Security: forwardv1.LinkSecurity_LINK_SECURITY_RAW},
		"gost tls":       {Security: forwardv1.LinkSecurity_LINK_SECURITY_TLS},
		"anixops auto":   {Security: forwardv1.LinkSecurity_LINK_SECURITY_ANIXOPS},
		"anixops tls":    {Security: forwardv1.LinkSecurity_LINK_SECURITY_ANIXOPS, Carrier: forwardv1.AnixOpsCarrier_ANIXOPS_CARRIER_TLS_TCP},
		"anixops plain":  {Security: forwardv1.LinkSecurity_LINK_SECURITY_ANIXOPS, Carrier: forwardv1.AnixOpsCarrier_ANIXOPS_CARRIER_PLAIN},
		"unset":          nil,
		"anixops unset":  {Security: forwardv1.LinkSecurity_LINK_SECURITY_ANIXOPS, Carrier: forwardv1.AnixOpsCarrier_ANIXOPS_CARRIER_UNSPECIFIED},
		"anixops quic?!": {Security: forwardv1.LinkSecurity_LINK_SECURITY_ANIXOPS, Carrier: forwardv1.AnixOpsCarrier_ANIXOPS_CARRIER_AUTO},
	} {
		if udpOnly(tr) {
			t.Errorf("%s has a TCP port and goes unchecked", name)
		}
	}
}

func TestDiagnoseKnowsTheAnixOpsSockets(t *testing.T) {
	hop := func(engine forwardv1.Engine, ingress *forwardv1.LinkTransport, protocol forwardv1.L4Protocol) *forwardv1.NodeHop {
		return &forwardv1.NodeHop{Engine: engine, Ingress: ingress, Listen: &forwardv1.Listen{Port: 1, Protocol: protocol}}
	}
	anix := func(c forwardv1.AnixOpsCarrier) *forwardv1.LinkTransport {
		return &forwardv1.LinkTransport{Security: forwardv1.LinkSecurity_LINK_SECURITY_ANIXOPS, Carrier: c}
	}
	tcp, udp, both := forwardv1.L4Protocol_L4_PROTOCOL_TCP, forwardv1.L4Protocol_L4_PROTOCOL_UDP, forwardv1.L4Protocol_L4_PROTOCOL_TCP_UDP
	for name, c := range map[string]struct {
		hop  *forwardv1.NodeHop
		want []string
	}{
		"quic carrier is UDP":           {hop(forwardv1.Engine_ENGINE_ANIXOPS, anix(forwardv1.AnixOpsCarrier_ANIXOPS_CARRIER_QUIC), tcp), []string{"udp"}},
		"tls carrier is TCP":            {hop(forwardv1.Engine_ENGINE_ANIXOPS, anix(forwardv1.AnixOpsCarrier_ANIXOPS_CARRIER_TLS_TCP), udp), []string{"tcp"}},
		"plain carrier is TCP":          {hop(forwardv1.Engine_ENGINE_ANIXOPS, anix(forwardv1.AnixOpsCarrier_ANIXOPS_CARRIER_PLAIN), both), []string{"tcp"}},
		"auto carrier is both":          {hop(forwardv1.Engine_ENGINE_ANIXOPS, anix(forwardv1.AnixOpsCarrier_ANIXOPS_CARRIER_AUTO), tcp), []string{"tcp", "udp"}},
		"unspecified carrier is AUTO":   {hop(forwardv1.Engine_ENGINE_ANIXOPS, anix(forwardv1.AnixOpsCarrier_ANIXOPS_CARRIER_UNSPECIFIED), tcp), []string{"tcp", "udp"}},
		"raw ingress follows the route": {hop(forwardv1.Engine_ENGINE_ANIXOPS, &forwardv1.LinkTransport{Security: forwardv1.LinkSecurity_LINK_SECURITY_RAW}, both), []string{"tcp", "udp"}},
		"gost follows the route":        {hop(forwardv1.Engine_ENGINE_GOST, nil, udp), []string{"udp"}},
	} {
		if got := hopProtocols(c.hop); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
	if socketProcess(forwardv1.Engine_ENGINE_ANIXOPS) != "anixops-relay" || socketProcess(forwardv1.Engine_ENGINE_GOST) != "gost" || socketProcess(forwardv1.Engine_ENGINE_NFTABLES) != "" {
		t.Fatal("socket process names")
	}
}
