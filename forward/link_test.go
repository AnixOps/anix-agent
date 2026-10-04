package forward

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	"github.com/AnixOps/anix-control/sdk/forward/driver/fake"
)

// linkRecorder stands in for the gost driver's switch and reload.
type linkRecorder struct {
	mu      sync.Mutex
	enabled []bool
	reloads atomic.Int64
}

func (r *linkRecorder) options(dir string) *LinkOptions {
	return &LinkOptions{
		Dir: dir,
		SetEnabled: func(enabled bool) error {
			r.mu.Lock()
			r.enabled = append(r.enabled, enabled)
			r.mu.Unlock()
			return nil
		},
		Reload: func(context.Context) error { r.reloads.Add(1); return nil },
	}
}

func (r *linkRecorder) switches() []bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]bool(nil), r.enabled...)
}

func readPEM(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s is not PEM", path)
	}
	return block.Bytes
}

func TestLinkCertificateLifecycle(t *testing.T) {
	previous := linkTick
	linkTick = 50 * time.Millisecond
	t.Cleanup(func() { linkTick = previous })

	control := newForwardControl(t, agentcontrol.CapabilityConfig, agentcontrol.CapabilityPackageReports, agentcontrol.CapabilityForward)
	control.SetLinkUnavailable(true)
	root := t.TempDir()
	dir := filepath.Join(root, "gost", "tls")
	recorder := &linkRecorder{}
	agent := startStreamAgent(t, control, root, fake.NewHost(nil), func(o *Options) { o.Links = recorder.options(dir) })
	eventually(t, "the forward.v1 session", func() bool { return agent.client.Negotiated(agentcontrol.CapabilityForward) })

	// link_cert_unavailable: nothing written, the Agent keeps trying.
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(dir, linkCertFile)); err == nil {
		t.Fatal("a link certificate without the link CA")
	}
	control.SetLinkUnavailable(false)
	agent.h.c.links.mu.Lock()
	agent.h.c.links.issueAt = time.Time{}
	agent.h.c.links.mu.Unlock()

	eventually(t, "the link certificate", func() bool { return len(control.LinkCertificates()) == 1 })
	eventually(t, "the gost driver switched to encrypted links", func() bool {
		s := recorder.switches()
		return len(s) == 1 && s[0]
	})
	// The files: key and certificate of the node, the bundle with the link
	// CA, 0640 in a 0750 directory.
	for _, name := range []string{linkKeyFile, linkCertFile, linkBundleFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o640 {
			t.Fatalf("%s mode %v, want 0640", name, info.Mode().Perm())
		}
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o750 {
		t.Fatalf("link directory: %v, %v", info, err)
	}
	cert, err := x509.ParseCertificate(readPEM(t, filepath.Join(dir, linkCertFile)))
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(readPEM(t, filepath.Join(dir, linkKeyFile)))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(key.(*ecdsa.PrivateKey).Public(), cert.PublicKey) {
		t.Fatal("the link key does not match the link certificate")
	}
	if reflect.DeepEqual(cert.PublicKey, agent.client.AgentPublicKey()) {
		t.Fatal("the link key is the agent key")
	}
	roots := x509.NewCertPool()
	roots.AddCert(control.LinkCA())
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: testNode.String(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("the link certificate does not verify for %s: %v", testNode.String(), err)
	}
	bundle, err := x509.ParseCertificate(readPEM(t, filepath.Join(dir, linkBundleFile)))
	if err != nil || !bundle.Equal(control.LinkCA()) {
		t.Fatalf("bundle %v, %v", bundle, err)
	}
	// The session restarted, so Control plans with the new capabilities.
	eventually(t, "a new Hello after the switch", func() bool { return len(control.Hellos()) >= 2 })

	// A rotation: the next CA joins the bundle at the hourly refresh.
	next := control.AddLinkCA()
	reloads := recorder.reloads.Load()
	agent.h.c.links.mu.Lock()
	agent.h.c.links.bundleAt = time.Time{}
	agent.h.c.links.mu.Unlock()
	eventually(t, "the refreshed bundle", func() bool {
		data, _ := os.ReadFile(filepath.Join(dir, linkBundleFile))
		rest, n := data, 0
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if c, err := x509.ParseCertificate(block.Bytes); err == nil && (c.Equal(next) || c.Equal(control.LinkCA())) {
				n++
			}
		}
		return n == 2
	})
	eventually(t, "gost reloaded for the new bundle", func() bool { return recorder.reloads.Load() > reloads })

	// Renewal at renew_after with a new key, then a reload.
	reloads = recorder.reloads.Load()
	agent.h.c.links.mu.Lock()
	agent.h.c.links.renewAt = time.Now().Add(-time.Second)
	agent.h.c.links.mu.Unlock()
	eventually(t, "the renewed link certificate", func() bool { return len(control.LinkCertificates()) == 2 })
	eventually(t, "gost reloaded for the renewed certificate", func() bool { return recorder.reloads.Load() > reloads })
	renewed := control.LinkCertificates()[1]
	if reflect.DeepEqual(renewed.PublicKey, cert.PublicKey) {
		t.Fatal("the renewal reused the link key")
	}
	if len(recorder.switches()) != 1 {
		t.Fatalf("switches %v: a renewal must only reload", recorder.switches())
	}

	// Revocation of the agent certificate deletes the link key and
	// certificate and switches gost back to RAW links.
	control.RefuseCertificates(agentcontrol.ErrorCodeCertRevoked)
	control.DropSessions()
	eventually(t, "the link key and certificate deleted", func() bool {
		_, keyErr := os.Stat(filepath.Join(dir, linkKeyFile))
		_, certErr := os.Stat(filepath.Join(dir, linkCertFile))
		return os.IsNotExist(keyErr) && os.IsNotExist(certErr)
	})
	eventually(t, "gost back to RAW links", func() bool {
		s := recorder.switches()
		return len(s) == 2 && !s[1]
	})
}

func TestLinkCertificateNotNegotiated(t *testing.T) {
	previous := linkTick
	linkTick = 50 * time.Millisecond
	t.Cleanup(func() { linkTick = previous })
	// Control does not serve forward.v1: the Agent never asks.
	control := newForwardControl(t, agentcontrol.CapabilityConfig, agentcontrol.CapabilityPackageReports)
	root := t.TempDir()
	recorder := &linkRecorder{}
	agent := startStreamAgent(t, control, root, fake.NewHost(nil), func(o *Options) { o.Links = recorder.options(filepath.Join(root, "tls")) })
	eventually(t, "the session", func() bool { return agent.client.Negotiated(agentcontrol.CapabilityConfig) })
	time.Sleep(300 * time.Millisecond)
	if n := len(control.LinkCertificates()); n != 0 {
		t.Fatalf("%d link certificates without forward.v1", n)
	}
}
