package forward

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	log "github.com/sirupsen/logrus"
)

// Forward link certificates (owner decision H28; PROTOCOL.md "Forward link
// certificates"). gost terminates and originates encrypted links with the
// node's link certificate, which Control's dedicated link CA issues:
//
//   - a link key of its own (ECDSA P-256), never the agent identity key,
//     and a new one at every renewal;
//   - asked for with IssueLinkCertificate over the agent certificate's mTLS
//     once a HelloAck lists forward.v1, renewed at renew_after_unix, and
//     whenever the node has no valid one;
//   - stored in gost's directory, not the Agent's PKI directory:
//     link.key (PKCS#8 PEM), link.crt and link-ca.crt (the whole link trust
//     bundle) in LinkOptions.Dir (/var/lib/anixops-gost/tls), the directory
//     0750 and the files 0640, group anixops-gost, so only the Agent writes
//     them and only gost reads them; each written to a temporary file and
//     renamed, the key and the certificate before the bundle;
//   - the bundle refreshed with GetLinkTrustBundle at start and hourly;
//   - gost reloaded after any file changed; when the node gains or loses
//     its link certificate the gost driver is rebuilt with or without the
//     link securities, the state applied again and the session restarted,
//     so Control plans with the node's new capabilities;
//   - on agent_cert_revoked the link key and certificate are deleted.
//
// A reload re-creates gost's services and so restarts their counters, but
// the driver records reloads only inside Apply (a follow-up of the gost
// driver adds a certificate-reload entry point that ends the counter
// epoch); until then Control counts nothing for the one observation
// interval of a renewal.

// Link file names in LinkOptions.Dir: the gost driver's DefaultLinkCert,
// DefaultLinkKey and DefaultLinkCA.
const (
	linkCertFile   = "link.crt"
	linkKeyFile    = "link.key"
	linkBundleFile = "link-ca.crt"
)

// Link certificate cadences.
const (
	linkBundleInterval = time.Hour
	linkRetryMin       = time.Minute
	linkRetryMax       = time.Hour
)

// linkTick is how often the link certificates are looked at (a variable
// for tests).
var linkTick = 30 * time.Second

// LinkOptions turn on forward link certificates.
type LinkOptions struct {
	// Dir is the directory gost reads them from: gost.DefaultDir + "/tls".
	Dir string
	// Group is gost's group (anixops-gost), which gets read access; empty
	// keeps the Agent's own group (tests).
	Group string
	// SetEnabled rebuilds the gost driver with the link securities (true)
	// or RAW links only (false).
	SetEnabled func(enabled bool) error
	// Reload makes a running gost read the files again.
	Reload func(ctx context.Context) error
}

// LinkClient is what the link certificates need of the control stream
// client (*agent.Client).
type LinkClient interface {
	IssueLinkCertificate(ctx context.Context, csrDER []byte) (*agentv1pb.LinkCertificate, error)
	LinkTrustBundle(ctx context.Context) ([][]byte, error)
	AgentPublicKey() crypto.PublicKey
	RestartSession()
}

type linkState struct {
	mu         sync.Mutex
	client     LinkClient
	negotiated bool
	enabled    bool
	notAfter   time.Time
	renewAt    time.Time
	issueAt    time.Time
	issueWait  time.Duration
	bundleAt   time.Time
	bundleWait time.Duration
	gid        int
	wake       chan struct{}
}

// AttachLinkClient gives the link certificates the client to call; the
// component then asks for one once a session negotiates forward.v1.
func (c *Component) AttachLinkClient(client LinkClient) {
	if c.opts.Links == nil {
		return
	}
	c.links.mu.Lock()
	c.links.client = client
	c.links.mu.Unlock()
	wake(c.links.wake)
}

// IdentityRejected handles Control refusing the agent certificate
// (agent.Client.OnIdentityRejected): on revocation the link key and
// certificate go with it.
func (c *Component) IdentityRejected(code string) {
	if c.opts.Links == nil || code != agentcontrol.ErrorCodeCertRevoked {
		return
	}
	dir := c.opts.Links.Dir
	for _, name := range []string{linkKeyFile, linkCertFile} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			c.logger.WithError(err).Warn("Could not delete the link certificate after the agent certificate was revoked")
		}
	}
	c.links.mu.Lock()
	c.links.notAfter, c.links.renewAt, c.links.issueAt = time.Time{}, time.Time{}, time.Time{}
	c.links.mu.Unlock()
	c.logger.Warn("The agent certificate was revoked: deleted the forward link key and certificate")
	c.linksChanged(c.ctx)
}

// linksAvailable tells whether gost has a link certificate to use.
func (c *Component) linksAvailable() bool {
	if c.opts.Links == nil {
		return c.opts.LinkCertificates
	}
	c.links.mu.Lock()
	defer c.links.mu.Unlock()
	return c.links.enabled
}

// startLinks reads what the directory holds and starts the loop.
func (c *Component) startLinks() {
	l := c.opts.Links
	c.links.gid = -1
	if l.Group != "" {
		if g, err := user.LookupGroup(l.Group); err == nil {
			if gid, err := strconv.Atoi(g.Gid); err == nil {
				c.links.gid = gid
			}
		} else {
			c.logger.WithError(err).WithField("group", l.Group).Warn("gost's group is missing; gost cannot read the link certificate (the installer creates it)")
		}
	}
	if cert, err := readCertificate(filepath.Join(l.Dir, linkCertFile)); err == nil && c.opts.Now().Before(cert.NotAfter) {
		c.links.notAfter = cert.NotAfter
		c.links.renewAt = cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) * 2 / 3)
	}
	c.links.enabled = c.opts.LinkCertificates
	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.runLinks() }()
	// The files may have expired or appeared while the Agent was down.
	c.linksChanged(c.ctx)
}

func (c *Component) runLinks() {
	ticker := time.NewTicker(linkTick)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		case <-c.links.wake:
		}
		c.linkRound(c.ctx)
	}
}

// linkRound refreshes the bundle and issues or renews the certificate when
// due.
func (c *Component) linkRound(ctx context.Context) {
	now := c.opts.Now()
	c.links.mu.Lock()
	client := c.links.client
	bundleDue := client != nil && !now.Before(c.links.bundleAt)
	issueDue := client != nil && c.links.negotiated && !now.Before(c.links.issueAt) &&
		(c.links.notAfter.IsZero() || !now.Before(c.links.renewAt) || !now.Before(c.links.notAfter))
	c.links.mu.Unlock()
	changed := false
	if issueDue {
		changed = c.issueLink(ctx, client, now) || changed
	} else if bundleDue {
		changed = c.refreshBundle(ctx, client, now) || changed
	}
	if changed {
		c.linksChanged(ctx)
	}
}

// backoff doubles wait within the link retry bounds.
func backoff(wait time.Duration) time.Duration {
	if wait <= 0 {
		return linkRetryMin
	}
	return min(wait*2, linkRetryMax)
}

// issueLink asks for a new link certificate with a new key and writes it.
func (c *Component) issueLink(ctx context.Context, client LinkClient, now time.Time) bool {
	entry := c.logger.WithField("dir", c.opts.Links.Dir)
	fail := func(err error, wait time.Duration) bool {
		c.links.mu.Lock()
		c.links.issueWait = wait
		c.links.issueAt = now.Add(wait)
		c.links.mu.Unlock()
		code := ""
		var coded *agentapi.ControlError
		if errors.As(err, &coded) {
			code = coded.Code
		}
		c.logChange("link-issue", err.Error(), func(e *log.Entry) {
			e.WithError(err).WithFields(log.Fields{"error_code": code, "retry_in": wait.String()}).Warn("Could not get the forward link certificate")
		})
		return false
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fail(err, linkRetryMin)
	}
	if agentKey := client.AgentPublicKey(); agentKey != nil && reflect.DeepEqual(agentKey, key.Public()) {
		return fail(errors.New("the link key equals the agent key"), linkRetryMin)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: c.nodeRef}}, key)
	if err != nil {
		return fail(err, linkRetryMin)
	}
	issued, err := client.IssueLinkCertificate(ctx, csr)
	if err != nil {
		c.links.mu.Lock()
		wait := backoff(c.links.issueWait)
		c.links.mu.Unlock()
		var coded *agentapi.ControlError
		if errors.As(err, &coded) && coded.Code == agentcontrol.ErrorCodeLinkNotNegotiated {
			// Ask again after a HelloAck that lists forward.v1.
			c.links.mu.Lock()
			c.links.negotiated = false
			c.links.mu.Unlock()
		}
		return fail(err, wait)
	}
	cert, err := x509.ParseCertificate(issued.GetCertificateDer())
	if err != nil {
		return fail(fmt.Errorf("Control's link certificate does not parse: %w", err), linkRetryMin)
	}
	if !reflect.DeepEqual(cert.PublicKey, key.Public()) || !now.Before(cert.NotAfter) {
		return fail(errors.New("Control's link certificate is not for the link key, or expired"), linkRetryMin)
	}
	bundle, err := bundlePEM(issued.GetTrustBundleDer())
	if err != nil {
		return fail(err, linkRetryMin)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fail(err, linkRetryMin)
	}
	if err := c.ensureLinkDir(); err != nil {
		return fail(err, linkRetryMin)
	}
	// The key and the certificate first, then the bundle that verifies the
	// peers.
	for _, f := range []struct {
		name string
		data []byte
	}{
		{linkKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})},
		{linkCertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})},
		{linkBundleFile, bundle},
	} {
		if err := c.writeLinkFile(f.name, f.data); err != nil {
			return fail(err, linkRetryMin)
		}
	}
	renewAt := time.Unix(issued.GetRenewAfterUnix(), 0)
	if issued.GetRenewAfterUnix() <= 0 {
		renewAt = cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) * 2 / 3)
	}
	c.links.mu.Lock()
	c.links.notAfter, c.links.renewAt, c.links.issueWait, c.links.issueAt = cert.NotAfter, renewAt, 0, time.Time{}
	c.links.bundleAt, c.links.bundleWait = now.Add(linkBundleInterval), 0
	c.links.mu.Unlock()
	c.logChange("link-issue", "", nil)
	entry.WithFields(log.Fields{"serial": issued.GetSerial(), "dns_name": issued.GetDnsName(), "not_after": cert.NotAfter.UTC().Format(time.RFC3339),
		"renew_after": renewAt.UTC().Format(time.RFC3339)}).Info("Installed the forward link certificate")
	return true
}

// refreshBundle rewrites the trust bundle when the set of link CAs changed.
func (c *Component) refreshBundle(ctx context.Context, client LinkClient, now time.Time) bool {
	ders, err := client.LinkTrustBundle(ctx)
	c.links.mu.Lock()
	if err != nil {
		c.links.bundleWait = backoff(c.links.bundleWait)
		c.links.bundleAt = now.Add(min(c.links.bundleWait, linkBundleInterval))
	} else {
		c.links.bundleWait, c.links.bundleAt = 0, now.Add(linkBundleInterval)
	}
	c.links.mu.Unlock()
	if err != nil {
		if !errors.Is(err, agentapi.ErrNoIdentity) {
			c.logChange("link-bundle", err.Error(), func(e *log.Entry) { e.WithError(err).Warn("Could not refresh the forward link trust bundle") })
		}
		return false
	}
	c.logChange("link-bundle", "", nil)
	bundle, err := bundlePEM(ders)
	if err != nil || len(ders) == 0 {
		return false
	}
	path := filepath.Join(c.opts.Links.Dir, linkBundleFile)
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, bundle) { // #nosec G304 -- our own directory
		return false
	}
	if err := c.ensureLinkDir(); err != nil {
		c.logger.WithError(err).Warn("Could not write the forward link trust bundle")
		return false
	}
	if err := c.writeLinkFile(linkBundleFile, bundle); err != nil {
		c.logger.WithError(err).Warn("Could not write the forward link trust bundle")
		return false
	}
	c.logger.WithField("cas", len(ders)).Info("Updated the forward link trust bundle")
	return true
}

// linksChanged reloads gost after the files changed, and rebuilds the gost
// driver when the node gained or lost a usable link certificate.
func (c *Component) linksChanged(ctx context.Context) {
	l := c.opts.Links
	now := c.opts.Now()
	_, keyErr := os.Stat(filepath.Join(l.Dir, linkKeyFile))
	_, bundleErr := os.Stat(filepath.Join(l.Dir, linkBundleFile))
	cert, certErr := readCertificate(filepath.Join(l.Dir, linkCertFile))
	usable := keyErr == nil && bundleErr == nil && certErr == nil && now.Before(cert.NotAfter)
	c.links.mu.Lock()
	switched := usable != c.links.enabled
	client := c.links.client
	c.links.mu.Unlock()
	if switched && l.SetEnabled != nil {
		if err := l.SetEnabled(usable); err != nil {
			c.logger.WithError(err).Error("Could not switch the gost driver's link securities")
			return
		}
	}
	c.links.mu.Lock()
	c.links.enabled = usable
	c.links.mu.Unlock()
	if switched {
		c.logger.WithField("link_certificate", usable).Info("The gost driver's encrypted links follow the link certificate; applying the state again")
		c.reapply(ctx)
		if client != nil {
			// Control replans with the node's new link securities.
			client.RestartSession()
		}
		return
	}
	if l.Reload != nil {
		if err := l.Reload(ctx); err != nil {
			c.logger.WithError(err).Warn("Could not reload gost after the link certificate changed")
		}
	}
}

// reapply applies the desired state again (a rebuilt driver renders
// differently).
func (c *Component) reapply(ctx context.Context) {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	if state := c.desiredState(); state != nil {
		c.apply(ctx, state)
	}
}

func (c *Component) ensureLinkDir() error {
	dir := c.opts.Links.Dir
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		return err
	}
	if c.links.gid >= 0 {
		return os.Chown(dir, -1, c.links.gid)
	}
	return nil
}

// writeLinkFile writes one file atomically, 0640 with gost's group.
func (c *Component) writeLinkFile(name string, data []byte) error {
	dir := c.opts.Links.Dir
	tmp, err := os.CreateTemp(dir, "."+name+"-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return err
	}
	if c.links.gid >= 0 {
		if err := tmp.Chown(-1, c.links.gid); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, filepath.Join(dir, name))
}

func bundlePEM(ders [][]byte) ([]byte, error) {
	var out bytes.Buffer
	for _, der := range ders {
		if _, err := x509.ParseCertificate(der); err != nil {
			return nil, fmt.Errorf("a link CA does not parse: %w", err)
		}
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	return out.Bytes(), nil
}

func readCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- our own directory
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("not PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
