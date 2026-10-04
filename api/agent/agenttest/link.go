package agenttest

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net/url"
	"reflect"
	"time"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"google.golang.org/grpc/codes"
)

// Forward link certificates (H28), modelled on anix-control's
// AgentEnrollment.IssueLinkCertificate and GetLinkTrustBundle: a link CA of
// its own, calls only with a valid agent client certificate,
// link_cert_not_negotiated unless the node's last Hello negotiated
// forward.v1, link_cert_request_invalid for a CSR with the agent key or
// another name, link_cert_unavailable while SetLinkUnavailable.

type linkState struct {
	caKey       *ecdsa.PrivateKey
	caCert      *x509.Certificate
	extraCAs    []*x509.Certificate
	unavailable bool
	lifetime    time.Duration
	issued      []*x509.Certificate
	bundles     int
	// helloForward: the node's last Hello negotiated forward.v1.
	helloForward bool
}

func (c *Control) linkCALocked() (*ecdsa.PrivateKey, *x509.Certificate) {
	if c.link.caCert == nil {
		c.link.caKey, c.link.caCert = newCA(c.t, "forward link CA")
	}
	return c.link.caKey, c.link.caCert
}

// LinkCA answers the link CA.
func (c *Control) LinkCA() *x509.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ca := c.linkCALocked()
	return ca
}

// AddLinkCA adds a next link CA to the trust bundle (a rotation).
func (c *Control) AddLinkCA() *x509.Certificate {
	_, ca := newCA(c.t, "next forward link CA")
	c.mu.Lock()
	c.link.extraCAs = append(c.link.extraCAs, ca)
	c.mu.Unlock()
	return ca
}

// SetLinkUnavailable makes both calls answer link_cert_unavailable (a
// Control without the link CA).
func (c *Control) SetLinkUnavailable(unavailable bool) {
	c.mu.Lock()
	c.link.unavailable = unavailable
	c.mu.Unlock()
}

// SetLinkLifetime sets the lifetime of the next link certificates (7 days
// by default); renew_after is two thirds of it.
func (c *Control) SetLinkLifetime(lifetime time.Duration) {
	c.mu.Lock()
	c.link.lifetime = lifetime
	c.mu.Unlock()
}

// LinkCertificates answers every link certificate issued.
func (c *Control) LinkCertificates() []*x509.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*x509.Certificate(nil), c.link.issued...)
}

// LinkBundleCalls counts the GetLinkTrustBundle calls answered.
func (c *Control) LinkBundleCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.link.bundles
}

func (c *Control) linkBundleLocked() [][]byte {
	_, ca := c.linkCALocked()
	out := [][]byte{ca.Raw}
	for _, extra := range c.link.extraCAs {
		out = append(out, extra.Raw)
	}
	return out
}

// linkPeer checks the call's agent client certificate.
func (c *Control) linkPeer(ctx context.Context) (*x509.Certificate, error) {
	chain := peerChain(ctx)
	if len(chain) == 0 || c.Mode() == ModeOff {
		return nil, refuse(ctx, codes.Unauthenticated, agentcontrol.ErrorCodeCertInvalid, "link certificates need the agent client certificate")
	}
	return c.verifyPeer(ctx, chain)
}

// IssueLinkCertificate implements AgentEnrollment.IssueLinkCertificate.
func (c *Control) IssueLinkCertificate(ctx context.Context, request *agentv1pb.IssueLinkCertificateRequest) (*agentv1pb.IssueLinkCertificateResponse, error) {
	leaf, err := c.linkPeer(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.link.unavailable:
		return nil, refuse(ctx, codes.FailedPrecondition, agentcontrol.ErrorCodeLinkUnavailable, "this Control issues no link certificates")
	case !c.link.helloForward:
		return nil, refuse(ctx, codes.FailedPrecondition, agentcontrol.ErrorCodeLinkNotNegotiated, "the node's last Hello did not negotiate forward.v1")
	}
	csr, err := x509.ParseCertificateRequest(request.GetCsrDer())
	if err != nil || csr.CheckSignature() != nil || len(csr.IPAddresses) > 0 || len(csr.EmailAddresses) > 0 ||
		reflect.DeepEqual(csr.PublicKey, leaf.PublicKey) {
		return nil, refuse(ctx, codes.InvalidArgument, agentcontrol.ErrorCodeLinkRequestInvalid, "the link certificate request is invalid")
	}
	node := c.node()
	identity, err := agentcontrol.NewAgentIdentity(c.Cluster, node)
	if err != nil {
		return nil, err
	}
	for _, name := range csr.DNSNames {
		if name != node.String() {
			return nil, refuse(ctx, codes.InvalidArgument, agentcontrol.ErrorCodeLinkRequestInvalid, "the request names another DNS name")
		}
	}
	lifetime := c.link.lifetime
	if lifetime <= 0 {
		lifetime = 7 * 24 * time.Hour
	}
	now := time.Now()
	serialBytes := make([]byte, 16)
	_, _ = rand.Read(serialBytes)
	serialBytes[0] &= 0x7f
	serial := new(big.Int).SetBytes(serialBytes)
	caKey, caCert := c.linkCALocked()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: node.String()}, DNSNames: []string{node.String()},
		URIs: []*url.URL{identity.URL()}, NotBefore: now.Add(-time.Second), NotAfter: now.Add(lifetime),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	c.link.issued = append(c.link.issued, cert)
	return &agentv1pb.IssueLinkCertificateResponse{Certificate: &agentv1pb.LinkCertificate{
		CertificateDer: der, TrustBundleDer: c.linkBundleLocked(), SpiffeId: identity.String(), Node: node.String(),
		DnsName: node.String(), Serial: hex.EncodeToString(serial.Bytes()), NotAfterUnix: template.NotAfter.Unix(),
		RenewAfterUnix: now.Add(lifetime * 2 / 3).Unix(),
	}}, nil
}

// GetLinkTrustBundle implements AgentEnrollment.GetLinkTrustBundle.
func (c *Control) GetLinkTrustBundle(ctx context.Context, _ *agentv1pb.GetLinkTrustBundleRequest) (*agentv1pb.GetLinkTrustBundleResponse, error) {
	if _, err := c.linkPeer(ctx); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.link.unavailable {
		return nil, refuse(ctx, codes.FailedPrecondition, agentcontrol.ErrorCodeLinkUnavailable, "this Control issues no link certificates")
	}
	c.link.bundles++
	return &agentv1pb.GetLinkTrustBundleResponse{TrustBundleDer: c.linkBundleLocked()}, nil
}
