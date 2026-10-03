// Package pki keeps the mTLS identity of the Agent control stream on disk
// (node-ops-service.md, section 5.3): a private key generated on the node,
// the client certificate Control's AgentEnrollment issued for it, and the CA
// bundle that signed it.
//
// Each node has its own directory under the root (DefaultRoot), named after
// the node ("proxy-12"):
//
//	identity.pem   the PKCS#8 private key, then the certificate (0600)
//	ca.pem         the agent CA bundle from the last issuance (0600)
//	identity.json  issuance metadata: serial, expiry, renewal time (0600)
//
// The key and the certificate share one file so a renewal replaces the pair
// with one rename. identity.pem is the source of truth: identity.json is
// used only when its serial matches. The directories are 0700. Files that
// are readable by group or others, or owned by another user, are refused, so
// the Agent enrolls again instead of using them. The key is never written
// anywhere else and is not "encrypted" with a derived key: file permissions
// are its protection.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
)

// DefaultRoot is where identities live unless AgentIdentity.CertDir says
// otherwise.
const DefaultRoot = "/var/lib/anix-agent/pki"

// Bootstrap methods recorded with an identity.
const (
	BootstrapNodeAPIKey           = "node-api-key"
	BootstrapEnrollmentCredential = "enrollment-credential"
	BootstrapRenewal              = "renewal"
)

// clockSkew tolerates a node clock slightly behind Control's when an issued
// certificate is checked.
const clockSkew = 5 * time.Minute

var (
	// ErrNotEnrolled means the node has no stored identity.
	ErrNotEnrolled = errors.New("agent identity is not enrolled")
	// ErrInsecureFile means a stored identity file is readable by group or
	// others, or not owned by the Agent's user.
	ErrInsecureFile = errors.New("agent identity file has insecure permissions")
	// ErrInvalidIssuance means Control answered with a certificate that does
	// not belong to the key, the node or the cluster this Agent expects.
	ErrInvalidIssuance = errors.New("issued agent certificate is invalid")
)

// Identity is an enrolled Agent's key and certificate.
type Identity struct {
	Key         *ecdsa.PrivateKey
	Leaf        *x509.Certificate
	TrustBundle []*x509.Certificate

	SPIFFEID   string
	Node       agentcontrol.AgentNode
	Cluster    string
	Serial     string
	NotBefore  time.Time
	NotAfter   time.Time
	RenewAfter time.Time

	// EnrolledAt is when the first certificate of this enrollment was
	// issued; RenewedAt when the current one replaced an earlier one.
	EnrolledAt time.Time
	RenewedAt  time.Time
	// Bootstrap is how the enrollment started: BootstrapNodeAPIKey or
	// BootstrapEnrollmentCredential.
	Bootstrap string
}

// TLSCertificate returns the identity as a TLS client certificate.
func (i *Identity) TLSCertificate() *tls.Certificate {
	if i == nil || i.Leaf == nil || i.Key == nil {
		return nil
	}
	return &tls.Certificate{Certificate: [][]byte{i.Leaf.Raw}, PrivateKey: i.Key, Leaf: i.Leaf}
}

// Expired reports whether the certificate can no longer authenticate.
func (i *Identity) Expired(now time.Time) bool {
	return i == nil || !now.Before(i.NotAfter)
}

// RenewalDue reports whether the certificate should be renewed.
func (i *Identity) RenewalDue(now time.Time) bool {
	return i != nil && !now.Before(i.RenewAfter)
}

// GenerateKey returns a new ECDSA P-256 key, which Control's CA accepts.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// NewCSR returns a PKCS#10 request in DER for key. Control uses only its
// public key and issues the identity of the authenticated node; the subject
// names the node for readability.
func NewCSR(key crypto.Signer, node agentcontrol.AgentNode) ([]byte, error) {
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: node.String()},
	}, key)
}

// Expectation is what an issued certificate must name.
type Expectation struct {
	Node agentcontrol.AgentNode
	// Cluster pins the SPIFFE cluster; empty accepts the cluster Control
	// names.
	Cluster string
	Now     time.Time
}

// FromIssued checks a certificate Control issued for key and returns the
// identity. The certificate must hold key's public key, name the expected
// node (and cluster, when pinned), allow client authentication, be valid now
// and chain to the bundle that came with it.
func FromIssued(key *ecdsa.PrivateKey, issued *agentv1pb.AgentCertificate, expect Expectation) (*Identity, error) {
	if key == nil || issued == nil || len(issued.CertificateDer) == 0 {
		return nil, fmt.Errorf("%w: no certificate", ErrInvalidIssuance)
	}
	leaf, err := x509.ParseCertificate(issued.CertificateDer)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidIssuance, err)
	}
	bundle := make([]*x509.Certificate, 0, len(issued.TrustBundleDer))
	for _, der := range issued.TrustBundleDer {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: trust bundle: %v", ErrInvalidIssuance, err)
		}
		bundle = append(bundle, certificate)
	}
	identity, err := newIdentity(key, leaf, bundle, expect)
	if err != nil {
		return nil, err
	}
	if issued.SpiffeId != "" && issued.SpiffeId != identity.SPIFFEID {
		return nil, fmt.Errorf("%w: Control named %s but the certificate carries %s", ErrInvalidIssuance, issued.SpiffeId, identity.SPIFFEID)
	}
	if len(bundle) == 0 {
		return nil, fmt.Errorf("%w: no trust bundle", ErrInvalidIssuance)
	}
	roots := x509.NewCertPool()
	for _, certificate := range bundle {
		roots.AddCert(certificate)
	}
	verifyAt := expect.Now
	if verifyAt.Before(leaf.NotBefore) && leaf.NotBefore.Sub(verifyAt) <= clockSkew {
		verifyAt = leaf.NotBefore
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, CurrentTime: verifyAt, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidIssuance, err)
	}
	if renewAfter := time.Unix(issued.RenewAfterUnix, 0); issued.RenewAfterUnix > 0 &&
		renewAfter.After(leaf.NotBefore) && renewAfter.Before(leaf.NotAfter) {
		identity.RenewAfter = renewAfter
	}
	return identity, nil
}

// newIdentity checks that leaf belongs to key and names the expected node.
func newIdentity(key *ecdsa.PrivateKey, leaf *x509.Certificate, bundle []*x509.Certificate, expect Expectation) (*Identity, error) {
	public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !public.Equal(key.Public()) {
		return nil, fmt.Errorf("%w: the certificate does not hold this Agent's key", ErrInvalidIssuance)
	}
	agentIdentity, err := agentcontrol.AgentIdentityFromCertificate(leaf)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidIssuance, err)
	}
	if agentIdentity.Node != expect.Node {
		return nil, fmt.Errorf("%w: the certificate names %s, this Agent runs %s", ErrInvalidIssuance, agentIdentity.Node, expect.Node)
	}
	if expect.Cluster != "" && agentIdentity.Cluster != expect.Cluster {
		return nil, fmt.Errorf("%w: the certificate belongs to cluster %q, AgentIdentity.Cluster is %q", ErrInvalidIssuance, agentIdentity.Cluster, expect.Cluster)
	}
	clientAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth {
		return nil, fmt.Errorf("%w: the certificate does not allow client authentication", ErrInvalidIssuance)
	}
	if !leaf.NotAfter.After(leaf.NotBefore) {
		return nil, fmt.Errorf("%w: empty validity", ErrInvalidIssuance)
	}
	return &Identity{
		Key: key, Leaf: leaf, TrustBundle: bundle,
		SPIFFEID: agentIdentity.String(), Node: agentIdentity.Node, Cluster: agentIdentity.Cluster,
		Serial: hex.EncodeToString(leaf.SerialNumber.Bytes()), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter,
		RenewAfter: defaultRenewAfter(leaf),
	}, nil
}

// defaultRenewAfter is two thirds of the certificate's lifetime, Control's
// renewal point when the metadata does not say.
func defaultRenewAfter(leaf *x509.Certificate) time.Time {
	return leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) * 2 / 3)
}
