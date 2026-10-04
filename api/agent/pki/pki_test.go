package pki

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testNode = agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: 12}

type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key, err := GenerateKey()
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "agent CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return testCA{key: key, cert: cert}
}

type issueOptions struct {
	node       agentcontrol.AgentNode
	cluster    string
	usages     []x509.ExtKeyUsage
	lifetime   time.Duration
	renewAfter time.Time
}

func (ca testCA) issue(t *testing.T, public *ecdsa.PublicKey, options issueOptions) *agentv1pb.AgentCertificate {
	t.Helper()
	if options.node == (agentcontrol.AgentNode{}) {
		options.node = testNode
	}
	if options.cluster == "" {
		options.cluster = "prod"
	}
	if options.usages == nil {
		options.usages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	if options.lifetime == 0 {
		options.lifetime = 7 * 24 * time.Hour
	}
	identity, err := agentcontrol.NewAgentIdentity(options.cluster, options.node)
	require.NoError(t, err)
	now := time.Now()
	serial := big.NewInt(now.UnixNano())
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: identity.String()},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(options.lifetime),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: options.usages, URIs: []*url.URL{identity.URL()},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, public, ca.key)
	require.NoError(t, err)
	renewAfter := options.renewAfter
	if renewAfter.IsZero() {
		renewAfter = now.Add(options.lifetime * 2 / 3)
	}
	return &agentv1pb.AgentCertificate{
		CertificateDer: der, TrustBundleDer: [][]byte{ca.cert.Raw}, SpiffeId: identity.String(), Node: options.node.String(),
		Serial: hex.EncodeToString(serial.Bytes()), NotAfterUnix: template.NotAfter.Unix(), RenewAfterUnix: renewAfter.Unix(),
	}
}

func TestFromIssuedAcceptsTheCertificateOfThisKeyAndNode(t *testing.T) {
	ca := newTestCA(t)
	key, err := GenerateKey()
	require.NoError(t, err)
	renewAfter := time.Now().Add(time.Hour).Truncate(time.Second)
	issued := ca.issue(t, &key.PublicKey, issueOptions{renewAfter: renewAfter})

	identity, err := FromIssued(key, issued, Expectation{Node: testNode, Cluster: "prod", Now: time.Now()})
	require.NoError(t, err)
	assert.Equal(t, "spiffe://anixops/prod/agent/proxy-12", identity.SPIFFEID)
	assert.Equal(t, testNode, identity.Node)
	assert.Equal(t, "prod", identity.Cluster)
	assert.Equal(t, issued.Serial, identity.Serial)
	assert.True(t, identity.RenewAfter.Equal(renewAfter), "Control's renew_after is used")
	require.NotNil(t, identity.TLSCertificate())
	assert.False(t, identity.Expired(time.Now()))
	assert.False(t, identity.RenewalDue(time.Now()))
	assert.True(t, identity.RenewalDue(renewAfter))

	// An unpinned cluster accepts Control's.
	_, err = FromIssued(key, issued, Expectation{Node: testNode, Now: time.Now()})
	require.NoError(t, err)

	// A renew_after outside the validity falls back to two thirds.
	issued.RenewAfterUnix = time.Now().Add(30 * 24 * time.Hour).Unix()
	identity, err = FromIssued(key, issued, Expectation{Node: testNode, Now: time.Now()})
	require.NoError(t, err)
	assert.True(t, identity.RenewAfter.Equal(defaultRenewAfter(identity.Leaf)))
}

func TestFromIssuedRefusesCertificatesThatAreNotThisAgents(t *testing.T) {
	ca := newTestCA(t)
	other := newTestCA(t)
	key, err := GenerateKey()
	require.NoError(t, err)
	otherKey, err := GenerateKey()
	require.NoError(t, err)
	expect := Expectation{Node: testNode, Cluster: "prod", Now: time.Now()}

	cases := map[string]*agentv1pb.AgentCertificate{
		"another key":     ca.issue(t, &otherKey.PublicKey, issueOptions{}),
		"another node":    ca.issue(t, &key.PublicKey, issueOptions{node: agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: 13}}),
		"a forward node":  ca.issue(t, &key.PublicKey, issueOptions{node: agentcontrol.AgentNode{Kind: agentcontrol.NodeKindForward, ID: 12}}),
		"another cluster": ca.issue(t, &key.PublicKey, issueOptions{cluster: "staging"}),
		"no client auth":  ca.issue(t, &key.PublicKey, issueOptions{usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}),
		"no certificate":  {},
		"a foreign CA":    other.issue(t, &key.PublicKey, issueOptions{}),
		"no trust bundle": func() *agentv1pb.AgentCertificate {
			c := ca.issue(t, &key.PublicKey, issueOptions{})
			c.TrustBundleDer = nil
			return c
		}(),
		"a SPIFFE ID differs": func() *agentv1pb.AgentCertificate {
			c := ca.issue(t, &key.PublicKey, issueOptions{})
			c.SpiffeId = "spiffe://anixops/prod/agent/proxy-99"
			return c
		}(),
	}
	cases["a foreign CA"].TrustBundleDer = [][]byte{ca.cert.Raw}
	for name, issued := range cases {
		_, err := FromIssued(key, issued, expect)
		require.Error(t, err, name)
		assert.True(t, errors.Is(err, ErrInvalidIssuance), name)
	}
}

func TestStoreSavesPrivatelyAndLoadsTheSameIdentity(t *testing.T) {
	ca := newTestCA(t)
	key, err := GenerateKey()
	require.NoError(t, err)
	identity, err := FromIssued(key, ca.issue(t, &key.PublicKey, issueOptions{}), Expectation{Node: testNode, Now: time.Now()})
	require.NoError(t, err)
	identity.EnrolledAt, identity.Bootstrap = time.Now().UTC().Truncate(time.Second), BootstrapNodeAPIKey

	root := filepath.Join(t.TempDir(), "pki")
	store, err := NewStore(root, testNode)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(root, "proxy-12"), store.Dir())
	_, err = store.Load(Expectation{})
	assert.True(t, errors.Is(err, ErrNotEnrolled))
	require.NoError(t, store.Save(identity))

	for path, mode := range map[string]os.FileMode{
		root: 0o700, store.Dir(): 0o700,
		filepath.Join(store.Dir(), "identity.pem"): 0o600, filepath.Join(store.Dir(), "ca.pem"): 0o600,
		filepath.Join(store.Dir(), "identity.json"): 0o600,
	} {
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, mode, info.Mode().Perm(), path)
	}
	entries, err := os.ReadDir(store.Dir())
	require.NoError(t, err)
	assert.Len(t, entries, 3, "no temporary files are left behind")

	loaded, err := store.Load(Expectation{Now: time.Now()})
	require.NoError(t, err)
	assert.True(t, loaded.Key.Equal(identity.Key))
	assert.Equal(t, identity.Serial, loaded.Serial)
	assert.Equal(t, identity.SPIFFEID, loaded.SPIFFEID)
	assert.True(t, loaded.RenewAfter.Equal(identity.RenewAfter.Truncate(time.Second)) || loaded.RenewAfter.Equal(identity.RenewAfter))
	assert.True(t, loaded.EnrolledAt.Equal(identity.EnrolledAt))
	assert.Equal(t, BootstrapNodeAPIKey, loaded.Bootstrap)
	assert.Len(t, loaded.TrustBundle, 1)

	status := store.Inspect(time.Now())
	assert.Equal(t, StateValid, status.State)
	assert.Equal(t, 1, status.CAs)
	assert.Equal(t, StateRenewalDue, store.Inspect(identity.RenewAfter.Add(time.Second)).State)
	assert.Equal(t, StateExpired, store.Inspect(identity.NotAfter).State)

	stores, err := List(root)
	require.NoError(t, err)
	require.Len(t, stores, 1)
	assert.Equal(t, testNode, stores[0].Node())

	require.NoError(t, store.Discard())
	assert.Equal(t, StateNotEnrolled, store.Inspect(time.Now()).State)
	require.NoError(t, store.Discard(), "discarding twice is harmless")
}

func TestStoreKeepsTheModeOfAnExistingRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "shared")
	require.NoError(t, os.Mkdir(root, 0o755))
	require.NoError(t, os.Chmod(root, 0o755))
	ca := newTestCA(t)
	key, err := GenerateKey()
	require.NoError(t, err)
	identity, err := FromIssued(key, ca.issue(t, &key.PublicKey, issueOptions{}), Expectation{Node: testNode, Now: time.Now()})
	require.NoError(t, err)
	store, err := NewStore(root, testNode)
	require.NoError(t, err)
	require.NoError(t, os.Mkdir(store.Dir(), 0o755))
	require.NoError(t, store.Save(identity))
	info, err := os.Stat(root)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm(), "an operator's existing root keeps its mode")
	info, err = os.Stat(store.Dir())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(), "the node directory is always private")
}

func TestStoreRefusesFilesOthersCanRead(t *testing.T) {
	store, identity := savedIdentity(t)
	path := filepath.Join(store.Dir(), "identity.pem")
	require.NoError(t, os.Chmod(path, 0o644))
	_, err := store.Load(Expectation{Now: time.Now()})
	assert.True(t, errors.Is(err, ErrInsecureFile))
	status := store.Inspect(time.Now())
	assert.Equal(t, StateInvalid, status.State)
	assert.Contains(t, status.Problem, "0644")

	// A new save replaces the file with a private one.
	require.NoError(t, store.Save(identity))
	_, err = store.Load(Expectation{Now: time.Now()})
	require.NoError(t, err)
}

func TestStoreRefusesAKeyAndCertificateThatDoNotMatch(t *testing.T) {
	store, _ := savedIdentity(t)
	ca := newTestCA(t)
	other, err := GenerateKey()
	require.NoError(t, err)
	foreign, err := FromIssued(other, ca.issue(t, &other.PublicKey, issueOptions{}), Expectation{Node: testNode, Now: time.Now()})
	require.NoError(t, err)
	mine, err := store.Load(Expectation{Now: time.Now()})
	require.NoError(t, err)
	foreign.Key = mine.Key
	require.NoError(t, store.Save(foreign))
	_, err = store.Load(Expectation{Now: time.Now()})
	assert.True(t, errors.Is(err, ErrInvalidIssuance))
}

func TestStoreIgnoresMetadataOfAnotherCertificate(t *testing.T) {
	store, identity := savedIdentity(t)
	metadataPath := filepath.Join(store.Dir(), "identity.json")
	var meta metadata
	raw, err := os.ReadFile(metadataPath)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &meta))
	meta.Serial = "00"
	meta.RenewAfter = identity.NotBefore.Add(time.Minute)
	raw, err = json.Marshal(meta)
	require.NoError(t, err)
	require.NoError(t, writePrivateFile(metadataPath, raw))
	loaded, err := store.Load(Expectation{Now: time.Now()})
	require.NoError(t, err)
	assert.True(t, loaded.RenewAfter.Equal(defaultRenewAfter(loaded.Leaf)))
	assert.Empty(t, loaded.Bootstrap)
}

func TestStorePinsTheCluster(t *testing.T) {
	store, _ := savedIdentity(t)
	_, err := store.Load(Expectation{Cluster: "staging", Now: time.Now()})
	assert.True(t, errors.Is(err, ErrInvalidIssuance))
}

func TestNewStoreNeedsAnAbsoluteRootAndANode(t *testing.T) {
	_, err := NewStore("relative/pki", testNode)
	require.Error(t, err)
	_, err = NewStore("/var/lib/anixops-agent/pki", agentcontrol.AgentNode{})
	require.Error(t, err)
	store, err := NewStore("", testNode)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(DefaultRoot, "proxy-12"), store.Dir())
}

func TestListSkipsOtherEntries(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"proxy-1", "forward-2", "proxy-01", "notes", ".hidden"} {
		require.NoError(t, os.Mkdir(filepath.Join(root, name), 0o700))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "proxy-3"), nil, 0o600))
	stores, err := List(root)
	require.NoError(t, err)
	var names []string
	for _, store := range stores {
		names = append(names, store.Node().String())
	}
	assert.Equal(t, []string{"forward-2", "proxy-1"}, names)
	missing, err := List(filepath.Join(root, "missing"))
	require.NoError(t, err)
	assert.Empty(t, missing)
}

func savedIdentity(t *testing.T) (*Store, *Identity) {
	t.Helper()
	ca := newTestCA(t)
	key, err := GenerateKey()
	require.NoError(t, err)
	identity, err := FromIssued(key, ca.issue(t, &key.PublicKey, issueOptions{}), Expectation{Node: testNode, Now: time.Now()})
	require.NoError(t, err)
	store, err := NewStore(t.TempDir(), testNode)
	require.NoError(t, err)
	require.NoError(t, store.Save(identity))
	return store, identity
}
