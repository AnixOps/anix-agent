package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
)

const (
	identityFile = "identity.pem"
	bundleFile   = "ca.pem"
	metadataFile = "identity.json"

	dirMode  fs.FileMode = 0o700
	fileMode fs.FileMode = 0o600

	pemPrivateKey  = "PRIVATE KEY"
	pemCertificate = "CERTIFICATE"
)

// Store is the identity directory of one node.
type Store struct {
	dir  string
	node agentcontrol.AgentNode
}

// NewStore returns the store of node under root (DefaultRoot when empty).
func NewStore(root string, node agentcontrol.AgentNode) (*Store, error) {
	if !node.Valid() {
		return nil, fmt.Errorf("agent identity store: invalid node %q", node.String())
	}
	if root == "" {
		root = DefaultRoot
	}
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("agent identity directory %q must be an absolute path", root)
	}
	return &Store{dir: filepath.Join(filepath.Clean(root), node.String()), node: node}, nil
}

// Dir is the node's identity directory.
func (s *Store) Dir() string { return s.dir }

// Node is the node the store belongs to.
func (s *Store) Node() agentcontrol.AgentNode { return s.node }

// metadata is identity.json.
type metadata struct {
	SPIFFEID   string    `json:"spiffe_id"`
	Node       string    `json:"node"`
	Serial     string    `json:"serial"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	RenewAfter time.Time `json:"renew_after"`
	EnrolledAt time.Time `json:"enrolled_at"`
	RenewedAt  time.Time `json:"renewed_at,omitzero"`
	Bootstrap  string    `json:"bootstrap,omitempty"`
}

// Load reads the node's identity. It answers ErrNotEnrolled without one,
// ErrInsecureFile for files others could read or replace, and an error for
// a key and certificate that do not belong together or to this node.
func (s *Store) Load(expect Expectation) (*Identity, error) {
	identityPath := filepath.Join(s.dir, identityFile)
	data, err := readPrivateFile(identityPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	key, leaf, err := decodeIdentity(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", identityPath, err)
	}
	var bundle []*x509.Certificate
	if raw, err := readPrivateFile(filepath.Join(s.dir, bundleFile)); err == nil {
		bundle, _ = decodeCertificates(raw)
	}
	if expect.Node == (agentcontrol.AgentNode{}) {
		expect.Node = s.node
	}
	identity, err := newIdentity(key, leaf, bundle, expect)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", identityPath, err)
	}
	if raw, err := readPrivateFile(filepath.Join(s.dir, metadataFile)); err == nil {
		var meta metadata
		if json.Unmarshal(raw, &meta) == nil && meta.Serial == identity.Serial {
			if meta.RenewAfter.After(identity.NotBefore) && meta.RenewAfter.Before(identity.NotAfter) {
				identity.RenewAfter = meta.RenewAfter
			}
			identity.EnrolledAt, identity.RenewedAt, identity.Bootstrap = meta.EnrolledAt, meta.RenewedAt, meta.Bootstrap
		}
	}
	return identity, nil
}

// Save stores identity, replacing the key and certificate in one rename.
func (s *Store) Save(identity *Identity) error {
	if identity == nil || identity.Key == nil || identity.Leaf == nil {
		return errors.New("agent identity store: nothing to save")
	}
	if identity.Node != s.node {
		return fmt.Errorf("agent identity store: identity of %s does not belong in %s", identity.Node, s.dir)
	}
	// The root is created private when missing; an existing one keeps the
	// operator's mode. The node directory is always private.
	if err := createPrivateDir(filepath.Dir(s.dir)); err != nil {
		return err
	}
	if err := createPrivateDir(s.dir); err != nil {
		return err
	}
	if err := os.Chmod(s.dir, dirMode); err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(identity.Key)
	if err != nil {
		return err
	}
	var pair bytes.Buffer
	_ = pem.Encode(&pair, &pem.Block{Type: pemPrivateKey, Bytes: keyDER})
	_ = pem.Encode(&pair, &pem.Block{Type: pemCertificate, Bytes: identity.Leaf.Raw})
	var bundle bytes.Buffer
	for _, certificate := range identity.TrustBundle {
		_ = pem.Encode(&bundle, &pem.Block{Type: pemCertificate, Bytes: certificate.Raw})
	}
	meta, err := json.MarshalIndent(metadata{
		SPIFFEID: identity.SPIFFEID, Node: identity.Node.String(), Serial: identity.Serial,
		NotBefore: identity.NotBefore.UTC(), NotAfter: identity.NotAfter.UTC(), RenewAfter: identity.RenewAfter.UTC(),
		EnrolledAt: identity.EnrolledAt.UTC(), RenewedAt: identity.RenewedAt.UTC(), Bootstrap: identity.Bootstrap,
	}, "", "  ")
	if err != nil {
		return err
	}
	if bundle.Len() > 0 {
		if err := writePrivateFile(filepath.Join(s.dir, bundleFile), bundle.Bytes()); err != nil {
			return err
		}
	}
	if err := writePrivateFile(filepath.Join(s.dir, identityFile), pair.Bytes()); err != nil {
		return err
	}
	return writePrivateFile(filepath.Join(s.dir, metadataFile), append(meta, '\n'))
}

// Discard removes the stored identity, after Control refused it or it
// expired; the Agent enrolls again.
func (s *Store) Discard() error {
	var errs []error
	for _, name := range []string{identityFile, metadataFile, bundleFile} {
		if err := os.Remove(filepath.Join(s.dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func decodeIdentity(data []byte) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	var (
		key  *ecdsa.PrivateKey
		leaf *x509.Certificate
	)
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		switch block.Type {
		case pemPrivateKey:
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("private key: %w", err)
			}
			ecKey, ok := parsed.(*ecdsa.PrivateKey)
			if !ok {
				return nil, nil, errors.New("private key is not ECDSA")
			}
			key = ecKey
		case pemCertificate:
			if leaf != nil {
				continue
			}
			parsed, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("certificate: %w", err)
			}
			leaf = parsed
		}
	}
	if key == nil || leaf == nil {
		return nil, nil, errors.New("identity file needs a private key and a certificate")
	}
	return key, leaf, nil
}

func decodeCertificates(data []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return certificates, nil
		}
		if block.Type != pemCertificate {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}
}

// readPrivateFile reads a file only when its permissions keep it private
// to the Agent's user.
func readPrivateFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := checkPrivate(path, info); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	if _, err := buffer.ReadFrom(file); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// checkPrivate refuses a regular file with group or other permissions, or
// owned by another user.
func checkPrivate(path string, info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrInsecureFile, path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s has mode %04o, want 0600", ErrInsecureFile, path, info.Mode().Perm())
	}
	if !ownedByCurrentUser(info) {
		return fmt.Errorf("%w: %s is not owned by the Agent's user", ErrInsecureFile, path)
	}
	return nil
}

// createPrivateDir creates dir with mode 0700 (whatever the umask) when it
// does not exist.
func createPrivateDir(dir string) error {
	info, err := os.Stat(dir)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", dir)
		}
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	return os.Chmod(dir, dirMode)
}

// writePrivateFile writes data to path with mode 0600 through a temporary
// file in the same directory, synced, then renamed over path.
func writePrivateFile(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer func() {
		if name != "" {
			_ = os.Remove(name)
		}
	}()
	if err := temporary.Chmod(fileMode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	name = ""
	syncDir(filepath.Dir(path))
	return nil
}

func syncDir(dir string) {
	if handle, err := os.Open(dir); err == nil {
		_ = handle.Sync()
		_ = handle.Close()
	}
}

// Status describes a stored identity for status output, without the key.
type Status struct {
	Node       string    `json:"node"`
	Dir        string    `json:"dir"`
	State      string    `json:"state"`
	Problem    string    `json:"problem,omitempty"`
	SPIFFEID   string    `json:"spiffe_id,omitempty"`
	Serial     string    `json:"serial,omitempty"`
	NotBefore  time.Time `json:"not_before,omitzero"`
	NotAfter   time.Time `json:"not_after,omitzero"`
	RenewAfter time.Time `json:"renew_after,omitzero"`
	EnrolledAt time.Time `json:"enrolled_at,omitzero"`
	RenewedAt  time.Time `json:"renewed_at,omitzero"`
	Bootstrap  string    `json:"bootstrap,omitempty"`
	CAs        int       `json:"trust_bundle_cas"`
}

// Identity states of Status.
const (
	StateValid       = "valid"
	StateRenewalDue  = "renewal-due"
	StateExpired     = "expired"
	StateNotEnrolled = "not-enrolled"
	StateInvalid     = "invalid"
)

// Inspect describes the node's stored identity at now.
func (s *Store) Inspect(now time.Time) Status {
	status := Status{Node: s.node.String(), Dir: s.dir}
	identity, err := s.Load(Expectation{Node: s.node, Now: now})
	switch {
	case errors.Is(err, ErrNotEnrolled):
		status.State = StateNotEnrolled
		return status
	case err != nil:
		status.State, status.Problem = StateInvalid, err.Error()
		return status
	}
	status.SPIFFEID, status.Serial = identity.SPIFFEID, identity.Serial
	status.NotBefore, status.NotAfter, status.RenewAfter = identity.NotBefore, identity.NotAfter, identity.RenewAfter
	status.EnrolledAt, status.RenewedAt, status.Bootstrap = identity.EnrolledAt, identity.RenewedAt, identity.Bootstrap
	status.CAs = len(identity.TrustBundle)
	switch {
	case identity.Expired(now):
		status.State = StateExpired
	case identity.RenewalDue(now):
		status.State = StateRenewalDue
	default:
		status.State = StateValid
	}
	return status
}

// List returns the stores of every node directory under root.
func List(root string) ([]*Store, error) {
	if root == "" {
		root = DefaultRoot
	}
	entries, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var stores []*Store
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		node, err := agentcontrol.ParseAgentNode(entry.Name())
		if err != nil {
			continue
		}
		store, err := NewStore(root, node)
		if err != nil {
			continue
		}
		stores = append(stores, store)
	}
	sort.Slice(stores, func(i, j int) bool { return stores[i].dir < stores[j].dir })
	return stores, nil
}
