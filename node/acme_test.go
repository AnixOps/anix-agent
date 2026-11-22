package node

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/AnixOps/anix-agent/v5/conf"
	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/registration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestACMEAccountPath(t *testing.T) {
	assert.Equal(t, filepath.Join("/etc/anixops/cert", "user", "user-me@example.com.json"),
		accountPath("/etc/anixops/cert/node.pem", "me@example.com"))
}

func TestACMEAccountIsStoredAndLoaded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user", "user-me@example.com.json")

	// No file: a new, unregistered account.
	account, err := loadACMEAccount(path, "me@example.com")
	require.NoError(t, err)
	assert.Nil(t, account.GetRegistration())
	assert.Equal(t, "me@example.com", account.GetEmail())
	require.IsType(t, &ecdsa.PrivateKey{}, account.GetPrivateKey())

	account.registration = &registration.Resource{URI: "https://acme.test/acct/1", Body: acme.Account{Status: "valid"}}
	require.NoError(t, saveACMEAccount(path, account))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	// The layout: Email, Registration and Key (SEC 1 PEM).
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var members map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &members))
	assert.ElementsMatch(t, []string{"Email", "Registration", "Key"}, keys(members))
	var stored struct {
		Email        string
		Registration *registration.Resource
		Key          string
	}
	require.NoError(t, json.Unmarshal(data, &stored))
	assert.Equal(t, "me@example.com", stored.Email)
	assert.Equal(t, "https://acme.test/acct/1", stored.Registration.URI)
	block, _ := pem.Decode([]byte(stored.Key))
	require.NotNil(t, block)
	assert.Equal(t, "EC PRIVATE KEY", block.Type)
	_, err = x509.ParseECPrivateKey(block.Bytes)
	require.NoError(t, err)

	loaded, err := loadACMEAccount(path, "me@example.com")
	require.NoError(t, err)
	assert.Equal(t, account.registration, loaded.GetRegistration())
	assert.True(t, account.key.(*ecdsa.PrivateKey).Equal(loaded.GetPrivateKey()))

	// The file of another e-mail: a new account.
	other, err := loadACMEAccount(path, "other@example.com")
	require.NoError(t, err)
	assert.Nil(t, other.GetRegistration())
	assert.False(t, account.key.(*ecdsa.PrivateKey).Equal(other.GetPrivateKey()))
}

func TestACMEAccountWrittenByEarlierVersionsLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user-old@example.com.json")
	account, err := loadACMEAccount(path, "old@example.com")
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(account.key.(*ecdsa.PrivateKey))
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	// The key as text and as bytes (base64 in JSON).
	for _, key := range []any{string(keyPEM), keyPEM} {
		data, err := json.Marshal(map[string]any{
			"Email": "old@example.com", "Key": key,
			"Registration": map[string]any{"body": map[string]any{"status": "valid"}, "uri": "https://acme.test/acct/7"},
		})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, data, 0o600))
		loaded, err := loadACMEAccount(path, "old@example.com")
		require.NoError(t, err)
		assert.Equal(t, "https://acme.test/acct/7", loaded.GetRegistration().URI)
		assert.True(t, account.key.(*ecdsa.PrivateKey).Equal(loaded.GetPrivateKey()))
	}

	require.NoError(t, os.WriteFile(path, []byte("{"), 0o600))
	_, err = loadACMEAccount(path, "old@example.com")
	assert.Error(t, err)
}

func TestRenewCertificateKeepsACertificateFarFromExpiry(t *testing.T) {
	dir := t.TempDir()
	config := &conf.CertConfig{CertMode: "dns", Provider: "cloudflare", Email: "me@example.com", CertDomain: "node.example.com",
		CertFile: filepath.Join(dir, "cert.pem"), KeyFile: filepath.Join(dir, "key.pem")}
	assert.Error(t, renewCertificate(config), "no certificate to renew")

	require.NoError(t, writeSelfSignedCertificate(config.CertDomain, config.CertFile, config.KeyFile))
	before, err := os.ReadFile(config.CertFile)
	require.NoError(t, err)
	require.NoError(t, renewCertificate(config))
	after, err := os.ReadFile(config.CertFile)
	require.NoError(t, err)
	assert.Equal(t, before, after)
	assert.NoDirExists(t, filepath.Join(dir, "user"), "no account without a renewal")
}

// TestACMEDNSIntegration obtains and renews a real certificate. It runs
// only with ANIXOPS_ACME_INTEGRATION=1 and the DNS provider's credentials
// in the environment.
func TestACMEDNSIntegration(t *testing.T) {
	if os.Getenv("ANIXOPS_ACME_INTEGRATION") != "1" {
		t.Skip("set ANIXOPS_ACME_INTEGRATION=1 to run the ACME DNS integration test")
	}
	env := func(name, fallback string) string {
		if value := os.Getenv(name); value != "" {
			return value
		}
		return fallback
	}
	dir := t.TempDir()
	config := &conf.CertConfig{
		CertMode:   "dns",
		Email:      env("ANIXOPS_ACME_EMAIL", "test@example.com"),
		CertDomain: env("ANIXOPS_ACME_DOMAIN", "test.example.com"),
		Provider:   env("ANIXOPS_ACME_PROVIDER", "cloudflare"),
		CertFile:   filepath.Join(dir, "cert.pem"),
		KeyFile:    filepath.Join(dir, "key.pem"),
	}
	require.NoError(t, ensureCertificate(config))
	assert.FileExists(t, config.KeyFile)
	assert.FileExists(t, accountPath(config.CertFile, config.Email))
	require.NoError(t, renewCertificate(config))
}

func keys(m map[string]json.RawMessage) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	return names
}
