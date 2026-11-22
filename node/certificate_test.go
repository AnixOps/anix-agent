package node

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnsureCertificateModes(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	for _, config := range []*conf.CertConfig{nil, {}, {CertMode: "none"}, {CertMode: "file", CertFile: cert, KeyFile: key}} {
		assert.NoError(t, ensureCertificate(config), "%+v", config)
	}
	for _, mode := range []string{"file", "self", "http", "dns"} {
		assert.ErrorContains(t, ensureCertificate(&conf.CertConfig{CertMode: mode, CertFile: cert}), mode)
		assert.Error(t, ensureCertificate(&conf.CertConfig{CertMode: mode, KeyFile: key}), mode)
	}
	assert.ErrorContains(t, ensureCertificate(&conf.CertConfig{CertMode: "acme", CertFile: cert, KeyFile: key}), `"acme"`)
	_, err := os.Stat(cert)
	assert.True(t, os.IsNotExist(err), "nothing written")
}

func TestEnsureCertificateWritesASelfSignedCertificate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")
	config := &conf.CertConfig{CertMode: "self", CertDomain: "node.example.com",
		CertFile: filepath.Join(dir, "cert.pem"), KeyFile: filepath.Join(dir, "key", "key.pem")}
	require.NoError(t, ensureCertificate(config))

	info, err := os.Stat(config.CertFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
	info, err = os.Stat(config.KeyFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	certPEM, err := os.ReadFile(config.CertFile)
	require.NoError(t, err)
	keyPEM, err := os.ReadFile(config.KeyFile)
	require.NoError(t, err)
	certBlock, _ := pem.Decode(certPEM)
	require.NotNil(t, certBlock)
	assert.Equal(t, "CERTIFICATE", certBlock.Type)
	keyBlock, _ := pem.Decode(keyPEM)
	require.NotNil(t, keyBlock)
	assert.Equal(t, "PRIVATE KEY", keyBlock.Type)
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	require.NoError(t, err)
	ecKey, ok := key.(*ecdsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, elliptic.P256(), ecKey.Curve)

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "node.example.com", cert.Subject.CommonName)
	assert.Equal(t, []string{"node.example.com"}, cert.DNSNames)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, cert.ExtKeyUsage)
	assert.WithinDuration(t, time.Now(), cert.NotBefore, time.Minute)
	assert.WithinDuration(t, time.Now().AddDate(10, 0, 0), cert.NotAfter, time.Minute)
	_, err = tls.X509KeyPair(certPEM, keyPEM)
	assert.NoError(t, err, "the key belongs to the certificate")

	// Existing files are kept.
	require.NoError(t, ensureCertificate(config))
	again, err := os.ReadFile(config.CertFile)
	require.NoError(t, err)
	assert.Equal(t, certPEM, again)

	// A missing key makes a new pair.
	require.NoError(t, os.Remove(config.KeyFile))
	require.NoError(t, ensureCertificate(config))
	again, err = os.ReadFile(config.CertFile)
	require.NoError(t, err)
	assert.NotEqual(t, certPEM, again)
}

func TestStartWithEnsuresTheCertificateOfATLSNode(t *testing.T) {
	dir := t.TempDir()
	core := newRecordingCore()
	controller := &Controller{nodeID: 1, apiHost: "https://control.test", server: core, Options: &conf.Options{
		Name:       "tls-node",
		CertConfig: &conf.CertConfig{CertMode: "self", CertDomain: "tls.example.com", CertFile: filepath.Join(dir, "c.pem"), KeyFile: filepath.Join(dir, "k.pem")},
	}}
	t.Cleanup(func() { _ = controller.Close() })
	info := vlessNode(443)
	info.Security = panel.Tls
	info.PushInterval = time.Hour
	require.NoError(t, controller.startWith(info, []panel.UserInfo{{Id: 1, Uuid: "user-1"}}, nil))
	assert.FileExists(t, filepath.Join(dir, "c.pem"))
	assert.Nil(t, controller.certJob, "a self-signed certificate is not renewed")

	// A TLS node without a usable certificate does not start.
	broken := &Controller{nodeID: 1, apiHost: "https://control.test", server: newRecordingCore(), Options: &conf.Options{
		Name: "broken", CertConfig: &conf.CertConfig{CertMode: "bogus"},
	}}
	t.Cleanup(func() { _ = broken.Close() })
	assert.ErrorContains(t, broken.startWith(info, nil, nil), "bogus")
	assert.False(t, broken.isStarted())
	assert.False(t, broken.nodeAdded)
}
