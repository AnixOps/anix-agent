package node

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/AnixOps/anix-agent/v5/conf"
)

// ensureCertificate makes sure a TLS node has its certificate files, as
// CertMode says: given (file), self-signed (self) or from the ACME CA
// (http, dns).
func (c *Controller) ensureCertificate() error {
	return ensureCertificate(c.CertConfig)
}

func ensureCertificate(config *conf.CertConfig) error {
	if config == nil {
		return nil
	}
	switch config.CertMode {
	case "", "none":
		return nil
	case "file", "self", "http", "dns":
	default:
		return fmt.Errorf("unsupported certificate mode %q", config.CertMode)
	}
	if config.CertFile == "" || config.KeyFile == "" {
		return fmt.Errorf("certificate mode %s needs CertFile and KeyFile", config.CertMode)
	}
	if config.CertMode == "file" || (fileExists(config.CertFile) && fileExists(config.KeyFile)) {
		return nil
	}
	if config.CertMode == "self" {
		return writeSelfSignedCertificate(config.CertDomain, config.CertFile, config.KeyFile)
	}
	return obtainCertificate(config)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// writeSelfSignedCertificate writes a self-signed certificate for domain,
// valid for 10 years, and its key.
func writeSelfSignedCertificate(domain, certFile, keyFile string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    now,
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create the self-signed certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writeCertificate(certFile, keyFile,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

// writeCertificate writes a certificate (0644) and its key (0600),
// creating their directories.
func writeCertificate(certFile, keyFile string, certPEM, keyPEM []byte) error {
	if err := writeFile(certFile, certPEM, 0o644); err != nil {
		return err
	}
	return writeFile(keyFile, keyPEM, 0o600)
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, mode)
}
