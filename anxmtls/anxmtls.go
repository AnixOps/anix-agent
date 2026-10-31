// Package anxmtls secures the gRPC management APIs of anx-server and
// anx-node with mutual TLS (anx spec §7 "管理面传输安全", F-24).
//
// The Agent holds the client certificate. For a process it starts itself,
// Generate makes a one-off CA, a server certificate for the loopback
// address the process listens on and a client certificate, writes the
// server's half into the process's directory and answers the client's
// credentials; the CA key never touches the disk. For an anx-node that
// runs on its own, Load reads the client certificate the operator issued.
package anxmtls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc/credentials"
)

// Files are the server's half of a Generate'd bundle, in the PEM files
// anx-server's --mgmt-tls-cert / --mgmt-tls-key / --mgmt-client-ca and
// anx-node's mgmt_tls {cert_file, key_file, client_ca_file} name.
type Files struct {
	Cert, Key, ClientCA string
}

// File names Generate writes.
const (
	CertFile     = "mgmt.crt"
	KeyFile      = "mgmt.key"
	ClientCAFile = "mgmt-client-ca.crt"
)

// validity of a Generate'd bundle; a process gets a new one each start.
const validity = 10 * 365 * 24 * time.Hour

// Markers in binaries that serve mTLS management APIs: anx-server's flag
// and anx-node's config field.
var (
	ServerMarker = []byte("--mgmt-tls-cert")
	NodeMarker   = []byte("mgmt_insecure_public")
)

// Supports reports whether binary is a release that knows marker (older
// anx-server / anx-node releases reject the mTLS settings and would not
// start). Unreadable binaries answer false.
func Supports(binary string, marker []byte) bool {
	data, err := os.ReadFile(binary)
	if err != nil {
		return false
	}
	return bytes.Contains(data, marker)
}

// Generate writes a new bundle into dir (created 0700, files 0600) for a
// server reached at host (an IP literal or a name) and answers the files
// and the client's credentials.
func Generate(dir, host string) (Files, credentials.TransportCredentials, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Files{}, nil, err
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "anix-agent management CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return Files{}, nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return Files{}, nil, err
	}
	leaf := func(name string, usage x509.ExtKeyUsage, server bool) ([]byte, *ecdsa.PrivateKey, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		template := &x509.Certificate{
			SerialNumber:          serial(),
			Subject:               pkix.Name{CommonName: name},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(validity),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{usage},
			BasicConstraintsValid: true,
		}
		if server {
			if ip := net.ParseIP(host); ip != nil {
				template.IPAddresses = []net.IP{ip}
			} else {
				template.DNSNames = []string{host}
			}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		return der, key, err
	}
	serverDER, serverKey, err := leaf("anx management", x509.ExtKeyUsageServerAuth, true)
	if err != nil {
		return Files{}, nil, err
	}
	clientDER, clientKey, err := leaf("anix-agent", x509.ExtKeyUsageClientAuth, false)
	if err != nil {
		return Files{}, nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Files{}, nil, err
	}
	files := Files{
		Cert:     filepath.Join(dir, CertFile),
		Key:      filepath.Join(dir, KeyFile),
		ClientCA: filepath.Join(dir, ClientCAFile),
	}
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return Files{}, nil, err
	}
	for path, block := range map[string]*pem.Block{
		files.Cert:     {Type: "CERTIFICATE", Bytes: serverDER},
		files.Key:      {Type: "PRIVATE KEY", Bytes: serverKeyDER},
		files.ClientCA: {Type: "CERTIFICATE", Bytes: caDER},
	} {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			return Files{}, nil, fmt.Errorf("management mTLS %s: %w", path, err)
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	client := tls.Certificate{Certificate: [][]byte{clientDER}, PrivateKey: clientKey}
	return files, credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{client},
		RootCAs:      roots,
		ServerName:   host,
		MinVersion:   tls.VersionTLS13,
	}), nil
}

// Load answers the credentials of a client certificate (certFile,
// keyFile) for a server whose certificate chains to caFile; serverName
// overrides the name checked against it ("" checks the dialed host).
func Load(certFile, keyFile, caFile, serverName string) (credentials.TransportCredentials, error) {
	if certFile == "" || keyFile == "" || caFile == "" {
		return nil, errors.New("management mTLS needs CertFile, KeyFile and CAFile")
	}
	client, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("management mTLS client certificate: %w", err)
	}
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("management mTLS CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("management mTLS CA %s has no certificate", caFile)
	}
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{client},
		RootCAs:      roots,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}), nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return n.Add(n, big.NewInt(1))
}
