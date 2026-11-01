package agenttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/agent/pki"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	"google.golang.org/grpc"
	grpccredentials "google.golang.org/grpc/credentials"
)

// Provision stores an identity Control issued for its node in a new
// directory and returns it: the AgentIdentity.CertDir of an Agent that
// enrolled before the test.
func (c *Control) Provision(t testing.TB) string {
	t.Helper()
	dir := t.TempDir()
	node := c.node()
	key, err := pki.GenerateKey()
	must(t, err)
	csr, err := pki.NewCSR(key, node)
	must(t, err)
	issued, err := c.issueFor(csr, node)
	must(t, err)
	identity, err := pki.FromIssued(key, issued, pki.Expectation{Node: node, Now: time.Now()})
	must(t, err)
	identity.EnrolledAt, identity.Bootstrap = time.Now().UTC(), pki.BootstrapEnrollmentCredential
	store, err := pki.NewStore(dir, node)
	must(t, err)
	must(t, store.Save(identity))
	return dir
}

// Listener is a TLS gRPC listener on 127.0.0.1 that asks for the agent
// client certificate, for tests that bring their own AgentControlService.
// Register the services on Server, then call Serve.
type Listener struct {
	Server *grpc.Server
	// Address is the listener's host:port.
	Address string
	// ServerName is the name in the server certificate.
	ServerName string
	// ServerCAs verifies the server certificate (Agent RootCAs).
	ServerCAs *x509.CertPool

	control  *Control
	listener net.Listener
}

// NewListener starts a listener; Provision issues the node's identity.
func NewListener(t testing.TB, nodeID uint32) *Listener {
	t.Helper()
	control := &Control{t: t, NodeID: nodeID, Cluster: "test-cluster", ServerName: "control.test"}
	serverCAKey, serverCACert := newCA(t, "control server CA")
	roots := x509.NewCertPool()
	roots.AddCert(serverCACert)
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: control.ServerName}, DNSNames: []string{control.ServerName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, serverCACert, &serverKey.PublicKey, serverCAKey)
	must(t, err)
	control.agentCAKey, control.agentCACert = newCA(t, "agent CA")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	server := grpc.NewServer(grpc.Creds(grpccredentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: serverKey}},
		ClientAuth:   tls.RequestClientCert, MinVersion: tls.VersionTLS12,
	})))
	t.Cleanup(server.Stop)
	return &Listener{Server: server, Address: listener.Addr().String(), ServerName: control.ServerName, ServerCAs: roots, control: control, listener: listener}
}

// Serve serves the registered services until the test ends.
func (l *Listener) Serve() {
	go func() { _ = l.Server.Serve(l.listener) }()
}

// Provision is Control.Provision for the listener's node.
func (l *Listener) Provision(t testing.TB) string {
	return l.control.Provision(t)
}

// Node is the listener's node.
func (l *Listener) Node() agentcontrol.AgentNode {
	return l.control.node()
}
