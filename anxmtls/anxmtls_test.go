package anxmtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	anxmgmtpb "github.com/AnixOps/anix-agent/v5/api/anxmgmt/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// serve runs a gRPC server with no services on the bundle's server half,
// requiring a client certificate that chains to its client CA, as
// anx-server / anx-node do.
func serve(t *testing.T, files Files) string {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(files.Cert, files.Key)
	require.NoError(t, err)
	data, err := os.ReadFile(files.ClientCA)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(data))
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	})))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	return listener.Addr().String()
}

func call(t *testing.T, addr string, creds credentials.TransportCredentials) error {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	require.NoError(t, err)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = anxmgmtpb.NewManagementClient(conn).Stats(ctx, &anxmgmtpb.StatsRequest{})
	return err
}

func TestGenerateMakesAWorkingBundle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mgmt")
	files, creds, err := Generate(dir, "127.0.0.1")
	require.NoError(t, err)
	for _, path := range []string{files.Cert, files.Key, files.ClientCA} {
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), path)
	}
	addr := serve(t, files)

	// Through TLS to the server, which has no services.
	err = call(t, addr, creds)
	assert.Equal(t, codes.Unimplemented, status.Code(err), "%v", err)

	// Plaintext and another bundle's client certificate do not get there.
	assert.Equal(t, codes.Unavailable, status.Code(call(t, addr, insecure.NewCredentials())))
	_, other, err := Generate(filepath.Join(t.TempDir(), "other"), "127.0.0.1")
	require.NoError(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(call(t, addr, other)))
}

func TestLoad(t *testing.T) {
	// The operator's files: a bundle whose client half is on disk too.
	dir := t.TempDir()
	files, _, err := Generate(filepath.Join(dir, "server"), "127.0.0.1")
	require.NoError(t, err)
	addr := serve(t, files)

	_, err = Load("", "key", "ca", "")
	require.Error(t, err)
	_, err = Load(filepath.Join(dir, "missing.crt"), filepath.Join(dir, "missing.key"), files.ClientCA, "")
	require.Error(t, err)
	_, err = Load(files.Cert, files.Key, files.Key, "")
	require.Error(t, err, "a key file holds no CA certificate")

	// The server's own pair as a client certificate: it chains to the
	// client CA but is not for client auth, so the server refuses it.
	creds, err := Load(files.Cert, files.Key, files.ClientCA, "")
	require.NoError(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(call(t, addr, creds)))
}

func TestSupports(t *testing.T) {
	dir := t.TempDir()
	newer := filepath.Join(dir, "anx-server")
	require.NoError(t, os.WriteFile(newer, []byte("\x7fELF...unknown flag --mgmt-tls-cert..."), 0o755))
	older := filepath.Join(dir, "anx-server-old")
	require.NoError(t, os.WriteFile(older, []byte("\x7fELF...--mgmt..."), 0o755))
	assert.True(t, Supports(newer, ServerMarker))
	assert.False(t, Supports(older, ServerMarker))
	assert.False(t, Supports(filepath.Join(dir, "missing"), ServerMarker))
}
