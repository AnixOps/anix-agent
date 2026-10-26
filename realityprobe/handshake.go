package realityprobe

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/xtls/reality"
	xnet "github.com/xtls/xray-core/common/net"
	xreality "github.com/xtls/xray-core/transport/internet/reality"
)

// RealityTimeout is the time a probe adds for its REALITY handshake, on top
// of timeout_ms: the REALITY server first learns the target's
// post-handshake records, which takes up to five seconds.
const RealityTimeout = 12 * time.Second

// realityFingerprint is the uTLS fingerprint of the loopback client: the
// one subscriptions hand out for REALITY (fp=chrome).
const realityFingerprint = "chrome"

// realityPing is what the loopback client sends once the handshake is
// authenticated; the server must read it back.
var realityPing = []byte("anix-reality-probe")

// reality runs a REALITY handshake through the target, on the node: a
// throwaway REALITY server on 127.0.0.1 with a fresh key pair and address
// as its dest, and a REALITY client that dials it with host as SNI. A
// target can answer TLS 1.3, h2 and X25519 to a plain client and still
// break REALITY, which relays the target's own handshake; only this tells.
//
// The REALITY code is the REALITY library's (github.com/xtls/reality for the
// server, Xray's client), linked in, not a running core.
func (p *Prober) reality(ctx context.Context, result *Result, host, address string) {
	started := time.Now()
	if err := realityHandshake(ctx, host, address); err != nil {
		result.fail(FailReality, err)
		return
	}
	result.RealityMS = time.Since(started).Milliseconds()
}

// realityHandshake answers nil when a REALITY client authenticates through a
// server whose dest is address and sends data the server reads.
func realityHandshake(ctx context.Context, host, address string) error {
	ctx, cancel := context.WithTimeout(ctx, RealityTimeout)
	defer cancel()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	shortID := make([]byte, 8)
	if _, err := rand.Read(shortID); err != nil {
		return err
	}

	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()

	server := (&xreality.Config{
		Type:        "tcp",
		Dest:        address,
		ServerNames: []string{host},
		PrivateKey:  key.Bytes(),
		ShortIds:    [][]byte{shortID},
	}).GetREALITYConfig()
	// As Xray's listener does: the server waits for these before it finishes
	// an authenticated handshake.
	reality.DetectPostHandshakeRecordsLens(server)
	served := make(chan error, 1)
	go func() {
		served <- serveOnce(ctx, listener, server)
	}()

	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		return err
	}
	defer raw.Close()
	stopRaw := context.AfterFunc(ctx, func() { raw.Close() })
	defer stopRaw()
	_, port, _ := net.SplitHostPort(address)
	portNumber, _ := strconv.ParseUint(port, 10, 16)
	client := &xreality.Config{
		Fingerprint: realityFingerprint,
		ServerName:  host,
		PublicKey:   key.PublicKey().Bytes(),
		ShortId:     shortID,
		// No spider: an unauthenticated handshake fails at once.
		SpiderY: make([]int64, 10),
	}
	conn, err := xreality.UClient(raw, client, ctx, xnet.TCPDestination(xnet.DomainAddress(host), xnet.Port(portNumber)))
	if err != nil {
		// The server's error, when it has one, says more.
		select {
		case serverErr := <-served:
			if serverErr != nil {
				return serverErr
			}
		case <-time.After(100 * time.Millisecond):
		}
		return err
	}
	defer conn.Close()
	if _, err := conn.Write(realityPing); err != nil {
		return fmt.Errorf("REALITY: write after the handshake: %w", err)
	}
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// serveOnce accepts one connection, completes the REALITY server handshake
// and reads realityPing.
func serveOnce(ctx context.Context, listener net.Listener, config *reality.Config) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	server, err := xreality.Server(conn, config)
	if err != nil {
		return err
	}
	defer server.Close()
	got := make([]byte, len(realityPing))
	if _, err := io.ReadFull(server, got); err != nil {
		return fmt.Errorf("REALITY: read after the handshake: %w", err)
	}
	if string(got) != string(realityPing) {
		return errors.New("REALITY: the server read other data than was sent")
	}
	return nil
}
