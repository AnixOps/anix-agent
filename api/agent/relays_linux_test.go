package agent

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"
)

// A relay connection carries TCP_USER_TIMEOUT equal to the control stream's
// keepalive timeout, as gRPC would set on a direct *net.TCPConn: a relay
// whose path dies with data unacknowledged is given up after that long, not
// after the kernel's retransmission default of about 15 minutes.
func TestRelayConnectionsCarryTheUserTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte{1})
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()

	relays, err := NewRelays([]string{listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := relays.Dial(ctx, "panel.example.com:50051")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	relayed, ok := conn.(*relayConn)
	if !ok {
		t.Fatalf("Dial answered %T, want *relayConn", conn)
	}
	tcp, ok := relayed.Conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("the relay connection is %T, want *net.TCPConn", relayed.Conn)
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got int
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		got, sockErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeout)
	}); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil {
		t.Fatal(sockErr)
	}
	if want := int(controlKeepaliveTimeout / time.Millisecond); got != want {
		t.Fatalf("TCP_USER_TIMEOUT = %d ms, want %d ms", got, want)
	}
}
