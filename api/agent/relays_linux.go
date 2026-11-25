package agent

import (
	"net"
	"syscall"
	"time"
)

// tcpUserTimeout is TCP_USER_TIMEOUT of linux/tcp.h (the syscall package
// does not define it on every architecture).
const tcpUserTimeout = 0x12

// setRelayUserTimeout sets TCP_USER_TIMEOUT on a relay connection. gRPC
// sets it from the keepalive timeout only on a *net.TCPConn, which the
// relay's wrapped connection is not, so the relay dialer sets it instead.
func setRelayUserTimeout(conn net.Conn, timeout time.Duration) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeout, int(timeout/time.Millisecond))
	})
}
