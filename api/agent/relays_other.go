//go:build !linux

package agent

import (
	"net"
	"time"
)

// setRelayUserTimeout is a no-op outside Linux, as gRPC's own.
func setRelayUserTimeout(net.Conn, time.Duration) {}
