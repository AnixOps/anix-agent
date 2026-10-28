package anxline

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Prober probes one path within timeout; nil means the path works.
type Prober interface {
	Probe(ctx context.Context, path Path, timeout time.Duration) error
}

// NetProber sends the probes from the path's own address, so policy
// routing (`ip rule from <addr>`) takes them over that path.
type NetProber struct {
	seq atomic.Uint32
}

// Probe implements Prober.
func (p *NetProber) Probe(ctx context.Context, path Path, timeout time.Duration) error {
	source, err := netip.ParseAddr(path.Addr)
	if err != nil {
		return err
	}
	switch path.Probe.Kind {
	case ProbeTCP:
		return probeTCP(ctx, source, path.Dev, path.Probe.Target, timeout)
	case ProbeICMP:
		return p.probeICMP(source, path.Probe.Target, timeout)
	default:
		return fmt.Errorf("unknown probe kind %q", path.Probe.Kind)
	}
}

// probeTCP connects from source; an RST (connection refused) is an answer
// from the far end, so it counts as success.
func probeTCP(ctx context.Context, source netip.Addr, dev, target string, timeout time.Duration) error {
	local := &net.TCPAddr{IP: source.AsSlice()}
	if source.Is6() {
		local.Zone = dev
	}
	dialer := net.Dialer{Timeout: timeout, LocalAddr: local}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err == nil {
		_ = conn.Close()
		return nil
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return nil
	}
	return err
}

// probeICMP sends one echo request from source and waits for its reply.
// It needs a raw socket (CAP_NET_RAW), which the Agent has.
func (p *NetProber) probeICMP(source netip.Addr, target string, timeout time.Duration) error {
	dst, err := netip.ParseAddr(target)
	if err != nil {
		return err
	}
	network, proto := "ip4:icmp", 1
	var echoType, replyType icmp.Type = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
	if dst.Is6() {
		network, proto = "ip6:ipv6-icmp", 58
		echoType, replyType = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	conn, err := icmp.ListenPacket(network, source.String())
	if err != nil {
		return err
	}
	defer conn.Close()
	id := os.Getpid() & 0xffff
	seq := int(p.seq.Add(1) & 0xffff)
	message := icmp.Message{Type: echoType, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("anx-line")}}
	packet, err := message.Marshal(nil)
	if err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err := conn.WriteTo(packet, &net.IPAddr{IP: dst.AsSlice()}); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		addr, ok := from.(*net.IPAddr)
		if !ok || !addr.IP.Equal(dst.AsSlice()) {
			continue
		}
		reply, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil || reply.Type != replyType {
			continue
		}
		if echo, ok := reply.Body.(*icmp.Echo); ok && echo.ID == id && echo.Seq == seq {
			return nil
		}
	}
}
