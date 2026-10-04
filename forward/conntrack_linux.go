//go:build linux

package forward

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/AnixOps/anix-control/sdk/forward/leastconn"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ConntrackSource is the live-connection source of the nftables driver for
// LEAST_CONN re-weighting (forward-sdk.md 7.1, L1): the driver forwards
// with DNAT, so its connections are conntrack entries, not sockets. It
// lists the conntrack table over netlink (CAP_NET_ADMIN, which the Agent
// has for nftables; vishvananda/netlink, Apache-2.0), keeps the entries
// whose connection mark carries one of the driver's hop marks (MarkMask),
// and counts each under its upstream: the reply direction's source, which
// is the original direction's destination after DNAT. TCP entries count
// from SYN to ESTABLISHED (closing and TIME_WAIT entries are not live);
// every UDP entry counts until conntrack expires it.
type ConntrackSource struct {
	// MarkMask is the nftables driver's mark mask.
	MarkMask uint32
	// Handle lists another network namespace's table (tests); nil is the
	// Agent's own.
	Handle *netlink.Handle
}

func newConntrackSource(mask uint32) leastconn.Source {
	return &ConntrackSource{MarkMask: mask}
}

// TCP conntrack states that count as live (include/uapi/linux/netfilter/
// nf_conntrack_tcp.h): SYN_SENT 1, SYN_RECV 2, ESTABLISHED 3.
const (
	tcpSynSent     = 1
	tcpEstablished = 3
)

// ActiveConns implements leastconn.Source.
func (s *ConntrackSource) ActiveConns(ctx context.Context) (map[netip.AddrPort]uint64, error) {
	out := map[netip.AddrPort]uint64{}
	for _, family := range []netlink.InetFamily{unix.AF_INET, unix.AF_INET6} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var flows []*netlink.ConntrackFlow
		var err error
		if s.Handle != nil {
			flows, err = s.Handle.ConntrackTableList(netlink.ConntrackTable, family)
		} else {
			flows, err = netlink.ConntrackTableList(netlink.ConntrackTable, family)
		}
		if err != nil {
			return nil, fmt.Errorf("list conntrack: %w", err)
		}
		for _, f := range flows {
			if f.Mark&s.MarkMask == 0 {
				continue
			}
			switch f.Forward.Protocol {
			case unix.IPPROTO_TCP:
				tcp, ok := f.ProtoInfo.(*netlink.ProtoInfoTCP)
				if !ok || tcp.State < tcpSynSent || tcp.State > tcpEstablished {
					continue
				}
			case unix.IPPROTO_UDP:
			default:
				continue
			}
			addr, ok := netip.AddrFromSlice(f.Reverse.SrcIP)
			if !ok {
				continue
			}
			out[netip.AddrPortFrom(addr.Unmap(), f.Reverse.SrcPort)]++
		}
	}
	return out, nil
}
