//go:build linux

package node

import (
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
)

// hostInterfaces reads the links, their addresses and the default routes
// over netlink.
func hostInterfaces() ([]observedInterface, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	byIndex := map[int]*observedInterface{}
	out := make([]observedInterface, 0, len(links))
	for _, link := range links {
		attrs := link.Attrs()
		iface := observedInterface{name: attrs.Name, up: attrs.Flags&net.FlagUp != 0}
		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if addr.IPNet == nil {
				continue
			}
			ip, ok := netip.AddrFromSlice(addr.IP)
			if !ok {
				continue
			}
			ones, _ := addr.Mask.Size()
			iface.addresses = append(iface.addresses, netip.PrefixFrom(ip.Unmap(), ones))
		}
		out = append(out, iface)
	}
	for i, link := range links {
		byIndex[link.Attrs().Index] = &out[i]
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteList(nil, family)
		if err != nil {
			return nil, err
		}
		for _, route := range routes {
			if !defaultRoute(route) {
				continue
			}
			iface := byIndex[route.LinkIndex]
			gw, ok := netip.AddrFromSlice(route.Gw)
			if iface == nil || !ok {
				continue
			}
			gw = gw.Unmap()
			if gw.Is4() && !iface.gatewayV4.IsValid() {
				iface.gatewayV4 = gw
			} else if gw.Is6() && !iface.gatewayV6.IsValid() {
				iface.gatewayV6 = gw
			}
		}
	}
	return out, nil
}

func defaultRoute(route netlink.Route) bool {
	if route.Dst == nil {
		return true
	}
	ones, _ := route.Dst.Mask.Size()
	return ones == 0
}
