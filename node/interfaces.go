package node

import (
	"net/netip"
	"sort"
	"strings"

	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
)

// The interfaces the network status reports (InterfaceFact), so Control
// offers them on the node page: the up interfaces with a global unicast
// address, each with its addresses (as prefixes) and default gateways.
// Container and tunnel interfaces are left out.

// maxInterfaceFacts bounds the report.
const maxInterfaceFacts = 32

// skippedInterfacePrefixes name interfaces that are not a machine's lines.
var skippedInterfacePrefixes = []string{"lo", "docker", "veth", "br-", "virbr", "cni", "flannel", "cali", "kube", "tun", "tap", "anx", "wg", "tailscale", "zt"}

// observedInterface is one interface as the host lists it.
type observedInterface struct {
	name      string
	up        bool
	addresses []netip.Prefix
	gatewayV4 netip.Addr
	gatewayV6 netip.Addr
}

// listInterfaces lists the host's interfaces; replaced in tests.
var listInterfaces = hostInterfaces

// interfaceFacts answers the facts of the host's line interfaces, nil when
// they cannot be read.
func interfaceFacts() []*networkv1.InterfaceFact {
	observed, err := listInterfaces()
	if err != nil {
		return nil
	}
	return factsOf(observed)
}

func factsOf(observed []observedInterface) []*networkv1.InterfaceFact {
	var facts []*networkv1.InterfaceFact
	for _, iface := range observed {
		if !iface.up || skippedInterface(iface.name) {
			continue
		}
		fact := &networkv1.InterfaceFact{Name: iface.name}
		for _, prefix := range iface.addresses {
			if addr := prefix.Addr(); addr.IsGlobalUnicast() && !addr.IsLinkLocalUnicast() {
				fact.Addresses = append(fact.Addresses, prefix.String())
			}
		}
		if len(fact.Addresses) == 0 {
			continue
		}
		sort.Strings(fact.Addresses)
		if iface.gatewayV4.IsValid() {
			fact.GatewayV4 = iface.gatewayV4.String()
		}
		if iface.gatewayV6.IsValid() {
			fact.GatewayV6 = iface.gatewayV6.WithZone("").String()
		}
		facts = append(facts, fact)
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].GetName() < facts[j].GetName() })
	if len(facts) > maxInterfaceFacts {
		facts = facts[:maxInterfaceFacts]
	}
	return facts
}

func skippedInterface(name string) bool {
	for _, prefix := range skippedInterfacePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
