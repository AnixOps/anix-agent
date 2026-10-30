package node

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The report keeps the up line interfaces with a global address, with
// their default gateways, and leaves out loopback, container and tunnel
// interfaces and link-local addresses.
func TestInterfaceFactsKeepLineInterfaces(t *testing.T) {
	facts := factsOf([]observedInterface{
		{name: "lo", up: true, addresses: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}},
		{name: "eth1", up: true, addresses: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.5/24"), netip.MustParsePrefix("fe80::1/64")}},
		{name: "eth0", up: true, addresses: []netip.Prefix{
			netip.MustParsePrefix("203.0.113.7/24"), netip.MustParsePrefix("2001:db8::7/64"), netip.MustParsePrefix("fe80::7/64")},
			gatewayV4: netip.MustParseAddr("203.0.113.1"), gatewayV6: netip.MustParseAddr("fe80::1%eth0")},
		{name: "docker0", up: true, addresses: []netip.Prefix{netip.MustParsePrefix("172.17.0.1/16")}},
		{name: "eth2", up: false, addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.9/24")}},
		{name: "eth3", up: true, addresses: []netip.Prefix{netip.MustParsePrefix("fe80::3/64")}},
	})
	require.Len(t, facts, 2)
	assert.Equal(t, "eth0", facts[0].GetName())
	assert.Equal(t, []string{"2001:db8::7/64", "203.0.113.7/24"}, facts[0].GetAddresses())
	assert.Equal(t, "203.0.113.1", facts[0].GetGatewayV4())
	assert.Equal(t, "fe80::1", facts[0].GetGatewayV6())
	assert.Equal(t, "eth1", facts[1].GetName())
	assert.Equal(t, []string{"10.0.0.5/24"}, facts[1].GetAddresses())
	assert.Empty(t, facts[1].GetGatewayV4())
}
