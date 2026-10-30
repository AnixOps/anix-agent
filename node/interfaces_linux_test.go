//go:build linux

package node

import "testing"

// Reading the links, addresses and routes needs no privilege.
func TestHostInterfacesReadsTheHost(t *testing.T) {
	observed, err := hostInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(observed) == 0 {
		t.Fatal("no interfaces")
	}
	for _, fact := range factsOf(observed) {
		t.Logf("%s %v gw4=%q gw6=%q", fact.GetName(), fact.GetAddresses(), fact.GetGatewayV4(), fact.GetGatewayV6())
	}
}
