// Command anixops-relay is the relay process of the experimental anixops
// forwarding engine (anix-control docs/architecture/anixops-protocol.md): the
// hop runtime that anixops-relay.service runs and the Agent's anixops driver
// controls over a unix socket. It holds no Agent code or keys, and the unit
// gives it nothing but CAP_NET_BIND_SERVICE (H22, decision P1). The program
// itself is sdk/forward/driver/anixops/relayd.Main.
package main

import (
	"os"

	"github.com/AnixOps/anix-control/sdk/forward/driver/anixops/relayd"
)

func main() {
	os.Exit(relayd.Main(os.Args[1:], os.Stdout, os.Stderr))
}
