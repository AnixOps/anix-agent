//go:build !linux

package forward

import "github.com/AnixOps/anix-control/sdk/forward/leastconn"

// newConntrackSource answers nil off Linux: there is no conntrack, and a
// LEAST_CONN hop stays weighted random by its rendered weights.
func newConntrackSource(uint32) leastconn.Source { return nil }
