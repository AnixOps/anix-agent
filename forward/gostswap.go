package forward

import (
	"context"
	"net/netip"
	"sync"

	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"github.com/AnixOps/anix-control/sdk/forward/driver"
	"github.com/AnixOps/anix-control/sdk/forward/driver/gost"
)

// gostDriver is the gost driver behind a switch: built with the link
// certificate's paths (TLS, WSS, QUIC and gRPC links) or without (RAW
// only). gost's Render is a function of its configuration, so when the node
// gains or loses its link certificate (H28) the component rebuilds the
// driver and applies the state again. Every driver instance reads the host
// back (gost's state file, its web API), so a rebuild loses nothing.
type gostDriver struct {
	mu      sync.RWMutex
	current *gost.Driver
	build   func(links bool) (*gost.Driver, error)
}

var (
	_ driver.Driver        = (*gostDriver)(nil)
	_ driver.QuotaEnforcer = (*gostDriver)(nil)
)

func newGostDriver(links bool, build func(bool) (*gost.Driver, error)) (*gostDriver, error) {
	d, err := build(links)
	if err != nil {
		return nil, err
	}
	return &gostDriver{current: d, build: build}, nil
}

// setLinks rebuilds the driver with or without the link certificate.
func (g *gostDriver) setLinks(links bool) error {
	d, err := g.build(links)
	if err != nil {
		return err
	}
	g.mu.Lock()
	g.current = d
	g.mu.Unlock()
	return nil
}

func (g *gostDriver) get() *gost.Driver {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.current
}

func (g *gostDriver) Engine() forwardv1.Engine { return forwardv1.Engine_ENGINE_GOST }

func (g *gostDriver) Capabilities(ctx context.Context) (*forwardv1.EngineCapabilities, error) {
	return g.get().Capabilities(ctx)
}

func (g *gostDriver) Render(state *forwardv1.NodeForwardState) (driver.Artifact, error) {
	return g.get().Render(state)
}

func (g *gostDriver) Apply(ctx context.Context, a driver.Artifact) (driver.ApplyResult, error) {
	return g.get().Apply(ctx, a)
}

func (g *gostDriver) Observe(ctx context.Context) (driver.Observation, error) {
	return g.get().Observe(ctx)
}

func (g *gostDriver) SetUpstreams(ctx context.Context, routeID string, hopIndex uint32, active []driver.Upstream) error {
	return g.get().SetUpstreams(ctx, routeID, hopIndex, active)
}

func (g *gostDriver) Remove(ctx context.Context) error { return g.get().Remove(ctx) }

func (g *gostDriver) EnforceQuotas(ctx context.Context) ([]driver.HopKey, error) {
	return g.get().EnforceQuotas(ctx)
}

// ActiveConns implements leastconn.Source.
func (g *gostDriver) ActiveConns(ctx context.Context) (map[netip.AddrPort]uint64, error) {
	return g.get().ActiveConns(ctx)
}
