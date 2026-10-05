package forward

import (
	"context"
	"sync"

	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"github.com/AnixOps/anix-control/sdk/forward/driver"
	"github.com/AnixOps/anix-control/sdk/forward/driver/anixops"
)

// anixopsDriver is the anixops driver behind a switch, as gostDriver is:
// built with the node's link certificate (the TLS_TCP and QUIC carriers) or
// without (PLAIN only). Render is a function of the driver's configuration,
// so when the node gains or loses its link certificate (H28) the component
// rebuilds the driver and applies the state again. Every driver instance reads
// the host back (the relay's state file and control socket), so a rebuild
// loses nothing.
type anixopsDriver struct {
	mu      sync.RWMutex
	current *anixops.Driver
	build   func(links bool) (*anixops.Driver, error)
}

var _ driver.Driver = (*anixopsDriver)(nil)

func newAnixOpsDriver(links bool, build func(bool) (*anixops.Driver, error)) (*anixopsDriver, error) {
	d, err := build(links)
	if err != nil {
		return nil, err
	}
	return &anixopsDriver{current: d, build: build}, nil
}

// setLinks rebuilds the driver with or without the link certificate.
func (a *anixopsDriver) setLinks(links bool) error {
	d, err := a.build(links)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.current = d
	a.mu.Unlock()
	return nil
}

func (a *anixopsDriver) get() *anixops.Driver {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.current
}

func (a *anixopsDriver) Engine() forwardv1.Engine { return forwardv1.Engine_ENGINE_ANIXOPS }

func (a *anixopsDriver) Capabilities(ctx context.Context) (*forwardv1.EngineCapabilities, error) {
	return a.get().Capabilities(ctx)
}

func (a *anixopsDriver) Render(state *forwardv1.NodeForwardState) (driver.Artifact, error) {
	return a.get().Render(state)
}

func (a *anixopsDriver) Apply(ctx context.Context, art driver.Artifact) (driver.ApplyResult, error) {
	return a.get().Apply(ctx, art)
}

func (a *anixopsDriver) Observe(ctx context.Context) (driver.Observation, error) {
	return a.get().Observe(ctx)
}

func (a *anixopsDriver) SetUpstreams(ctx context.Context, routeID string, hopIndex uint32, active []driver.Upstream) error {
	return a.get().SetUpstreams(ctx, routeID, hopIndex, active)
}

func (a *anixopsDriver) Remove(ctx context.Context) error { return a.get().Remove(ctx) }

// ReloadCredentials makes a running relay read the link files again.
func (a *anixopsDriver) ReloadCredentials(ctx context.Context) error {
	return a.get().ReloadCredentials(ctx)
}
