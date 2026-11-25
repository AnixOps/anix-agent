package node

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v5/api/agent"
	"github.com/AnixOps/anix-agent/v5/api/panel"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	"github.com/AnixOps/anix-agent/v5/mesh"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	log "github.com/sirupsen/logrus"
)

// The intranet mesh (docs/mesh.md): the member "mesh" of the configuration
// lists the networks the kernel joins. While the node's existing mesh
// program the member names still runs, the networks wait for it to be
// taken over (as root, `anix-agent mesh takeover`); the
// kernel's state goes to Control as the PackageReport "mesh.status" after
// each change and every meshStatusInterval. One node of an Agent drives
// it: the kernel runs one set of networks.

// meshStatusInterval spaces out the status reports.
var meshStatusInterval = time.Minute

// meshComponent runs the mesh member on the kernel.
type meshComponent struct {
	core     vCore.MeshApplier
	takeover *mesh.Takeover

	// runMu serializes run: a snapshot and the retry loop may race.
	runMu      sync.Mutex
	mu         sync.Mutex
	client     *agentapi.Client
	negotiated bool
	// member is the member applied last, nil for none; err why the kernel
	// does not run it.
	member *panel.Mesh
	err    error
	// took is what the takeover found, nil for nothing.
	took *panel.MeshTakeoverResult

	wake    chan struct{}
	stop    chan struct{}
	stopped chan struct{}
	once    sync.Once
}

// newMeshComponent answers the mesh component of core, nil when no kernel
// of it can run the mesh.
func newMeshComponent(core vCore.Core) *meshComponent {
	applier, ok := core.(vCore.MeshApplier)
	if !ok {
		return nil
	}
	return &meshComponent{
		core: applier, takeover: &mesh.Takeover{},
		wake: make(chan struct{}, 1), stop: make(chan struct{}), stopped: make(chan struct{}),
	}
}

func (c *meshComponent) logger() *log.Entry {
	return log.WithField("component", "agent-mesh")
}

// MeshSession implements agentapi.MeshHandler.
func (c *meshComponent) MeshSession(negotiated bool) {
	c.mu.Lock()
	c.negotiated = negotiated
	c.mu.Unlock()
	if negotiated {
		c.signal()
	}
}

func (c *meshComponent) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *meshComponent) attach(client *agentapi.Client) {
	c.mu.Lock()
	c.client = client
	c.mu.Unlock()
	go c.loop()
}

func (c *meshComponent) close() {
	c.once.Do(func() {
		close(c.stop)
		c.mu.Lock()
		started := c.client != nil
		c.mu.Unlock()
		if started {
			<-c.stopped
		}
	})
}

func (c *meshComponent) loop() {
	defer close(c.stopped)
	ticker := time.NewTicker(meshStatusInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-c.wake:
		case <-ticker.C:
			c.retry()
		}
		c.report()
	}
}

// retry applies the member again once what held it back is gone: an
// updated kernel has the mesh, or the existing program was taken over.
func (c *meshComponent) retry() {
	c.mu.Lock()
	member, err := c.member, c.err
	c.mu.Unlock()
	if member != nil && (errors.Is(err, vCore.ErrMeshUnsupported) || errors.Is(err, errTakeoverPending)) {
		_ = c.run(member)
	}
}

// apply runs the snapshot's member "mesh"; a snapshot without it stops the
// networks. A kernel without the mesh fails nothing: the report says so.
func (c *meshComponent) apply(snapshot *agentv1pb.ConfigSnapshot) error {
	if snapshot == nil {
		return nil
	}
	member, err := panel.ParseMesh(snapshot.GetConfigJson())
	if err != nil {
		return agentapi.InvalidConfig(err)
	}
	c.mu.Lock()
	same := reflect.DeepEqual(member, c.member)
	c.mu.Unlock()
	if same {
		return nil
	}
	err = c.run(member)
	c.signal()
	if errors.Is(err, vCore.ErrMeshUnsupported) || errors.Is(err, errTakeoverPending) {
		return nil
	}
	return err
}

// errTakeoverPending holds the networks back while the existing program
// runs: joining its network next to it would put two nodes on one address.
var errTakeoverPending = errors.New("the existing mesh program still runs; take it over with `anix-agent mesh takeover` (as root)")

// run gives the kernel the networks, unless the kernel has no mesh or the
// existing program the member names still runs.
func (c *meshComponent) run(member *panel.Mesh) error {
	c.runMu.Lock()
	defer c.runMu.Unlock()
	var networks []panel.MeshNetwork
	took := &panel.MeshTakeoverResult{}
	if member != nil {
		networks = member.Networks
		if running := c.takeover.Detect(member.Takeover); len(running) > 0 {
			took = &panel.MeshTakeoverResult{Found: true, Error: errTakeoverPending.Error()}
		}
	}
	took.Stopped = c.takeover.Stopped()
	if !took.Found && len(took.Stopped) > 0 {
		took.Found = true
	}
	var err error
	switch {
	case len(networks) > 0 && !c.core.MeshSupported():
		err = vCore.ErrMeshUnsupported
	case len(networks) > 0 && took.Error != "":
		err = errTakeoverPending
	default:
		err = c.core.ApplyMesh(networks)
	}
	if !took.Found {
		took = nil
	}
	c.mu.Lock()
	c.member, c.err, c.took = member, err, took
	c.mu.Unlock()
	if err == nil && len(networks) > 0 {
		c.logger().WithField("networks", len(networks)).Info("Applied the mesh networks")
	}
	return err
}

// status is the report payload now.
func (c *meshComponent) status(ctx context.Context) panel.MeshStatus {
	c.mu.Lock()
	member, applyErr, took := c.member, c.err, c.took
	c.mu.Unlock()
	status := panel.MeshStatus{Networks: []panel.MeshNetworkStatus{}, Takeover: took}
	if member == nil || len(member.Networks) == 0 {
		return status
	}
	var running map[string]panel.MeshNetworkStatus
	if applyErr == nil {
		read, err := c.core.MeshStatus(ctx)
		applyErr = err
		running = make(map[string]panel.MeshNetworkStatus, len(read))
		for _, network := range read {
			running[network.ID] = network
		}
	}
	for _, network := range member.Networks {
		entry, ok := running[network.ID]
		if !ok {
			entry = panel.MeshNetworkStatus{ID: network.ID, Peers: []panel.MeshPeerStatus{}}
			switch {
			case errors.Is(applyErr, vCore.ErrMeshUnsupported):
				entry.Alerts = []panel.MeshAlert{{Code: panel.MeshAlertUnsupported, Detail: applyErr.Error()}}
			case errors.Is(applyErr, errTakeoverPending):
				entry.Alerts = []panel.MeshAlert{{Code: panel.MeshAlertTakeoverPending, Detail: applyErr.Error()}}
			case applyErr != nil:
				entry.Error = applyErr.Error()
			default:
				entry.Error = "the kernel does not run this network"
			}
		}
		if entry.Peers == nil {
			entry.Peers = []panel.MeshPeerStatus{}
		}
		status.Networks = append(status.Networks, entry)
	}
	return status
}

// report sends the status on a session that negotiated the mesh.
func (c *meshComponent) report() {
	c.mu.Lock()
	client, negotiated := c.client, c.negotiated
	c.mu.Unlock()
	if client == nil || !negotiated {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	payload, err := json.Marshal(c.status(ctx))
	cancel()
	if err != nil {
		c.logger().WithError(err).Warn("Could not build the mesh status")
		return
	}
	report := &agentv1pb.PackageReport{
		PluginId: agentapi.MeshPluginID, Kind: agentapi.MeshStatusKind, Version: agentapi.MeshStatusVersion,
		PayloadJson: payload, ObservedAtUnixMs: time.Now().UnixMilli(),
	}
	if err := client.DataPlane().SendMeshStatus(report); err != nil && !errors.Is(err, agentapi.ErrSessionGone) {
		c.logger().WithError(err).Warn("Could not send the mesh status")
	}
}
