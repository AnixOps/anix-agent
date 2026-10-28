package node

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v5/api/agent"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
	"github.com/AnixOps/anix-control/sdk/network"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

// The device network model (network.v1; anix-control
// docs/design/network-model): the Agent lists the components its core runs
// in Hello, applies the device's NetworkPlan from the configuration member
// "network" on the core (vCore.NetworkApplier) and reports the core's
// NetworkStatus on the stream, after each plan and every
// networkStatusInterval. One node of an Agent drives it: the core runs one
// plan.

// networkStatusInterval spaces out the status reports between plans.
var networkStatusInterval = time.Minute

// networkComponent runs one device's plan on the core.
type networkComponent struct {
	device  string
	applier vCore.NetworkApplier
	caps    *networkv1.DeviceCapabilities

	mu         sync.Mutex
	client     *agentapi.Client
	negotiated bool
	// plan is the plan the core runs, nil for none.
	plan *networkv1.NetworkPlan
	// wake asks the loop for a status report now.
	wake    chan struct{}
	stop    chan struct{}
	stopped chan struct{}
	once    sync.Once
}

// newNetworkComponent answers the network component of proxy node nodeID
// on core, nil when the core runs no component of the model.
func newNetworkComponent(nodeID int, core vCore.Core) *networkComponent {
	applier, ok := core.(vCore.NetworkApplier)
	if !ok || len(applier.NetworkKinds()) == 0 {
		return nil
	}
	device := agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: uint32(nodeID)}.String() // #nosec G115 -- node IDs are uint32 on the wire.
	kinds := make([]*networkv1.KindSupport, 0, len(applier.NetworkKinds()))
	for _, kind := range applier.NetworkKinds() {
		kinds = append(kinds, proto.Clone(kind).(*networkv1.KindSupport))
	}
	return &networkComponent{
		device: device, applier: applier,
		caps: &networkv1.DeviceCapabilities{DeviceRef: device, Kinds: kinds},
		wake: make(chan struct{}, 1), stop: make(chan struct{}), stopped: make(chan struct{}),
	}
}

func (c *networkComponent) logger() *log.Entry {
	return log.WithFields(log.Fields{"component": "agent-network", "device": c.device})
}

// HelloCapability implements agentapi.NetworkHandler.
func (c *networkComponent) HelloCapability() (*agentv1pb.Capability, error) {
	return network.HelloCapability(c.caps)
}

// NetworkSession implements agentapi.NetworkHandler: a session that
// negotiated network.v1 gets the current status at once.
func (c *networkComponent) NetworkSession(negotiated bool) {
	c.mu.Lock()
	c.negotiated = negotiated
	c.mu.Unlock()
	if negotiated {
		c.signal()
	}
}

func (c *networkComponent) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// attach binds the component to the node's client and starts its status
// loop.
func (c *networkComponent) attach(client *agentapi.Client) {
	c.mu.Lock()
	c.client = client
	c.mu.Unlock()
	go c.loop()
}

// close stops the status loop.
func (c *networkComponent) close() {
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

func (c *networkComponent) loop() {
	defer close(c.stopped)
	ticker := time.NewTicker(networkStatusInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-c.wake:
		case <-ticker.C:
		}
		c.report(nil)
	}
}

// apply runs the snapshot's member "network": a plan with a new hash
// replaces the core's. Without the member, or with generation 0 (the model
// gives the device nothing), the core keeps what it runs.
func (c *networkComponent) apply(snapshot *agentv1pb.ConfigSnapshot) error {
	if snapshot == nil {
		return nil
	}
	plan, found, err := network.PlanFromNodeConfig(snapshot.GetConfigJson())
	if err != nil {
		return agentapi.InvalidConfig(fmt.Errorf("network plan: %w", err))
	}
	if !found || plan.GetGeneration() == 0 {
		return nil
	}
	if plan.GetDeviceRef() != c.device {
		return agentapi.InvalidConfig(fmt.Errorf("network plan: it is for %q, not %q", plan.GetDeviceRef(), c.device))
	}
	if err := network.Check(plan); err != nil {
		return agentapi.InvalidConfig(fmt.Errorf("network plan: %w", err))
	}
	if unsupported := network.Unsupported(plan, c.caps); len(unsupported) > 0 {
		return fmt.Errorf("network plan: this Agent does not run %s", strings.Join(unsupported, ", "))
	}
	c.mu.Lock()
	current := c.plan
	c.mu.Unlock()
	if current != nil && current.GetHash() == plan.GetHash() && current.GetGeneration() == plan.GetGeneration() {
		return nil
	}
	status, applyErr := c.applier.ApplyNetwork(plan)
	if status == nil && applyErr != nil {
		return fmt.Errorf("network plan generation %d: %w", plan.GetGeneration(), applyErr)
	}
	c.mu.Lock()
	c.plan = plan
	c.mu.Unlock()
	c.logger().WithFields(log.Fields{"generation": plan.GetGeneration(), "paths": len(plan.GetPaths())}).
		Info("Applied the device's network plan")
	c.report(status)
	if applyErr != nil {
		return fmt.Errorf("network plan generation %d: %w", plan.GetGeneration(), applyErr)
	}
	return nil
}

// report sends status, or the core's status read now, for the plan the
// core runs. Nothing is sent before a plan or without a negotiated
// session.
func (c *networkComponent) report(status *networkv1.NetworkStatus) {
	c.mu.Lock()
	plan, client, negotiated := c.plan, c.client, c.negotiated
	c.mu.Unlock()
	if plan == nil || client == nil || !negotiated {
		return
	}
	if status == nil {
		read, err := c.applier.NetworkStatus()
		if err != nil {
			c.logger().WithError(err).Warn("Could not read the core's network status")
			return
		}
		status = read
	}
	status = proto.Clone(status).(*networkv1.NetworkStatus)
	status.DeviceRef, status.Generation, status.PlanHash = c.device, plan.GetGeneration(), plan.GetHash()
	status.ObservedAtUnixMs = time.Now().UnixMilli()
	report, err := network.StatusReport(status)
	if err != nil {
		c.logger().WithError(err).Warn("Could not build the network status")
		return
	}
	if err := client.DataPlane().SendNetworkStatus(report); err != nil && !errors.Is(err, agentapi.ErrSessionGone) {
		c.logger().WithError(err).Warn("Could not send the network status")
	}
}
