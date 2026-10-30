package node

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/AnixOps/anix-agent/v5/anxline"
	"github.com/AnixOps/anix-agent/v5/anxserver"
	agentapi "github.com/AnixOps/anix-agent/v5/api/agent"
	"github.com/AnixOps/anix-agent/v5/conf"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	"github.com/AnixOps/anix-agent/v5/networkroute"
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

// networkRouting answers the policy-routing manager of the host, nil when
// it has none (not Linux, or no ip command): the Agent then runs no egress
// that needs routing.
var networkRouting = func() *networkroute.Manager {
	if runtime.GOOS != "linux" {
		return nil
	}
	path, err := exec.LookPath("ip")
	if err != nil {
		return nil
	}
	return &networkroute.Manager{IP: path, Run: networkroute.Run}
}

// networkServers answers the manager of the accepting anx_line ends: the
// anx-server Agent upgrades install, else one on PATH; nil when the host
// has none (or is not Linux): the Agent then accepts no anx_line transport.
var networkServers = func() *anxserver.Manager {
	if runtime.GOOS != "linux" {
		return nil
	}
	path := conf.InstalledAnxServerPath
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		if path, err = exec.LookPath("anx-server"); err != nil {
			return nil
		}
	}
	return &anxserver.Manager{
		Binary: path, Dir: filepath.Join(conf.DefaultStateRoot, "anx-server"),
		RST: func(links []anxline.Link) error {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return anxline.ApplyRST(ctx, anxline.ExecRunner{}, "", anxserver.RSTTable, links)
		},
		Buffers: func() error { return anxserver.RaiseSocketBuffers("/proc/sys") },
	}
}

// routedEgressKinds are the egress kinds the Agent runs itself when it can
// route: the core binds the source, the Agent's policy routing sends it out
// of its line.
var routedEgressKinds = []string{network.EgressDedicatedIP}

// networkComponent runs one device's plan on the core.
type networkComponent struct {
	device  string
	applier vCore.NetworkApplier
	caps    *networkv1.DeviceCapabilities
	// routes installs the egresses' policy routing, nil without it.
	routes *networkroute.Manager
	// servers runs the accepting anx_line ends, nil without anx-server.
	servers *anxserver.Manager

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
	caps := &networkv1.DeviceCapabilities{DeviceRef: device, Kinds: kinds}
	routes := networkRouting()
	if routes != nil {
		routes.First, routes.Last = network.RoutingRange(caps)
		for _, kind := range routedEgressKinds {
			caps.Kinds = append(caps.Kinds, &networkv1.KindSupport{
				Component: networkv1.Component_COMPONENT_EGRESS, Kind: kind, Versions: []uint32{1}, Executor: "agent",
			})
		}
	}
	servers := networkServers()
	if servers != nil {
		// anx-server accepts anx_line and dials the transports relay hops
		// use, leaving by a hop egress.
		listKind(caps, networkv1.Component_COMPONENT_TRANSPORT, network.TransportAnxLine)
		listKind(caps, networkv1.Component_COMPONENT_EGRESS, network.EgressHop)
	}
	return &networkComponent{
		device: device, applier: applier, caps: caps, routes: routes, servers: servers,
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

// close stops the status loop and the anx-server processes.
func (c *networkComponent) close() {
	c.once.Do(func() {
		close(c.stop)
		c.mu.Lock()
		started := c.client != nil
		c.mu.Unlock()
		if started {
			<-c.stopped
		}
		if c.servers != nil {
			c.servers.Close()
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
	if err := c.lineRoles(plan); err != nil {
		return agentapi.InvalidConfig(fmt.Errorf("network plan: %w", err))
	}
	var accepts []anxserver.Accept
	if c.servers != nil {
		if accepts, err = anxserver.Accepts(plan); err != nil {
			return agentapi.InvalidConfig(fmt.Errorf("network plan: %w", err))
		}
	}
	c.mu.Lock()
	current := c.plan
	c.mu.Unlock()
	if current != nil && current.GetHash() == plan.GetHash() && current.GetGeneration() == plan.GetGeneration() {
		return nil
	}
	if err := c.route(plan); err != nil {
		return fmt.Errorf("network plan generation %d: %w", plan.GetGeneration(), err)
	}
	status, applyErr := c.applier.ApplyNetwork(plan)
	if status == nil && applyErr != nil {
		return fmt.Errorf("network plan generation %d: %w", plan.GetGeneration(), applyErr)
	}
	if c.servers != nil {
		applyErr = errors.Join(applyErr, c.servers.Apply(accepts))
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

// listKind lists kind v1 with the Agent as an executor. A kind is listed
// once: where the core runs it too, its entry names both executors.
func listKind(caps *networkv1.DeviceCapabilities, component networkv1.Component, kind string) {
	for _, support := range caps.GetKinds() {
		if support.GetComponent() == component && support.GetKind() == kind {
			support.Executor = strings.TrimPrefix(support.GetExecutor()+",agent", ",")
			return
		}
	}
	caps.Kinds = append(caps.Kinds, &networkv1.KindSupport{Component: component, Kind: kind, Versions: []uint32{1}, Executor: "agent"})
}

// lineRoles refuses the anx_line ends this device cannot run: the core
// dials (anx-node), anx-server accepts, and the capabilities list the kind
// once for both.
func (c *networkComponent) lineRoles(plan *networkv1.NetworkPlan) error {
	coreDials := false
	for _, kind := range c.applier.NetworkKinds() {
		if kind.GetComponent() == networkv1.Component_COMPONENT_TRANSPORT && kind.GetKind() == network.TransportAnxLine {
			coreDials = true
		}
	}
	relayed := anxserver.Relayed(plan)
	for _, transport := range plan.GetTransports() {
		if transport.GetKind() != network.TransportAnxLine {
			continue
		}
		switch transport.GetRole() {
		case networkv1.TransportRole_TRANSPORT_ROLE_DIAL:
			if relayed[transport.GetId()] {
				// anx-server dials it, with the hop that relays into it.
				continue
			}
			if !coreDials {
				return fmt.Errorf("transport %s: dialing anx_line needs anx-node as the core (AnixcoreConfig.AnxLine)", transport.GetId())
			}
		case networkv1.TransportRole_TRANSPORT_ROLE_ACCEPT:
			if c.servers == nil {
				return fmt.Errorf("transport %s: accepting anx_line needs anx-server on this host", transport.GetId())
			}
		}
	}
	return nil
}

// route installs plan's policy routing before the core binds the egress
// sources. Without routing, a plan that needs it is refused.
func (c *networkComponent) route(plan *networkv1.NetworkPlan) error {
	first, last := network.RoutingRange(c.caps)
	routes, err := networkroute.Routes(plan, first, last)
	if err != nil {
		return agentapi.InvalidConfig(err)
	}
	if c.routes == nil {
		if len(routes) > 0 {
			return fmt.Errorf("egress %s needs policy routing, which this host has not (it needs Linux and the ip command)", routes[0].Egress)
		}
		return nil
	}
	return c.routes.Apply(routes)
}

// report sends status, or the core's status read now, for the plan the
// core runs, with the accepting anx_line ends and the server key. Before a
// plan only the server key is sent (the dialing ends' plans wait for it);
// nothing is sent without a negotiated session.
func (c *networkComponent) report(status *networkv1.NetworkStatus) {
	c.mu.Lock()
	plan, client, negotiated := c.plan, c.client, c.negotiated
	c.mu.Unlock()
	if client == nil || !negotiated {
		return
	}
	var keys []*networkv1.PublicKey
	if c.servers != nil {
		public, err := c.servers.PublicKey()
		if err != nil {
			c.logger().WithError(err).Warn("Could not make the anx-server key")
		} else {
			keys = append(keys, &networkv1.PublicKey{Kind: network.TransportAnxLine, Key: public})
		}
	}
	if plan == nil {
		if len(keys) == 0 {
			return
		}
		status = &networkv1.NetworkStatus{}
	} else if status == nil {
		read, err := c.applier.NetworkStatus()
		if err != nil {
			c.logger().WithError(err).Warn("Could not read the core's network status")
			return
		}
		status = read
	}
	status = proto.Clone(status).(*networkv1.NetworkStatus)
	if c.servers != nil && plan != nil {
		status.Components = append(status.Components, c.servers.Status()...)
	}
	status.PublicKeys = append(status.PublicKeys, keys...)
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
