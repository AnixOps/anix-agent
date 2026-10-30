package anixcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"

	vCore "github.com/AnixOps/anix-agent/v5/core"
	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
	"github.com/AnixOps/anix-control/sdk/network"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var _ vCore.NetworkApplier = (*Core)(nil)

// The device network model on anixcore (networkcore node-runtime
// `network`): the plan goes to anixcore as is (PUT /v1/network), which
// runs each egress as an outbound `egress:<id>` bound to its source and
// sends an inbound's connections down the active path of the ingress its
// `ingress` key names. The core joins a node's inbound to the user
// ingress listening on the node's port. The plan is kept, so a restarted
// anixcore gets it again before its inbounds.

// networkKinds are the components anixcore runs (node-runtime network.rs):
// ingresses of either kind and egresses leaving from the device's own
// address. The Agent adds dedicated_ip where it can route, and the
// accepting anx_line ends where anx-server is installed (node network.go);
// anx-node (AnxLine) dials anx_line transports (anxline.go).
var networkKinds = []*networkv1.KindSupport{
	{Component: networkv1.Component_COMPONENT_INGRESS, Kind: network.IngressDirect, Versions: []uint32{1}, Executor: coreType},
	{Component: networkv1.Component_COMPONENT_INGRESS, Kind: network.IngressNAT, Versions: []uint32{1}, Executor: coreType},
	{Component: networkv1.Component_COMPONENT_EGRESS, Kind: network.EgressNATDirect, Versions: []uint32{1}, Executor: coreType},
}

var networkPlanJSON = protojson.MarshalOptions{UseProtoNames: true}

// kernelNetworkStatus is anixcore's answer to /v1/network.
type kernelNetworkStatus struct {
	Generation uint64 `json:"generation"`
	Egresses   []struct {
		ID              string  `json:"id"`
		State           string  `json:"state"`
		RTTMs           *uint64 `json:"rtt_ms"`
		Detail          *string `json:"detail"`
		ChangedAtUnixMs int64   `json:"changed_at_unix_ms"`
	} `json:"egresses"`
	Ingresses []struct {
		ID             string  `json:"id"`
		State          string  `json:"state"`
		ActiveEgressID *string `json:"active_egress_id"`
	} `json:"ingresses"`
}

// NetworkKinds implements vCore.NetworkApplier.
func (c *Core) NetworkKinds() []*networkv1.KindSupport {
	if c.config.AnxLine {
		return append(append([]*networkv1.KindSupport(nil), networkKinds...), lineKinds...)
	}
	return networkKinds
}

// ApplyNetwork implements vCore.NetworkApplier: anixcore replaces its plan
// with plan (nil or an empty plan removes it), and the inbounds whose
// ingress changed are created again with their new `ingress` key.
func (c *Core) ApplyNetwork(plan *networkv1.NetworkPlan) (*networkv1.NetworkStatus, error) {
	body, err := networkBody(plan)
	if err != nil {
		return nil, err
	}
	links, reverse, err := dialLinks(plan)
	if err != nil {
		return nil, err
	}
	if err := c.reopen(reverse); err != nil {
		return nil, err
	}
	forwards, err := forwardInbounds(plan)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client == nil {
		return nil, errors.New("anixcore: the core is not started")
	}
	// The links go in first: the plan's paths leave by them.
	if err := c.syncLinks(links); err != nil {
		return nil, err
	}
	c.wantedLinks = links
	answer, err := c.putNetwork(body)
	if err != nil {
		return nil, err
	}
	answer.Components = append(answer.Components, linkStatus(c.line, c.heldLinks())...)
	c.network = nil
	if len(plan.GetIngresses())+len(plan.GetEgresses())+len(plan.GetPaths()) > 0 {
		c.network = body
	}
	// The forwards go in after the plan: they leave by its egresses.
	c.wantedForwards = forwards
	var failed error
	if err := c.syncForwards(forwards); err != nil {
		failed = err
	}
	answer.PortForwards = forwardStatus(c.client, c.heldForwards())
	c.ingresses = userIngresses(plan)
	for tag, n := range c.nodes {
		ingress := c.ingressOf(n)
		if ingress == n.ingress {
			continue
		}
		n.ingress = ingress
		if !n.created {
			continue
		}
		if err := c.recreate(tag, n); err != nil {
			failed = errors.Join(failed, fmt.Errorf("anixcore node %s: %w", tag, err))
		}
	}
	return answer, failed
}

// NetworkStatus implements vCore.NetworkApplier.
func (c *Core) NetworkStatus() (*networkv1.NetworkStatus, error) {
	c.mu.Lock()
	client, line, links, forwards := c.client, c.line, c.heldLinks(), c.heldForwards()
	c.mu.Unlock()
	if client == nil {
		return nil, errors.New("anixcore: the core is not started")
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	var answer kernelNetworkStatus
	if err := client.getNetwork(ctx, &answer); err != nil {
		return nil, networkError(err)
	}
	status := answer.status()
	status.Components = append(status.Components, linkStatus(line, links)...)
	status.PortForwards = forwardStatus(client, forwards)
	return status, nil
}

// networkBody is plan as anixcore reads it: protojson with proto names,
// `{}` for no plan, without the port forwards, which run as inbounds
// (forward.go).
func networkBody(plan *networkv1.NetworkPlan) (json.RawMessage, error) {
	if plan == nil {
		return json.RawMessage(`{}`), nil
	}
	if len(plan.GetPortForwards()) > 0 {
		plan = proto.Clone(plan).(*networkv1.NetworkPlan)
		plan.PortForwards = nil
	}
	encoded, err := networkPlanJSON.Marshal(plan)
	if err != nil {
		return nil, fmt.Errorf("anixcore network: %w", err)
	}
	return encoded, nil
}

// putNetwork sends body to anixcore; c.mu is held.
func (c *Core) putNetwork(body json.RawMessage) (*networkv1.NetworkStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	var answer kernelNetworkStatus
	if err := c.client.putNetwork(ctx, body, &answer); err != nil {
		return nil, networkError(err)
	}
	return answer.status(), nil
}

func networkError(err error) error {
	if isStatus(err, 404) {
		return errors.New("anixcore: this anixcore has no network model; update it")
	}
	return fmt.Errorf("anixcore network: %w", err)
}

// userIngresses maps each listen port of the plan's user ingresses to the
// first ingress on it.
func userIngresses(plan *networkv1.NetworkPlan) map[int]string {
	ingresses := map[int]string{}
	for _, ingress := range plan.GetIngresses() {
		if ingress.GetAudience() != networkv1.Audience_AUDIENCE_USER {
			continue
		}
		port := int(ingress.GetListen().GetPort())
		if _, taken := ingresses[port]; !taken && port > 0 {
			ingresses[port] = ingress.GetId()
		}
	}
	return ingresses
}

// ingressOf is the ingress n's inbound joins, "" for none; c.mu is held.
func (c *Core) ingressOf(n *node) string {
	if n.info == nil || n.info.Common == nil {
		return ""
	}
	return c.ingresses[n.info.Common.ServerPort]
}

// recreate removes n's inbound and adds it again, for a new ingress key;
// c.mu is held.
func (c *Core) recreate(tag string, n *node) error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	if err := c.client.removeInbound(ctx, tag); err != nil && !isStatus(err, 404) {
		return err
	}
	n.created = false
	return c.create(tag, n)
}

// status converts anixcore's answer into the components of a
// NetworkStatus; the device, plan and time are the caller's.
func (s *kernelNetworkStatus) status() *networkv1.NetworkStatus {
	status := &networkv1.NetworkStatus{Generation: s.Generation}
	for _, egress := range s.Egresses {
		component := &networkv1.ComponentStatus{
			Component: networkv1.Component_COMPONENT_EGRESS, Id: egress.ID,
			State: componentState(egress.State), ChangedAtUnixMs: egress.ChangedAtUnixMs,
		}
		if egress.RTTMs != nil {
			component.RttMs = uint32(min(*egress.RTTMs, math.MaxUint32)) // #nosec G115 -- clamped.
		}
		if egress.Detail != nil {
			component.Detail = truncate(*egress.Detail, network.MaxTextBytes)
		}
		status.Components = append(status.Components, component)
	}
	for _, ingress := range s.Ingresses {
		component := &networkv1.ComponentStatus{
			Component: networkv1.Component_COMPONENT_INGRESS, Id: ingress.ID, State: componentState(ingress.State),
		}
		if ingress.ActiveEgressID != nil {
			component.ActiveEgressId = *ingress.ActiveEgressID
		}
		status.Components = append(status.Components, component)
	}
	return status
}

func componentState(state string) networkv1.ComponentState {
	switch state {
	case "applied":
		return networkv1.ComponentState_COMPONENT_STATE_APPLIED
	case "degraded":
		return networkv1.ComponentState_COMPONENT_STATE_DEGRADED
	case "down":
		return networkv1.ComponentState_COMPONENT_STATE_DOWN
	default:
		return networkv1.ComponentState_COMPONENT_STATE_UNSPECIFIED
	}
}

// truncate cuts text to at most limit bytes on a rune boundary.
func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	for limit > 0 && !utf8.RuneStart(text[limit]) {
		limit--
	}
	return text[:limit]
}
