package anixcore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
	"github.com/AnixOps/anix-control/sdk/network"
)

// The plan's port forwards (forward rules on the network model) run as
// anixcore `forward` inbounds (networkcore inbound-forward), one per port
// forward, tagged forwardTagPrefix + id. Their traffic leaves by the
// outbound of their next hop: `egress:<id>` for an internet egress, or
// `anx-line:<transport id>` for a dialing anx_line transport, where the
// targets are resolved and dialed at the last hop. anixcore counts each
// inbound's bytes, which the status reports cumulatively.

// forwardTagPrefix starts the inbound tag of a port forward.
const forwardTagPrefix = "forward-"

// forwardInbounds answers the forward inbounds of plan's port forwards, by
// tag.
func forwardInbounds(plan *networkv1.NetworkPlan) (map[string]map[string]any, error) {
	transports := map[string]*networkv1.Transport{}
	for _, transport := range plan.GetTransports() {
		transports[transport.GetId()] = transport
	}
	inbounds := map[string]map[string]any{}
	for _, forward := range plan.GetPortForwards() {
		tag := forwardTagPrefix + forward.GetId()
		inbound := map[string]any{
			"tag": tag, "type": "forward",
			"listen": forward.GetListen().GetAddress(), "listen_port": forward.GetListen().GetPort(),
			"network": strings.Join(forward.GetProtocols(), ","),
		}
		switch {
		case forward.GetEgressId() != "":
			inbound["outbound"] = "egress:" + forward.GetEgressId()
		case forward.GetTransportId() != "":
			transport := transports[forward.GetTransportId()]
			if transport.GetKind() != network.TransportAnxLine || transport.GetRole() != networkv1.TransportRole_TRANSPORT_ROLE_DIAL {
				return nil, fmt.Errorf("port forward %s: transport %s is not a dialing anx_line transport", forward.GetId(), forward.GetTransportId())
			}
			inbound["outbound"] = "anx-line:" + transport.GetId()
		default:
			return nil, fmt.Errorf("port forward %s: no next hop", forward.GetId())
		}
		targets := forward.GetTargets()
		if len(targets) == 1 {
			inbound["server"], inbound["server_port"] = targets[0].GetHost(), targets[0].GetPort()
		} else {
			// Several targets need an anixcore with balancing
			// (networkcore #139); the first one is not chosen silently.
			list := make([]map[string]any, 0, len(targets))
			for _, target := range targets {
				list = append(list, map[string]any{"server": target.GetHost(), "server_port": target.GetPort()})
			}
			inbound["targets"] = list
		}
		inbounds[tag] = inbound
	}
	return inbounds, nil
}

// syncForwards makes anixcore run exactly wanted: changed and gone forward
// inbounds are removed, new and changed ones added; c.mu is held.
func (c *Core) syncForwards(wanted map[string]map[string]any) error {
	if c.forwards == nil {
		c.forwards = map[string]map[string]any{}
	}
	var remove, add []string
	for tag, inbound := range c.forwards {
		if want, ok := wanted[tag]; !ok || !sameInbound(want, inbound) {
			remove = append(remove, tag)
		}
	}
	for tag, inbound := range wanted {
		if have, ok := c.forwards[tag]; !ok || !sameInbound(have, inbound) {
			add = append(add, tag)
		}
	}
	sort.Strings(remove)
	sort.Strings(add)
	for _, tag := range remove {
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		err := c.client.removeInbound(ctx, tag)
		cancel()
		if err != nil && !isStatus(err, 404) {
			return fmt.Errorf("anixcore remove forward %s: %w", tag, err)
		}
		delete(c.forwards, tag)
	}
	for _, tag := range add {
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		err := c.client.addInbound(ctx, wanted[tag])
		cancel()
		if err != nil {
			return fmt.Errorf("anixcore add forward %s: %w", tag, err)
		}
		c.forwards[tag] = wanted[tag]
	}
	return nil
}

func sameInbound(a, b map[string]any) bool {
	encodedA, errA := json.Marshal(a)
	encodedB, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(encodedA, encodedB)
}

// forwardStatus answers one status per port forward anixcore runs, with
// the bytes it relayed since it started.
func forwardStatus(client *client, tags []string) []*networkv1.PortForwardStatus {
	var statuses []*networkv1.PortForwardStatus
	for _, tag := range tags {
		status := &networkv1.PortForwardStatus{Id: strings.TrimPrefix(tag, forwardTagPrefix)}
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		traffic, err := client.inboundTraffic(ctx, tag)
		cancel()
		if err != nil {
			status.State = networkv1.ComponentState_COMPONENT_STATE_DOWN
			status.Detail = truncate(fmt.Sprintf("anixcore forward traffic: %v", err), network.MaxTextBytes)
		} else {
			status.State = networkv1.ComponentState_COMPONENT_STATE_APPLIED
			status.UpBytes, status.DownBytes = traffic.Up, traffic.Down
		}
		statuses = append(statuses, status)
	}
	return statuses
}

// heldForwards answers the tags of the forward inbounds anixcore runs;
// c.mu is held.
func (c *Core) heldForwards() []string {
	tags := make([]string, 0, len(c.forwards))
	for tag := range c.forwards {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
}

// inboundBytes is anixcore's count of one inbound's bytes, all users and
// none together.
type inboundBytes struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

func (c *client) inboundTraffic(ctx context.Context, tag string) (inboundBytes, error) {
	var answer struct {
		Inbound inboundBytes `json:"inbound"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/inbounds/"+url.PathEscape(tag)+"/traffic", nil, &answer)
	return answer.Inbound, err
}
