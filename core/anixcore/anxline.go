package anixcore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/AnixOps/anix-agent/v5/anxserver"
	anxmgmtpb "github.com/AnixOps/anix-agent/v5/api/anxmgmt/v1"
	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
	"github.com/AnixOps/anix-control/sdk/network"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

// The dialing ends of anx_line transports (conf AnixcoreConfig.AnxLine):
// the binary is anx-node, which serves `anx-line:<link id>` outbounds for
// the links its ANX-Line management API (contracts/anx, AddLinks) holds,
// and the plan's paths into a transport leave by `anx-line:<transport id>`.
// So each dialing transport becomes the link of the same id, added before
// the plan that uses it and removed after; a restarted anx-node gets its
// links again before its plan. Links are not kept by anx-node.

// lineKinds are what anx-node adds: the anx_line transports it dials and
// the hop egresses they leave by (Control's auto routes give every dialing
// transport one).
var lineKinds = []*networkv1.KindSupport{
	{Component: networkv1.Component_COMPONENT_TRANSPORT, Kind: network.TransportAnxLine, Versions: []uint32{1}, Executor: coreType},
	{Component: networkv1.Component_COMPONENT_EGRESS, Kind: network.EgressHop, Versions: []uint32{1}, Executor: coreType},
}

// connectLine opens anx-node's ANX-Line management client.
var connectLine = func(addr string) (anxmgmtpb.ManagementClient, func() error, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, err
	}
	return anxmgmtpb.NewManagementClient(conn), conn.Close, nil
}

// reverseListener is anx-node's rendezvous listener (anx ANX-Line §4.6):
// Listen ("" for none) and whether it also accepts the C2 / C3 dial-backs
// (`anx_line.reverse_quic` / `reverse_faketcp`, anx ANX-LINE-REVERSE §6.3).
type reverseListener struct {
	Listen        string
	QUIC, FakeTCP bool
}

// dialLinks answers the links of plan's dialing anx_line ends, by id, and
// the rendezvous listener their reverse links need; transports only relay
// hops use are anx-server's (anxserver.Relayed).
func dialLinks(plan *networkv1.NetworkPlan) (map[string]*anxmgmtpb.Link, reverseListener, error) {
	relayed := anxserver.Relayed(plan)
	links := map[string]*anxmgmtpb.Link{}
	var reverse reverseListener
	for _, transport := range plan.GetTransports() {
		if transport.GetKind() != network.TransportAnxLine || transport.GetRole() != networkv1.TransportRole_TRANSPORT_ROLE_DIAL ||
			relayed[transport.GetId()] {
			continue
		}
		link, err := anxserver.DialLink(transport)
		if err != nil {
			return nil, reverseListener{}, err
		}
		if link.GetReverse() {
			// anx-node opens one rendezvous listener for all its reverse
			// links (`anx_line.reverse_listen`).
			listen := transport.GetAnxLine().GetReverseListen()
			if listen == "" || (reverse.Listen != "" && listen != reverse.Listen) {
				return nil, reverseListener{}, fmt.Errorf("transport %s: reverse links need one reverse listener, have %q and %q", transport.GetId(), reverse.Listen, listen)
			}
			reverse.Listen = listen
			// One listener for all: it accepts a carrier any link orders.
			quic, faketcp := anxserver.ReverseCarriers(transport.GetAnxLine().GetCarrierOrder())
			reverse.QUIC, reverse.FakeTCP = reverse.QUIC || quic, reverse.FakeTCP || faketcp
		}
		links[link.GetLinkId()] = link
	}
	return links, reverse, nil
}

// reopen relaunches an anx-node this core started whose rendezvous
// listener is not listen, and gives it everything again; an anx-node the
// core did not start (ApiAddress) keeps its own `anx_line.reverse_listen`.
func (c *Core) reopen(listen reverseListener) error {
	c.mu.Lock()
	process, exited := c.process, c.exited
	if process == nil || !c.config.AnxLine || c.reverse == listen {
		c.mu.Unlock()
		return nil
	}
	c.reverse = listen
	// Not c.process any more: supervise leaves it be.
	c.process = nil
	c.mu.Unlock()
	_ = process.Process.Signal(os.Interrupt)
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		_ = process.Process.Kill()
		<-exited
	}
	if err := c.launch(); err != nil {
		c.mu.Lock()
		started := c.process != nil
		c.mu.Unlock()
		if !started {
			// A process that started and failed is supervised already.
			go c.supervise(nil, err)
		}
		return fmt.Errorf("anixcore: relaunch anx-node for reverse listener %q: %w", listen.Listen, err)
	}
	// The last plan's links may need the listener that just went; the
	// plan being applied replaces them.
	if err := c.replay(); err != nil {
		log.WithField("core", coreType).WithError(err).Warn("restore anixcore after reopening the reverse listener")
	}
	return nil
}

// syncLinks makes anx-node hold exactly wanted: changed and gone links are
// removed, new and changed ones added; c.mu is held.
func (c *Core) syncLinks(wanted map[string]*anxmgmtpb.Link) error {
	if c.line == nil {
		if len(wanted) > 0 {
			return errors.New("anixcore: dialing anx_line needs anx-node (AnixcoreConfig.AnxLine)")
		}
		return nil
	}
	if c.links == nil {
		c.links = map[string]*anxmgmtpb.Link{}
	}
	var remove []string
	for id, link := range c.links {
		if want, ok := wanted[id]; !ok || !proto.Equal(want, link) {
			remove = append(remove, id)
		}
	}
	sort.Strings(remove)
	var add []*anxmgmtpb.Link
	for id, link := range wanted {
		if have, ok := c.links[id]; !ok || !proto.Equal(have, link) {
			add = append(add, link)
		}
	}
	sort.Slice(add, func(i, j int) bool { return add[i].GetLinkId() < add[j].GetLinkId() })
	if len(remove) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		_, err := c.line.RemoveLinks(ctx, &anxmgmtpb.RemoveLinksRequest{LinkIds: remove})
		cancel()
		if err != nil {
			return fmt.Errorf("anx-node remove links: %w", err)
		}
		for _, id := range remove {
			delete(c.links, id)
		}
	}
	if len(add) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		_, err := c.line.AddLinks(ctx, &anxmgmtpb.AddLinksRequest{Links: add})
		cancel()
		if err != nil {
			return fmt.Errorf("anx-node add links: %w", err)
		}
		for _, link := range add {
			c.links[link.GetLinkId()] = link
		}
	}
	return nil
}

// linkStatus answers one transport component per link anx-node holds:
// applied, with the carrier in use once the link is connected (links
// connect on their first flow).
func linkStatus(line anxmgmtpb.ManagementClient, links []string) []*networkv1.ComponentStatus {
	if line == nil || len(links) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	answer, err := line.LinkStats(ctx, &anxmgmtpb.LinkStatsRequest{})
	cancel()
	stats := map[string]*anxmgmtpb.LinkStat{}
	for _, stat := range answer.GetLinks() {
		stats[stat.GetLinkId()] = stat
	}
	var components []*networkv1.ComponentStatus
	for _, id := range links {
		component := &networkv1.ComponentStatus{Component: networkv1.Component_COMPONENT_TRANSPORT, Id: id}
		stat := stats[id]
		switch {
		case err != nil:
			component.State = networkv1.ComponentState_COMPONENT_STATE_DOWN
			component.Detail = truncate(fmt.Sprintf("anx-node link stats: %v", err), network.MaxTextBytes)
		case stat == nil:
			component.State = networkv1.ComponentState_COMPONENT_STATE_DOWN
			component.Detail = "anx-node does not hold the link"
		default:
			component.State = networkv1.ComponentState_COMPONENT_STATE_APPLIED
			if stat.GetConnected() {
				component.Carrier = truncate(stat.GetCarrier(), network.MaxTextBytes)
				component.RttMs = stat.GetRttMs()
				if component.RttMs == 0 {
					// Only QUIC carriers measure a round trip: on the
					// others the handshake of the carrier's last probe
					// stands in for it.
					for _, probe := range stat.GetProbes() {
						if probe.GetCarrier() == stat.GetCarrier() && probe.GetOk() && probe.GetHandshakeMs() > 0 {
							component.RttMs = probe.GetHandshakeMs()
						}
					}
				}
			}
		}
		components = append(components, component)
	}
	return components
}

// heldLinks answers the ids of the links anx-node holds; c.mu is held.
func (c *Core) heldLinks() []string {
	ids := make([]string, 0, len(c.links))
	for id := range c.links {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
