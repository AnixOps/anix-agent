// Package anxserver runs the accepting ends of the device network model's
// anx_line transports (anix-control docs/design/network-model): anx-server
// processes that listen on the hop ingress's addresses and admit each link
// by its link key (contracts/anx BOUNDARY.md; the key is a user key of
// AddUsers). Accepted traffic leaves anx-server toward its target bound to
// the source of the egress the plan forwards the transport to.
//
// The server key is generated once (`anx-server keygen`) and kept in the
// Manager's directory; its public half is what the dialing ends need, and
// the Agent reports it in NetworkStatus.public_keys.
//
// Transports that share their listen addresses, server name and egress
// sources share one process; each process gets a loopback management
// endpoint the Manager drives over gRPC (anx.mgmt.v1).
package anxserver

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
	"github.com/AnixOps/anix-control/sdk/network"
)

// Accept is one anx_line transport this device accepts.
type Accept struct {
	// Transport is the transport id, LinkID the ANX-Line link id.
	Transport string
	LinkID    string
	LinkKey   []byte
	// TCP, QUIC and FakeTCP are the listen addresses per carrier, "" for a
	// carrier not offered.
	TCP, QUIC, FakeTCP string
	// L2 serves the jacketed egress on TCP (server name required); l1 serves
	// the bare one.
	L2         bool
	ServerName string
	// Sources are the egress source addresses, at most one per family.
	Sources []netip.Addr
}

// Accepts answers the anx_line transports plan has this device accept, in
// transport id order.
func Accepts(plan *networkv1.NetworkPlan) ([]Accept, error) {
	egresses := map[string]*networkv1.Egress{}
	for _, egress := range plan.GetEgresses() {
		egresses[egress.GetId()] = egress
	}
	forwarded := map[string]*networkv1.Forwarding{}
	for _, forwarding := range plan.GetForwarding() {
		forwarded[forwarding.GetFromTransportId()] = forwarding
	}
	var accepts []Accept
	for _, transport := range plan.GetTransports() {
		if transport.GetKind() != network.TransportAnxLine {
			continue
		}
		if transport.GetRole() != networkv1.TransportRole_TRANSPORT_ROLE_ACCEPT {
			// The dialing end is the core's (anx-node).
			continue
		}
		settings := transport.GetAnxLine()
		key, err := hex.DecodeString(settings.GetLinkKey())
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("transport %s: the link key is not 32 bytes of hex", transport.GetId())
		}
		accept := Accept{
			Transport: transport.GetId(), LinkID: settings.GetLinkId(), LinkKey: key,
			TCP: settings.GetTcpAddr(), QUIC: settings.GetQuicAddr(), FakeTCP: settings.GetFaketcpAddr(),
			L2: settings.GetEgress() == "l2", ServerName: settings.GetServerName(),
		}
		if accept.LinkID == "" {
			accept.LinkID = accept.Transport
		}
		if forwarding := forwarded[transport.GetId()]; forwarding != nil {
			if next := forwarding.GetTransportId(); next != "" {
				return nil, fmt.Errorf("transport %s: forwarding into transport %s is not run by this Agent", transport.GetId(), next)
			}
			id := forwarding.GetEgressId()
			egress := egresses[id]
			if egress == nil {
				return nil, fmt.Errorf("transport %s: forwarded to egress %q, which is not in the plan", transport.GetId(), id)
			}
			if source := egress.GetSource(); source != "" && source != network.SourceAuto {
				address, err := netip.ParseAddr(source)
				if err != nil {
					return nil, fmt.Errorf("transport %s: egress %s source %q: %w", transport.GetId(), id, source, err)
				}
				accept.Sources = append(accept.Sources, address.Unmap())
			}
		}
		accepts = append(accepts, accept)
	}
	sort.Slice(accepts, func(i, j int) bool { return accepts[i].Transport < accepts[j].Transport })
	return accepts, nil
}

// listener is what a process is started with: transports that share it
// share the process.
type listener struct {
	TCP, QUIC, FakeTCP string
	L2                 bool
	ServerName         string
	Sources            string
}

func (a Accept) listener() listener {
	sources := make([]string, 0, len(a.Sources))
	for _, source := range a.Sources {
		sources = append(sources, source.String())
	}
	sort.Strings(sources)
	return listener{TCP: a.TCP, QUIC: a.QUIC, FakeTCP: a.FakeTCP, L2: a.L2, ServerName: a.ServerName,
		Sources: strings.Join(sources, ",")}
}

// defaultServerName is the --sni of a bare (l1) server, which serves no
// jacket but must be given one.
const defaultServerName = "anx-line"

// args are the `anx-server run` arguments of l without the key, the
// management endpoint and, for l1, the jacket listener the caller picks.
func (l listener) args() []string {
	name := l.ServerName
	if name == "" {
		name = defaultServerName
	}
	args := []string{"--sni", name}
	if l.TCP != "" {
		if l.L2 {
			args = append(args, "--listen", l.TCP)
		} else {
			args = append(args, "--bare-listen", l.TCP)
		}
	}
	if l.QUIC != "" {
		args = append(args, "--quic-listen", l.QUIC)
	}
	if l.FakeTCP != "" {
		args = append(args, "--faketcp-listen", l.FakeTCP)
	}
	if l.Sources != "" {
		for _, source := range strings.Split(l.Sources, ",") {
			args = append(args, "--egress-source", source)
		}
	}
	return args
}

// group checks the accepts and groups them by listener: two listeners may
// not share an address, a family has at most one source.
func group(accepts []Accept) (map[listener][]Accept, error) {
	groups := map[listener][]Accept{}
	links := map[string]string{}
	for _, accept := range accepts {
		if accept.TCP == "" && accept.QUIC == "" && accept.FakeTCP == "" {
			return nil, fmt.Errorf("transport %s: no listen address", accept.Transport)
		}
		if accept.L2 && accept.ServerName == "" {
			return nil, fmt.Errorf("transport %s: l2 needs a server name", accept.Transport)
		}
		var v4, v6 int
		for _, source := range accept.Sources {
			if source.Is4() {
				v4++
			} else {
				v6++
			}
		}
		if v4 > 1 || v6 > 1 {
			return nil, fmt.Errorf("transport %s: more than one egress source per family", accept.Transport)
		}
		if other, taken := links[accept.LinkID]; taken {
			return nil, fmt.Errorf("transports %s and %s: the same link id %q", other, accept.Transport, accept.LinkID)
		}
		links[accept.LinkID] = accept.Transport
		l := accept.listener()
		groups[l] = append(groups[l], accept)
	}
	owners := map[string]listener{}
	for l := range groups {
		for _, address := range []string{"tcp " + l.TCP, "udp " + l.QUIC, "fake-tcp " + l.FakeTCP} {
			if strings.HasSuffix(address, " ") {
				continue
			}
			if other, taken := owners[address]; taken && other != l {
				return nil, fmt.Errorf("listen address %s is wanted by two anx-server configurations (different carriers, server names or egress sources)", address)
			}
			owners[address] = l
		}
	}
	return groups, nil
}
