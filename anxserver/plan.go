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
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	anxmgmtpb "github.com/AnixOps/anix-agent/v5/api/anxmgmt/v1"
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
	// Next is the ANX-Line link accepted traffic is relayed into when the
	// plan forwards the transport into a dialing anx_line transport (a
	// relay hop), nil when it leaves by an egress.
	Next *anxmgmtpb.Link
	// ReverseDial is the rendezvous a reverse transport's egress dials
	// back to (anx ANX-Line §4.6, SetReverseDials): such a transport
	// listens on nothing. ReverseListen is the rendezvous listener a relay
	// hop opens when Next is a reverse link.
	ReverseDial, ReverseListen string
	// HubPublic is, for a reverse l2 transport (anx ANX-LINE-REVERSE
	// §6.4), the rendezvous node's server key: the egress dials back as the
	// A2 jacket's client with ServerName as SNI and authenticates to it.
	HubPublic string
	// ReverseA2SNI is, for a relay hop whose Next is a reverse l2 link,
	// the server names its A2 rendezvous listener (on ReverseListen) takes;
	// "" for a bare rendezvous.
	ReverseA2SNI string
	// ReverseQUIC and ReverseFakeTCP are the C2 / C3 dial-backs of a
	// reverse transport (anx ANX-LINE-REVERSE §6.3), on when its carrier
	// order names the carrier: the egress keeps them toward ReverseDial, a
	// relay hop accepts them on ReverseListen (the same UDP port, the next
	// TCP port).
	ReverseQUIC, ReverseFakeTCP bool
}

// ReverseCarriers answers whether a reverse transport's carrier order
// names C2 (quic) and C3 (faketcp); an empty order is C1 only, so both
// ends agree without anx's default order.
func ReverseCarriers(order []string) (quic, faketcp bool) {
	for _, carrier := range order {
		switch carrier {
		case "c2", "quic":
			quic = true
		case "c3", "faketcp":
			faketcp = true
		}
	}
	return quic, faketcp
}

// Accepts answers the anx_line transports plan has this device accept, in
// transport id order.
func Accepts(plan *networkv1.NetworkPlan) ([]Accept, error) {
	egresses := map[string]*networkv1.Egress{}
	for _, egress := range plan.GetEgresses() {
		egresses[egress.GetId()] = egress
	}
	transports := map[string]*networkv1.Transport{}
	for _, transport := range plan.GetTransports() {
		transports[transport.GetId()] = transport
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
		if settings.GetReverse() {
			accept.ReverseDial = settings.GetReverseDial()
			if accept.L2 {
				// The A2 dial-back runs on c1 only.
				accept.HubPublic = settings.GetServerPublic()
			} else {
				accept.ReverseQUIC, accept.ReverseFakeTCP = ReverseCarriers(settings.GetCarrierOrder())
			}
		}
		if accept.LinkID == "" {
			accept.LinkID = accept.Transport
		}
		if forwarding := forwarded[transport.GetId()]; forwarding != nil {
			if next := forwarding.GetTransportId(); next != "" {
				into := transports[next]
				if into.GetKind() != network.TransportAnxLine || into.GetRole() != networkv1.TransportRole_TRANSPORT_ROLE_DIAL {
					return nil, fmt.Errorf("transport %s: forwarded into transport %q, which is not a dialing anx_line transport of the plan", transport.GetId(), next)
				}
				link, err := DialLink(into)
				if err != nil {
					return nil, err
				}
				accept.Next = link
				if link.GetReverse() {
					accept.ReverseListen = into.GetAnxLine().GetReverseListen()
					if link.GetEgress() == "l2" {
						// The egress dials back under the A2 jacket (anx
						// ANX-LINE-REVERSE §6.4): an A2 rendezvous, c1 only.
						accept.ReverseA2SNI = link.GetServerName()
						if accept.ReverseA2SNI == "" {
							return nil, fmt.Errorf("transport %s: the reverse l2 link %s needs a server name", transport.GetId(), next)
						}
					} else {
						accept.ReverseQUIC, accept.ReverseFakeTCP = ReverseCarriers(into.GetAnxLine().GetCarrierOrder())
					}
				}
				accepts = append(accepts, accept)
				continue
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

// DialLink answers the ANX-Line link of a dialing anx_line transport: the
// kernel names its outbound by the transport id (`anx-line:<id>`), so the
// link id is the transport id.
func DialLink(transport *networkv1.Transport) (*anxmgmtpb.Link, error) {
	settings := transport.GetAnxLine()
	key, err := hex.DecodeString(settings.GetLinkKey())
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("transport %s: the link key is not 32 bytes of hex", transport.GetId())
	}
	link := &anxmgmtpb.Link{
		LinkId: transport.GetId(), LinkKey: key, ServerPublic: settings.GetServerPublic(),
		QuicAddr: settings.GetQuicAddr(), FaketcpAddr: settings.GetFaketcpAddr(), TcpAddr: settings.GetTcpAddr(),
		Egress: settings.GetEgress(), ServerName: settings.GetServerName(),
		// A reverse link takes the connections its egress dials back to
		// the rendezvous (anx ANX-Line §4.6) and has no carrier address.
		Reverse: settings.GetReverse(),
		// UDP on a connection of its own, apart from bulk TCP (anx
		// ANX-LINE-ONBOARDING §3, TBD-L15).
		UdpLanes: 1,
	}
	if len(settings.GetCarrierOrder()) > 0 || settings.GetMultipath() || settings.GetFec() {
		link.Policy = &anxmgmtpb.LinePolicy{
			Order: append([]string(nil), settings.GetCarrierOrder()...), Multipath: settings.GetMultipath(), Fec: settings.GetFec(),
		}
	}
	return link, nil
}

// Relayed answers the dialing transports of plan that only relay hops use
// (forwarding into them): anx-server dials them, not the core.
func Relayed(plan *networkv1.NetworkPlan) map[string]bool {
	relayed := map[string]bool{}
	for _, forwarding := range plan.GetForwarding() {
		if next := forwarding.GetTransportId(); next != "" {
			relayed[next] = true
		}
	}
	for _, path := range plan.GetPaths() {
		delete(relayed, path.GetTransportId())
	}
	for _, forward := range plan.GetPortForwards() {
		delete(relayed, forward.GetTransportId())
	}
	for _, proxy := range plan.GetReverseProxies() {
		delete(relayed, proxy.GetTransportId())
	}
	return relayed
}

// listener is what a process is started with: transports that share it
// share the process.
type listener struct {
	TCP, QUIC, FakeTCP string
	L2                 bool
	ServerName         string
	Sources            string
	ReverseListen      string
	// ReverseA2SNI: ReverseListen is an A2 rendezvous with these server
	// names (--reverse-a2-listen), "" for a bare one (--reverse-listen).
	ReverseA2SNI string
	// ReverseQUIC / ReverseFakeTCP: the C2 / C3 dial-backs, accepted on
	// ReverseListen or, with no ReverseListen, dialed by the egress.
	ReverseQUIC, ReverseFakeTCP bool
}

func (a Accept) listener() listener {
	sources := make([]string, 0, len(a.Sources))
	for _, source := range a.Sources {
		sources = append(sources, source.String())
	}
	sort.Strings(sources)
	return listener{TCP: a.TCP, QUIC: a.QUIC, FakeTCP: a.FakeTCP, L2: a.L2, ServerName: a.ServerName,
		Sources: strings.Join(sources, ","), ReverseListen: a.ReverseListen, ReverseA2SNI: a.ReverseA2SNI,
		ReverseQUIC: a.ReverseQUIC, ReverseFakeTCP: a.ReverseFakeTCP}
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
			// The jacket answers what does not authenticate with the site it
			// wears (spec §2.1, §4 step 1) and copies that site's
			// ServerHello: without a dest a probe is closed instead, which
			// sets the listener apart on a cross-border segment. The site is
			// the first server name on 443, REALITY's usual dest.
			site, _, _ := strings.Cut(name, ",")
			args = append(args, "--listen", l.TCP, "--dest", net.JoinHostPort(site, "443"))
		} else {
			args = append(args, "--bare-listen", l.TCP)
		}
	}
	if l.QUIC != "" {
		args = append(args, "--quic-listen", l.QUIC)
	}
	if l.QUIC != "" || l.ReverseQUIC {
		// UDP relayed over QUIC is dropped in the listener's socket buffer
		// under load (anx ANX-LINE-ONBOARDING §6): a large socket buffer,
		// which the host's net.core.rmem_max/wmem_max must allow
		// (RaiseSocketBuffers), and a larger DATAGRAM buffer. The same
		// holds for the C2 dial-back on both ends (anx TBD-L16).
		args = append(args, "--quic-sockbuf", strconv.Itoa(QUICSocketBuffer), "--quic-dgram-buf", strconv.Itoa(QUICDatagramBuffer))
	}
	if l.FakeTCP != "" {
		args = append(args, "--faketcp-listen", l.FakeTCP)
	}
	if l.ReverseListen != "" && l.ReverseA2SNI != "" {
		// The A2 rendezvous of reverse l2 links (anx ANX-LINE-REVERSE
		// §6.4): what does not authenticate goes to the first name's site,
		// as on the forward A2 listener.
		site, _, _ := strings.Cut(l.ReverseA2SNI, ",")
		args = append(args, "--reverse-a2-listen", l.ReverseListen, "--reverse-a2-sni", l.ReverseA2SNI,
			"--reverse-a2-dest", net.JoinHostPort(site, "443"))
	} else if l.ReverseListen != "" {
		args = append(args, "--reverse-listen", l.ReverseListen)
		if l.ReverseQUIC {
			args = append(args, "--reverse-quic")
		}
		if l.ReverseFakeTCP {
			args = append(args, "--reverse-faketcp")
		}
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
		listens := accept.TCP != "" || accept.QUIC != "" || accept.FakeTCP != ""
		switch {
		case accept.ReverseDial != "" && listens:
			// The egress opens no port; the rendezvous runs the link over
			// the connections it dials back.
			return nil, fmt.Errorf("transport %s: a reverse transport has no listen address", accept.Transport)
		case accept.ReverseDial != "" && accept.L2 && (accept.HubPublic == "" || accept.ServerName == ""):
			// l2 dials back as the A2 jacket's client (anx
			// ANX-LINE-REVERSE §6.4).
			return nil, fmt.Errorf("transport %s: a reverse l2 transport needs the rendezvous's server key and a server name", accept.Transport)
		case accept.ReverseDial != "":
			if _, _, err := net.SplitHostPort(accept.ReverseDial); err != nil {
				return nil, fmt.Errorf("transport %s: reverse dial %q is not host:port", accept.Transport, accept.ReverseDial)
			}
		case !listens:
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
		addresses := []string{"tcp " + l.TCP, "udp " + l.QUIC, "fake-tcp " + l.FakeTCP, "tcp " + l.ReverseListen}
		if l.ReverseListen != "" && l.ReverseQUIC {
			// The C2 dial-backs share the rendezvous port number on UDP.
			addresses = append(addresses, "udp "+l.ReverseListen)
		}
		for _, address := range addresses {
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
