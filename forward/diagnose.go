package forward

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"github.com/AnixOps/anix-control/sdk/forward/model"
	"github.com/AnixOps/anix-control/sdk/forward/validate"
)

// Forward diagnostic checks (Control's route diagnosis, forward-sdk.md
// section 7.6, F3c; sdk/api/agent/v1/PROTOCOL.md, "Forward diagnostic
// checks"). Control sends them as agent.diagnostic tasks, one hop of one
// route each. The safety rule: a check resolves the hop from the state the
// component holds and probes only that hop's listener and upstreams; it
// never dials an address Control names, and a target's every address must
// pass the target policy. A check never changes the node.

// The checks.
const (
	CheckListen       = "forward.listen"
	CheckPortConflict = "forward.port_conflict"
	CheckConnect      = "forward.connect"
	CheckUDPProbe     = "forward.udp_probe"
)

// Verdicts of a check and of each item.
const (
	VerdictOK           = "ok"
	VerdictFailed       = "failed"
	VerdictInconclusive = "inconclusive"
	VerdictSkipped      = "skipped"
)

const (
	defaultCheckTimeout = 3 * time.Second
	minCheckTimeout     = 100 * time.Millisecond
	maxCheckTimeout     = 10 * time.Second
	// maxCheckItems bounds a result's items.
	maxCheckItems = 64
	// udpProbePayload is the one datagram a UDP probe sends.
	udpProbePayload = "anixops-diag\n"
	// ownTable is the nftables driver's table, which is never foreign.
	ownFamily, ownTable = "inet", "anixops_fwd"
)

// IsCheck reports whether action is a forward check.
func IsCheck(action string) bool {
	switch action {
	case CheckListen, CheckPortConflict, CheckConnect, CheckUDPProbe:
		return true
	}
	return false
}

// CheckResult is a check's answer: the "result" member of the
// agent.diagnostic state.
type CheckResult struct {
	Check      string      `json:"check"`
	RouteID    string      `json:"route_id"`
	HopIndex   uint32      `json:"hop_index"`
	Generation uint64      `json:"generation"`
	Status     string      `json:"status"`
	Code       string      `json:"code,omitempty"`
	Message    string      `json:"message,omitempty"`
	Items      []CheckItem `json:"items,omitempty"`
}

// CheckItem is one listener, port claim or upstream a check looked at.
type CheckItem struct {
	Target   string `json:"target"`
	Protocol string `json:"protocol,omitempty"`
	Status   string `json:"status"`
	Code     string `json:"code,omitempty"`
	Message  string `json:"message,omitempty"`
	RTTMicro uint32 `json:"rtt_us,omitempty"`
}

// CheckParams are a check's parameters, as Control normalized them.
type CheckParams struct {
	RouteID      string
	HopIndex     uint32
	Generation   uint64
	Timeout      time.Duration
	Upstream     string
	AllowPrivate bool
}

// ParseCheckParams reads a task's parameters.
func ParseCheckParams(params map[string]any) (CheckParams, error) {
	var p CheckParams
	p.RouteID, _ = params["route_id"].(string)
	if p.RouteID == "" {
		return p, errors.New("route_id is required")
	}
	index, ok := number(params["hop_index"])
	if !ok || index < 0 || index > 7 {
		return p, errors.New("hop_index must be an integer from 0 to 7")
	}
	p.HopIndex = uint32(index) // #nosec G115 -- bounded above.
	if generation, ok := number(params["generation"]); ok && generation > 0 {
		p.Generation = uint64(generation) // #nosec G115 -- positive.
	}
	p.Timeout = defaultCheckTimeout
	if timeout, ok := number(params["timeout_ms"]); ok {
		p.Timeout = min(max(time.Duration(timeout)*time.Millisecond, minCheckTimeout), maxCheckTimeout)
	}
	p.Upstream, _ = params["upstream"].(string)
	policy, _ := params["target_policy"].(string)
	switch policy {
	case "", "public_only":
	case "allow_private":
		p.AllowPrivate = true
	default:
		return p, fmt.Errorf("target_policy %q is unknown", policy)
	}
	return p, nil
}

func number(raw any) (int64, bool) {
	switch v := raw.(type) {
	case float64:
		if v != float64(int64(v)) {
			return 0, false
		}
		return int64(v), true
	case int:
		return int64(v), true
	case int64:
		return v, true
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	}
	return 0, false
}

// Diagnose runs one forward check. An error means the check could not
// run (an unknown action, malformed parameters); what a check finds is in
// the result.
func (c *Component) Diagnose(ctx context.Context, action string, params map[string]any) (*CheckResult, error) {
	if !IsCheck(action) {
		return nil, fmt.Errorf("%q is not a forward check", action)
	}
	p, err := ParseCheckParams(params)
	if err != nil {
		return nil, err
	}
	state := c.desiredState()
	result := &CheckResult{Check: action, RouteID: p.RouteID, HopIndex: p.HopIndex, Generation: state.GetGeneration()}
	var hop *forwardv1.NodeHop
	for _, h := range state.GetHops() {
		if h.GetRouteId() == p.RouteID && h.GetHopIndex() == p.HopIndex {
			hop = h
			break
		}
	}
	if hop == nil {
		result.Status, result.Code = VerdictFailed, "hop_not_applied"
		result.Message = fmt.Sprintf("the node's state (generation %d) does not hold route %s hop %d", state.GetGeneration(), p.RouteID, p.HopIndex)
		return result, nil
	}
	switch action {
	case CheckListen:
		c.checkListen(ctx, hop, result)
	case CheckPortConflict:
		c.checkPortConflict(ctx, hop, result)
	case CheckConnect, CheckUDPProbe:
		c.checkUpstreams(ctx, hop, p, action == CheckUDPProbe, result)
	}
	if len(result.Items) > maxCheckItems {
		result.Items = result.Items[:maxCheckItems]
	}
	if result.Status == "" {
		result.Status = aggregate(result.Items)
	}
	if p.Generation != 0 && p.Generation != state.GetGeneration() && result.Message == "" {
		result.Message = fmt.Sprintf("the node holds generation %d, Control wants %d", state.GetGeneration(), p.Generation)
	}
	return result, nil
}

// aggregate is failed when an item failed, else inconclusive when one is,
// else ok; skipped when every item was skipped.
func aggregate(items []CheckItem) string {
	verdict, skipped := VerdictOK, 0
	for _, item := range items {
		switch item.Status {
		case VerdictFailed:
			return VerdictFailed
		case VerdictInconclusive:
			verdict = VerdictInconclusive
		case VerdictSkipped:
			skipped++
		}
	}
	if len(items) > 0 && skipped == len(items) {
		return VerdictSkipped
	}
	return verdict
}

func protocols(listen *forwardv1.Listen) []string {
	switch listen.GetProtocol() {
	case forwardv1.L4Protocol_L4_PROTOCOL_UDP:
		return []string{"udp"}
	case forwardv1.L4Protocol_L4_PROTOCOL_TCP_UDP:
		return []string{"tcp", "udp"}
	}
	return []string{"tcp"}
}

// hopProtocols answers the socket protocols a hop's listener holds: the
// route's, except for an anixops carrier listener, whose sockets are the
// carrier's (TCP for TLS_TCP and PLAIN, UDP for QUIC, both for AUTO).
func hopProtocols(hop *forwardv1.NodeHop) []string {
	if hop.GetEngine() == forwardv1.Engine_ENGINE_ANIXOPS && hop.GetIngress().GetSecurity() == forwardv1.LinkSecurity_LINK_SECURITY_ANIXOPS {
		switch hop.GetIngress().GetCarrier() {
		case forwardv1.AnixOpsCarrier_ANIXOPS_CARRIER_QUIC:
			return []string{"udp"}
		case forwardv1.AnixOpsCarrier_ANIXOPS_CARRIER_TLS_TCP, forwardv1.AnixOpsCarrier_ANIXOPS_CARRIER_PLAIN:
			return []string{"tcp"}
		}
		return []string{"tcp", "udp"}
	}
	return protocols(hop.GetListen())
}

// socketProcess answers the process name whose sockets an engine's hops are,
// or "" for an engine without sockets of its own (nftables).
func socketProcess(engine forwardv1.Engine) string {
	switch engine {
	case forwardv1.Engine_ENGINE_GOST:
		return "gost"
	case forwardv1.Engine_ENGINE_ANIXOPS:
		return "anixops-relay"
	}
	return ""
}

func listenTarget(listen *forwardv1.Listen) string {
	address := listen.GetAddress()
	if address == "" {
		address = "*"
	}
	return net.JoinHostPort(address, strconv.FormatUint(uint64(listen.GetPort()), 10))
}

func (c *Component) hopError(hop *forwardv1.NodeHop) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, he := range c.hopErrors {
		if he.GetRouteId() == hop.GetRouteId() && he.GetHopIndex() == hop.GetHopIndex() {
			return he.GetMessage()
		}
	}
	return ""
}

// checkListen: the hop's own listener holds its port. nftables has no
// socket: the driver running the hop (its rules in inet anixops_fwd) is
// the listener. gost's and the anixops relay's listeners are sockets on the
// port (hopProtocols says which).
func (c *Component) checkListen(ctx context.Context, hop *forwardv1.NodeHop, result *CheckResult) {
	if message := c.hopError(hop); message != "" {
		result.Status, result.Code, result.Message = VerdictFailed, "hop_error", message
		return
	}
	target := listenTarget(hop.GetListen())
	if process := socketProcess(hop.GetEngine()); process != "" {
		socks, err := c.sockets(ctx, false)
		if err != nil {
			result.Status, result.Code, result.Message = VerdictInconclusive, "ss_unavailable", err.Error()
			return
		}
		for _, proto := range hopProtocols(hop) {
			item := CheckItem{Target: target, Protocol: proto, Status: VerdictFailed, Code: "not_listening", Message: "no socket is bound to the port"}
			for _, s := range socks {
				if s.matches(proto, hop.GetListen()) {
					item = CheckItem{Target: target, Protocol: proto, Status: VerdictOK, Code: "listening", Message: process + " listens"}
					break
				}
			}
			result.Items = append(result.Items, item)
		}
		return
	}
	d, ok := c.opts.Registry.Get(hop.GetEngine())
	if !ok {
		result.Status, result.Code, result.Message = VerdictFailed, "hop_error", "no driver runs "+hop.GetEngine().String()+" on this node"
		return
	}
	obs, err := d.Observe(ctx)
	if err != nil {
		result.Status, result.Code, result.Message = VerdictInconclusive, "observe_failed", err.Error()
		return
	}
	running := false
	for _, counter := range obs.Counters {
		if counter.GetRouteId() == hop.GetRouteId() && counter.GetHopIndex() == hop.GetHopIndex() {
			running = true
			break
		}
	}
	for _, proto := range protocols(hop.GetListen()) {
		item := CheckItem{Target: target, Protocol: proto, Status: VerdictOK, Code: "listening", Message: "the hop's rules are in " + ownFamily + " " + ownTable}
		if !obs.Applied || !running {
			item.Status, item.Code, item.Message = VerdictFailed, "not_listening", "the driver does not run the hop"
		}
		result.Items = append(result.Items, item)
	}
}

// checkPortConflict: no socket of another process and no rule of another
// nftables table claims the hop's listen port.
func (c *Component) checkPortConflict(ctx context.Context, hop *forwardv1.NodeHop, result *CheckResult) {
	listen := hop.GetListen()
	port := listen.GetPort()
	socks, err := c.sockets(ctx, true)
	if err != nil {
		result.Items = append(result.Items, CheckItem{Target: listenTarget(listen), Status: VerdictInconclusive, Code: "ss_unavailable", Message: err.Error()})
	}
	for _, proto := range hopProtocols(hop) {
		for _, s := range socks {
			if !s.matches(proto, listen) {
				continue
			}
			if own := socketProcess(hop.GetEngine()); own != "" && (s.process == "" || s.process == own) {
				// The engine's own socket (or one ss cannot name, which its
				// driver already refused to share on its apply).
				continue
			}
			who := s.process
			if who == "" {
				who = "a process"
			}
			result.Items = append(result.Items, CheckItem{Target: s.local, Protocol: proto, Status: VerdictFailed, Code: "foreign_listener",
				Message: fmt.Sprintf("%s listens on %s port %d", who, proto, port)})
		}
	}
	rules, err := c.foreignNATRules(ctx, port, hopProtocols(hop))
	if err != nil {
		result.Items = append(result.Items, CheckItem{Target: listenTarget(listen), Status: VerdictInconclusive, Code: "nft_unavailable", Message: err.Error()})
	}
	for _, rule := range rules {
		result.Items = append(result.Items, CheckItem{Target: listenTarget(listen), Protocol: rule.proto, Status: VerdictFailed, Code: "foreign_nat_rule",
			Message: fmt.Sprintf("table %s %s chain %s rewrites destination port %d", rule.family, rule.table, rule.chain, port)})
	}
	if len(result.Items) == 0 {
		result.Status = VerdictOK
		result.Message = fmt.Sprintf("no foreign listener or nat rule claims port %d", port)
	}
}

// targetPolicy is the stricter of the hop's policy and Control's.
func targetPolicy(hop *forwardv1.NodeHop, allowPrivate bool) model.TargetPolicy {
	if allowPrivate && hop.GetTargetPolicy() == forwardv1.TargetPolicy_TARGET_POLICY_ALLOW_PRIVATE {
		return model.TargetPolicyAllowPrivate
	}
	return model.TargetPolicyPublicOnly
}

// checkUpstreams dials each of the hop's upstreams at once: a TCP connect,
// or one datagram and a wait for any reply.
func (c *Component) checkUpstreams(ctx context.Context, hop *forwardv1.NodeHop, p CheckParams, udp bool, result *CheckResult) {
	var upstreams []*forwardv1.Upstream
	for _, u := range hop.GetUpstreams() {
		if p.Upstream == "" || net.JoinHostPort(u.GetAddress(), strconv.FormatUint(uint64(u.GetPort()), 10)) == p.Upstream {
			upstreams = append(upstreams, u)
		}
	}
	if len(upstreams) == 0 {
		result.Status, result.Code = VerdictFailed, "unknown_upstream"
		result.Message = fmt.Sprintf("%s is not an upstream of the hop", p.Upstream)
		if p.Upstream == "" {
			result.Code, result.Message = "no_upstream", "the hop has no upstream"
		}
		return
	}
	policy := targetPolicy(hop, p.AllowPrivate)
	items := make([]CheckItem, len(upstreams))
	var wg sync.WaitGroup
	for i, u := range upstreams {
		wg.Add(1)
		go func(i int, u *forwardv1.Upstream) {
			defer wg.Done()
			items[i] = c.probeUpstream(ctx, u, policy, p.Timeout, udp)
		}(i, u)
	}
	wg.Wait()
	result.Items = items
	verb := "reachable"
	if udp {
		verb = "answered"
	}
	result.Message = fmt.Sprintf("%d of %d upstreams %s", countStatus(items, VerdictOK), len(items), verb)
}

func countStatus(items []CheckItem, status string) int {
	n := 0
	for _, item := range items {
		if item.Status == status {
			n++
		}
	}
	return n
}

func (c *Component) probeUpstream(ctx context.Context, u *forwardv1.Upstream, policy model.TargetPolicy, timeout time.Duration, udp bool) CheckItem {
	port := strconv.FormatUint(uint64(u.GetPort()), 10)
	item := CheckItem{Target: net.JoinHostPort(u.GetAddress(), port), Protocol: "tcp"}
	if udp {
		item.Protocol = "udp"
	}
	if u.GetNodeRef() != "" {
		// A next hop listens on its link's carrier: QUIC has no TCP
		// listener, and TLS, WSS and gRPC no UDP one.
		security := u.GetEgress().GetSecurity()
		quic := security == forwardv1.LinkSecurity_LINK_SECURITY_QUIC
		raw := security == forwardv1.LinkSecurity_LINK_SECURITY_UNSPECIFIED || security == forwardv1.LinkSecurity_LINK_SECURITY_RAW
		if !udp && quic {
			item.Status, item.Code, item.Message = VerdictSkipped, "link_not_tcp", "the link to the next hop is QUIC: no TCP listener to connect to"
			return item
		}
		if udp && !raw && !quic {
			item.Status, item.Code, item.Message = VerdictSkipped, "link_not_udp", "the link to the next hop is "+security.String()+": no UDP listener to probe"
			return item
		}
	}
	dialTo := u.GetAddress()
	if u.GetNodeRef() == "" {
		// A target: every address it resolves to must pass the policy.
		addrs, err := c.resolve(ctx, u.GetAddress(), timeout)
		if err != nil {
			item.Status, item.Code, item.Message = VerdictFailed, "resolve_failed", err.Error()
			return item
		}
		dialTo = ""
		var refusal error
		for _, addr := range addrs {
			if err := validate.CheckTargetAddress(addr, policy); err != nil {
				refusal = err
				continue
			}
			if dialTo == "" {
				dialTo = addr.Unmap().String()
			}
		}
		if refusal != nil {
			// One refused address refuses the target, as the drivers do.
			item.Status, item.Code, item.Message = VerdictSkipped, "target_not_allowed", "not probed: "+refusal.Error()
			return item
		}
	}
	address := net.JoinHostPort(dialTo, port)
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	network := "tcp"
	if udp {
		network = "udp"
	}
	began := time.Now()
	conn, err := c.opts.Dial(dialCtx, network, address)
	if err != nil {
		item.Status, item.Code, item.Message = VerdictFailed, "unreachable", err.Error()
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			item.Code = "timeout"
		}
		return item
	}
	defer func() { _ = conn.Close() }()
	if !udp {
		item.Status, item.Code, item.RTTMicro = VerdictOK, "reachable", micros(time.Since(began))
		return item
	}
	deadline, _ := dialCtx.Deadline()
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte(udpProbePayload)); err != nil {
		item.Status, item.Code, item.Message = VerdictFailed, "unreachable", err.Error()
		return item
	}
	buffer := make([]byte, 512)
	if _, err := conn.Read(buffer); err != nil {
		switch {
		case errors.Is(err, syscall.ECONNREFUSED):
			item.Status, item.Code, item.Message = VerdictFailed, "port_unreachable", "ICMP port unreachable"
		case isTimeout(err) || errors.Is(err, context.DeadlineExceeded):
			item.Status, item.Code, item.Message = VerdictInconclusive, "no_reply", "no reply within the timeout (a UDP service need not answer)"
		default:
			item.Status, item.Code, item.Message = VerdictInconclusive, "no_reply", err.Error()
		}
		return item
	}
	item.Status, item.Code, item.RTTMicro = VerdictOK, "reply", micros(time.Since(began))
	return item
}

func micros(d time.Duration) uint32 {
	return uint32(min(max(d.Microseconds(), 1), 1<<32-1)) // #nosec G115 -- bounded.
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func (c *Component) resolve(ctx context.Context, host string, timeout time.Duration) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	lookup := c.opts.Lookup
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	addrs, err := lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%s has no address", host)
	}
	return addrs, nil
}

// run runs a read-only host command (ss, nft).
func (c *Component) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if c.opts.Run != nil {
		return c.opts.Run(ctx, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- fixed read-only commands with fixed arguments.
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if message := strings.TrimSpace(stderr.String()); message != "" {
			return nil, fmt.Errorf("%s: %w: %s", name, err, firstLine(message))
		}
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// hostSocket is a listening TCP or bound UDP socket of the host.
type hostSocket struct {
	network string
	// addr is invalid for a wildcard.
	addr    netip.Addr
	port    uint32
	local   string
	process string
}

func (s hostSocket) matches(proto string, listen *forwardv1.Listen) bool {
	if s.network != proto || s.port != listen.GetPort() {
		return false
	}
	if !s.addr.IsValid() || listen.GetAddress() == "" {
		return true
	}
	a, err := netip.ParseAddr(listen.GetAddress())
	return err == nil && a.Unmap() == s.addr
}

// sockets lists the host's listening sockets (ss -H -l -n -t -u, with -p
// for the process names ss may show).
func (c *Component) sockets(ctx context.Context, processes bool) ([]hostSocket, error) {
	args := []string{"-H", "-l", "-n", "-t", "-u"}
	if processes {
		args = append(args, "-p")
	}
	ss := c.opts.SS
	if ss == "" {
		ss = "ss"
	}
	out, err := c.run(ctx, ss, args...)
	if err != nil {
		return nil, err
	}
	return parseSockets(out), nil
}

// parseSockets reads ss's listing: "Netid State Recv-Q Send-Q Local:Port
// Peer:Port [Process]". Lines it cannot read are skipped.
func parseSockets(out []byte) []hostSocket {
	var socks []hostSocket
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || (f[0] != "tcp" && f[0] != "udp") {
			continue
		}
		local := f[4]
		i := strings.LastIndexByte(local, ':')
		if i < 0 {
			continue
		}
		port, err := strconv.ParseUint(local[i+1:], 10, 16)
		if err != nil {
			continue
		}
		host := strings.TrimSuffix(strings.TrimPrefix(local[:i], "["), "]")
		if j := strings.IndexByte(host, '%'); j >= 0 {
			host = host[:j]
		}
		s := hostSocket{network: f[0], port: uint32(port), local: local}
		if host != "*" {
			a, err := netip.ParseAddr(host)
			if err != nil {
				continue
			}
			if a = a.Unmap(); !a.IsUnspecified() {
				s.addr = a
			}
		}
		if len(f) > 6 {
			s.process = processName(strings.Join(f[6:], " "))
		}
		socks = append(socks, s)
	}
	return socks
}

// processName reads the first name of ss's users:(("gost",pid=1,fd=3)).
func processName(field string) string {
	i := strings.Index(field, `(("`)
	if i < 0 {
		return ""
	}
	rest := field[i+3:]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// natRule is a foreign rule that rewrites the destination of a port.
type natRule struct {
	family, table, chain, proto string
}

// foreignNATRules reads the whole ruleset (read only) and answers the rules
// of other tables that rewrite destinations (dnat, redirect, tproxy, or
// iptables-nft's DNAT, REDIRECT and TPROXY targets) and match port, as the
// nftables driver's conflict detection does before an apply. Named sets
// and rules nft cannot decode are not followed.
func (c *Component) foreignNATRules(ctx context.Context, port uint32, protos []string) ([]natRule, error) {
	nft := c.opts.NFT
	if nft == "" {
		nft = "nft"
	}
	out, err := c.run(ctx, nft, "-j", "list", "ruleset")
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(out))
	decoder.UseNumber()
	var listing struct {
		Nftables []map[string]any `json:"nftables"`
	}
	if err := decoder.Decode(&listing); err != nil {
		return nil, fmt.Errorf("nft printed an unreadable ruleset: %w", err)
	}
	var rules []natRule
	seen := map[natRule]bool{}
	for _, item := range listing.Nftables {
		rule, ok := item["rule"].(map[string]any)
		if !ok {
			continue
		}
		family, _ := rule["family"].(string)
		table, _ := rule["table"].(string)
		chain, _ := rule["chain"].(string)
		if family == ownFamily && table == ownTable {
			continue
		}
		exprs, _ := rule["expr"].([]any)
		if !rewritesDestination(exprs) {
			continue
		}
		for _, m := range destinationPorts(exprs) {
			if uint64(port) < m.lo || uint64(port) > m.hi {
				continue
			}
			for _, proto := range protos {
				if m.proto == "tcp" && proto != "tcp" || m.proto == "udp" && proto != "udp" {
					continue
				}
				r := natRule{family: family, table: table, chain: chain, proto: proto}
				if !seen[r] {
					seen[r] = true
					rules = append(rules, r)
				}
			}
		}
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].family+rules[i].table+rules[i].chain+rules[i].proto < rules[j].family+rules[j].table+rules[j].chain+rules[j].proto
	})
	return rules, nil
}

func rewritesDestination(exprs []any) bool {
	for _, e := range exprs {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		for _, k := range []string{"dnat", "redirect", "tproxy"} {
			if _, ok := m[k]; ok {
				return true
			}
		}
		if xt, ok := m["xt"].(map[string]any); ok {
			if name, _ := xt["name"].(string); name == "DNAT" || name == "REDIRECT" || name == "TPROXY" {
				return true
			}
		}
	}
	return false
}

type portMatch struct {
	proto  string
	lo, hi uint64
}

func destinationPorts(exprs []any) []portMatch {
	var out []portMatch
	for _, e := range exprs {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		match, ok := m["match"].(map[string]any)
		if !ok {
			continue
		}
		if op, _ := match["op"].(string); op != "==" && op != "in" {
			continue
		}
		left, _ := match["left"].(map[string]any)
		payload, _ := left["payload"].(map[string]any)
		if field, _ := payload["field"].(string); field != "dport" {
			continue
		}
		proto, _ := payload["protocol"].(string)
		for _, r := range portRanges(match["right"]) {
			out = append(out, portMatch{proto: proto, lo: r[0], hi: r[1]})
		}
	}
	return out
}

func portRanges(v any) [][2]uint64 {
	switch x := v.(type) {
	case json.Number:
		if n, err := strconv.ParseUint(x.String(), 10, 16); err == nil {
			return [][2]uint64{{n, n}}
		}
	case map[string]any:
		if r, ok := x["range"].([]any); ok && len(r) == 2 {
			lo, hi := portRanges(r[0]), portRanges(r[1])
			if len(lo) == 1 && len(hi) == 1 {
				return [][2]uint64{{lo[0][0], hi[0][1]}}
			}
		}
		if s, ok := x["set"].([]any); ok {
			var out [][2]uint64
			for _, e := range s {
				out = append(out, portRanges(e)...)
			}
			return out
		}
	case []any:
		var out [][2]uint64
		for _, e := range x {
			out = append(out, portRanges(e)...)
		}
		return out
	}
	return nil
}

// IsCheck reports whether action is a forward check (diagnostic.Checker).
func (c *Component) IsCheck(action string) bool { return IsCheck(action) }

// Check runs a forward check for the agent.diagnostic executor
// (diagnostic.Checker): the result, its verdict and its summary.
func (c *Component) Check(ctx context.Context, action string, params map[string]any) (any, string, string, error) {
	result, err := c.Diagnose(ctx, action, params)
	if err != nil {
		return nil, "", "", err
	}
	return result, result.Status, result.Message, nil
}
