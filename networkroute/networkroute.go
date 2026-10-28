// Package networkroute installs the policy routing of the device network
// model's egresses (anix-control docs/design/network-model §6.5): an egress
// whose source is an address of a line other than the default one leaves
// through that line only when its packets are routed there, so each such
// egress gets
//
//	ip route replace default [via <gateway>] dev <interface> src <source> table <T>
//	ip rule add from <source>/<32|128> table <T> priority <P>
//
// The Agent owns a table and rule-priority range (default 20000–20999,
// DeviceCapabilities.routing_first/last): every rule with a priority in it
// is the Agent's, and Apply removes the ones the plan no longer has (and
// flushes their tables), also those an earlier Agent process left. An
// egress with source "auto" leaves through the default route and needs
// none.
package networkroute

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"

	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
	"github.com/AnixOps/anix-control/sdk/network"
)

// Route is one egress's routing.
type Route struct {
	Egress    string
	Source    netip.Addr
	Interface string
	// Gateway is invalid for an on-link default route.
	Gateway  netip.Addr
	Table    uint32
	Priority uint32
}

func (r Route) family() string {
	if r.Source.Is4() {
		return "-4"
	}
	return "-6"
}

func (r Route) from() string {
	return netip.PrefixFrom(r.Source, r.Source.BitLen()).String()
}

// Routes answers the routing plan needs in the range first–last: one
// Route per egress with an address source, in egress id order. A table or
// priority the egress names is kept; the others take the lowest numbers of
// the range no other egress uses.
func Routes(plan *networkv1.NetworkPlan, first, last uint32) ([]Route, error) {
	lines := map[string]*networkv1.Line{}
	for _, line := range plan.GetLines() {
		lines[line.GetId()] = line
	}
	var routes []Route
	tables, priorities := map[uint32]bool{}, map[uint32]bool{}
	for _, egress := range plan.GetEgresses() {
		source := egress.GetSource()
		if source == "" || source == network.SourceAuto {
			continue
		}
		address, err := netip.ParseAddr(source)
		if err != nil {
			return nil, fmt.Errorf("egress %s: source %q: %w", egress.GetId(), source, err)
		}
		line := lines[egress.GetLineId()]
		if line.GetInterface() == "" {
			return nil, fmt.Errorf("egress %s: line %q has no interface", egress.GetId(), egress.GetLineId())
		}
		route := Route{Egress: egress.GetId(), Source: address.Unmap(), Interface: line.GetInterface(),
			Table: egress.GetRouting().GetTable(), Priority: egress.GetRouting().GetRulePriority()}
		gateway := egress.GetGateway()
		if gateway == "" {
			gateway = line.GetGatewayV4()
			if route.Source.Is6() {
				gateway = line.GetGatewayV6()
			}
		}
		if gateway != "" {
			if route.Gateway, err = netip.ParseAddr(gateway); err != nil {
				return nil, fmt.Errorf("egress %s: gateway %q: %w", egress.GetId(), gateway, err)
			}
		}
		for _, number := range []uint32{route.Table, route.Priority} {
			if number != 0 && (number < first || number > last) {
				return nil, fmt.Errorf("egress %s: table or priority %d is outside %d–%d", egress.GetId(), number, first, last)
			}
		}
		if route.Table != 0 {
			tables[route.Table] = true
		}
		if route.Priority != 0 {
			priorities[route.Priority] = true
		}
		routes = append(routes, route)
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Egress < routes[j].Egress })
	next := func(used map[uint32]bool) (uint32, error) {
		for number := first; number <= last; number++ {
			if !used[number] {
				used[number] = true
				return number, nil
			}
		}
		return 0, fmt.Errorf("the routing range %d–%d is full", first, last)
	}
	for i := range routes {
		var err error
		if routes[i].Table == 0 {
			if routes[i].Table, err = next(tables); err != nil {
				return nil, err
			}
		}
		if routes[i].Priority == 0 {
			if routes[i].Priority, err = next(priorities); err != nil {
				return nil, err
			}
		}
	}
	return routes, nil
}

// Runner runs a command and answers its standard output.
type Runner func(name string, args ...string) ([]byte, error)

// Run runs a command on the host.
func Run(name string, args ...string) ([]byte, error) {
	out, err := exec.Command(name, args...).Output() // #nosec G204 -- the ip binary with arguments built here.
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return out, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return out, nil
}

// Manager installs routes with the ip command.
type Manager struct {
	// IP is the ip binary ("ip").
	IP string
	// Run runs it (Run).
	Run Runner
	// First and Last bound the tables and priorities the Agent owns.
	First, Last uint32

	mu sync.Mutex
}

// rule is a rule of `ip -j rule show`.
type rule struct {
	Priority uint32 `json:"priority"`
	Src      string `json:"src"`
	SrcLen   int    `json:"srclen"`
	Table    string `json:"table"`
}

// Apply makes the host's rules in the range exactly routes: each route's
// table gets its default route and its rule, and every other rule in the
// range is deleted with its table flushed.
func (m *Manager) Apply(routes []Route) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var failed error
	for _, family := range []string{"-4", "-6"} {
		current, err := m.rules(family)
		if err != nil {
			return err
		}
		wanted := map[string]bool{}
		for _, route := range routes {
			if route.family() == family {
				wanted[ruleKey(route.Priority, route.from(), strconv.FormatUint(uint64(route.Table), 10))] = true
			}
		}
		present := map[string]bool{}
		for _, existing := range current {
			from := existing.Src
			if from != "" && existing.SrcLen > 0 {
				from += "/" + strconv.Itoa(existing.SrcLen)
			}
			key := ruleKey(existing.Priority, from, existing.Table)
			if wanted[key] {
				present[key] = true
				continue
			}
			args := []string{family, "rule", "delete", "priority", strconv.FormatUint(uint64(existing.Priority), 10)}
			if from != "" {
				args = append(args, "from", from)
			}
			if existing.Table != "" {
				args = append(args, "table", existing.Table)
			}
			if _, err := m.Run(m.ip(), args...); err != nil {
				failed = errors.Join(failed, err)
			}
			if table, err := strconv.ParseUint(existing.Table, 10, 32); err == nil && m.owns(uint32(table)) {
				if _, err := m.Run(m.ip(), family, "route", "flush", "table", existing.Table); err != nil {
					failed = errors.Join(failed, err)
				}
			}
		}
		for _, route := range routes {
			if route.family() != family {
				continue
			}
			table := strconv.FormatUint(uint64(route.Table), 10)
			args := []string{family, "route", "replace", "default"}
			if route.Gateway.IsValid() {
				args = append(args, "via", route.Gateway.String())
			}
			args = append(args, "dev", route.Interface, "src", route.Source.String(), "table", table)
			if _, err := m.Run(m.ip(), args...); err != nil {
				failed = errors.Join(failed, fmt.Errorf("egress %s: %w", route.Egress, err))
				continue
			}
			if present[ruleKey(route.Priority, route.from(), table)] {
				continue
			}
			if _, err := m.Run(m.ip(), family, "rule", "add", "from", route.from(), "table", table,
				"priority", strconv.FormatUint(uint64(route.Priority), 10)); err != nil {
				failed = errors.Join(failed, fmt.Errorf("egress %s: %w", route.Egress, err))
			}
		}
	}
	return failed
}

func (m *Manager) ip() string {
	if m.IP == "" {
		return "ip"
	}
	return m.IP
}

func (m *Manager) owns(number uint32) bool {
	return number >= m.First && number <= m.Last
}

// rules lists the family's rules with a priority in the range.
func (m *Manager) rules(family string) ([]rule, error) {
	out, err := m.Run(m.ip(), "-j", family, "rule", "show")
	if err != nil {
		return nil, err
	}
	var all []rule
	if len(strings.TrimSpace(string(out))) > 0 {
		if err := json.Unmarshal(out, &all); err != nil {
			return nil, fmt.Errorf("ip -j %s rule show: %w", family, err)
		}
	}
	var owned []rule
	for _, r := range all {
		if m.owns(r.Priority) {
			owned = append(owned, r)
		}
	}
	return owned, nil
}

func ruleKey(priority uint32, from, table string) string {
	return strconv.FormatUint(uint64(priority), 10) + " " + from + " " + table
}
