package panel

import (
	"encoding/json"
	"fmt"
	"strings"
)

// EgressProtocolShadowsocks is the relay protocol of Control's egress
// routes today: Shadowsocks 2022 with the route's method and key.
const EgressProtocolShadowsocks = "shadowsocks"

// EgressConfig is the member "egress" of a node's configuration document
// (anixops.nodeconfig/v1, Control's egress routes): the domains this node
// sends out through another node, and the relay inbounds this node serves
// for the nodes that send their traffic out here. Nil or empty when the
// node takes part in no egress route.
//
// The member names no kernel: each core that runs it (vCore.EgressApplier;
// Xray today, networkcore later) translates the domains and relays into
// its own routing, and refuses a relay protocol it does not speak.
type EgressConfig struct {
	// Routes send the traffic to Domains through Server instead of this
	// node's own exit.
	Routes []EgressRoute `json:"routes"`
	// Relays are the inbounds the source nodes of this node's egress
	// routes connect to.
	Relays []EgressRelay `json:"relays"`
}

// EgressRoute is one egress route of a source node.
type EgressRoute struct {
	ID      uint64   `json:"id"`
	Domains []string `json:"domains"`
	// Server is the exit node's relay inbound.
	Server EgressServer `json:"server"`
}

// EgressServer is the relay inbound a source node connects to.
type EgressServer struct {
	// Protocol is the relay's protocol; empty is EgressProtocolShadowsocks.
	Protocol string `json:"protocol,omitempty"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Method   string `json:"method"`
	Password string `json:"password"`
}

// EgressRelay is a relay inbound an exit node serves for one egress route.
type EgressRelay struct {
	ID uint64 `json:"id"`
	// Protocol is the relay's protocol; empty is EgressProtocolShadowsocks.
	Protocol string `json:"protocol,omitempty"`
	Port     int    `json:"port"`
	Method   string `json:"method"`
	Password string `json:"password"`
}

// Empty tells whether the configuration asks for nothing.
func (c *EgressConfig) Empty() bool {
	return c == nil || (len(c.Routes) == 0 && len(c.Relays) == 0)
}

// ParseEgress reads the member "egress" of a configuration document. A
// document without it, or with null, has none (nil, nil).
func ParseEgress(document []byte) (*EgressConfig, error) {
	var holder struct {
		Egress *EgressConfig `json:"egress"`
	}
	if err := json.Unmarshal(document, &holder); err != nil {
		return nil, fmt.Errorf("decode the egress member: %w", err)
	}
	if holder.Egress == nil {
		return nil, nil
	}
	if err := holder.Egress.Validate(); err != nil {
		return nil, err
	}
	return holder.Egress, nil
}

// Validate checks every route and relay: ids are unique, ports are valid,
// a route has domains and a server, and every entry has a method and a
// password.
func (c *EgressConfig) Validate() error {
	if c == nil {
		return nil
	}
	seen := map[uint64]bool{}
	for _, route := range c.Routes {
		if route.ID == 0 || seen[route.ID] {
			return fmt.Errorf("egress route %d: the id is missing or repeated", route.ID)
		}
		seen[route.ID] = true
		if len(route.Domains) == 0 {
			return fmt.Errorf("egress route %d: no domains", route.ID)
		}
		for _, domain := range route.Domains {
			if strings.TrimSpace(domain) == "" {
				return fmt.Errorf("egress route %d: an empty domain", route.ID)
			}
		}
		if strings.TrimSpace(route.Server.Host) == "" {
			return fmt.Errorf("egress route %d: the server has no host", route.ID)
		}
		if err := checkEgressEndpoint(route.Server.Port, route.Server.Method, route.Server.Password); err != nil {
			return fmt.Errorf("egress route %d: %w", route.ID, err)
		}
	}
	seen = map[uint64]bool{}
	for _, relay := range c.Relays {
		if relay.ID == 0 || seen[relay.ID] {
			return fmt.Errorf("egress relay %d: the id is missing or repeated", relay.ID)
		}
		seen[relay.ID] = true
		if err := checkEgressEndpoint(relay.Port, relay.Method, relay.Password); err != nil {
			return fmt.Errorf("egress relay %d: %w", relay.ID, err)
		}
	}
	return nil
}

// EgressProtocol is a relay's protocol with the default filled in.
func EgressProtocol(protocol string) string {
	if protocol == "" {
		return EgressProtocolShadowsocks
	}
	return protocol
}

func checkEgressEndpoint(port int, method, password string) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %d", port)
	}
	if strings.TrimSpace(method) == "" {
		return fmt.Errorf("no method")
	}
	if password == "" {
		return fmt.Errorf("no password")
	}
	return nil
}
