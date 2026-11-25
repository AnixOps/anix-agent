package panel

import (
	"encoding/json"
	"fmt"
)

// ControlRouteMember is the configuration member that carries a node's
// region relay route (anix-control internal/relayroute).
const ControlRouteMember = "control_route"

// ControlRoute is the member "control_route": the region relays the node
// reaches Control through, never directly, and the release caches it
// downloads releases from.
//
// Contract with Control (R34): no member keeps the route the Agent has;
// empty or missing relays never mean "reach Control directly" (the Agent
// keeps its relays and warns); only Direct does.
type ControlRoute struct {
	Relays        []string `json:"relays"`
	ReleaseCaches []string `json:"release_caches"`
	Direct        bool     `json:"direct"`
}

// ParseControlRoute reads the member "control_route" of a configuration
// document; nil when the document has none.
func ParseControlRoute(document []byte) (*ControlRoute, error) {
	var holder struct {
		Route *ControlRoute `json:"control_route"`
	}
	if len(document) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(document, &holder); err != nil {
		return nil, fmt.Errorf("decode the %s member: %w", ControlRouteMember, err)
	}
	return holder.Route, nil
}
