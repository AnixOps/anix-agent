package panel

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// ParseQoS reads the member "qos" of a configuration document (Control's
// traffic priorities and per-user class caps, anix-control
// internal/trafficqos): the classes of destinations with a priority (high,
// normal, low) and an optional cap per user, and the node's download
// capacity. The member is passed to the core as it is; nil when the
// document has none or null, so the core turns its priorities off.
func ParseQoS(document []byte) (json.RawMessage, error) {
	var holder struct {
		QoS json.RawMessage `json:"qos"`
	}
	if err := json.Unmarshal(document, &holder); err != nil {
		return nil, fmt.Errorf("decode the qos member: %w", err)
	}
	trimmed := bytes.TrimSpace(holder.QoS)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	if trimmed[0] != '{' {
		return nil, fmt.Errorf("the qos member is not an object")
	}
	return trimmed, nil
}
