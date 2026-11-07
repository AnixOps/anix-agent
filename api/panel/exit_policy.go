package panel

import (
	"encoding/json"
	"fmt"
)

// ExitPolicy is the member "exit_policy" of a configuration document: what
// an exit node refuses. Control sends it only when something is on.
type ExitPolicy struct {
	// BlockMainland refuses connections to mainland-China addresses.
	BlockMainland bool `json:"block_mainland"`
}

// ParseExitPolicy reads the member "exit_policy" of a configuration
// document; a document without it has the zero policy.
func ParseExitPolicy(document []byte) (ExitPolicy, error) {
	var holder struct {
		ExitPolicy *ExitPolicy `json:"exit_policy"`
	}
	if err := json.Unmarshal(document, &holder); err != nil {
		return ExitPolicy{}, fmt.Errorf("decode the exit_policy member: %w", err)
	}
	if holder.ExitPolicy == nil {
		return ExitPolicy{}, nil
	}
	return *holder.ExitPolicy, nil
}
