package forward

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// The persisted state: the NodeForwardState the component last accepted
// from Control, and whether every engine applies it. It lives in
// Options.StateDir (the Agent's own state, never gost's directory):
// stateFileName, mode 0600, in a directory of mode 0700. The Agent
// re-applies it at start, before it connects to Control, so forwarding
// comes back after a reboot (nftables rules do not survive one) and while
// Control is unreachable (forward-sdk.md sections 6.1 and 8.5).

const (
	stateFileName = "state.json"
	// stateFileVersion is the layout of the file.
	stateFileVersion = 1
)

// persisted is the file's layout.
type persisted struct {
	Version int    `json:"version"`
	NodeRef string `json:"node_ref"`
	// State is the NodeForwardState as protojson with the proto field
	// names (sdk/forward/wire's encoding).
	State   json.RawMessage `json:"state"`
	Applied bool            `json:"applied"`
	SavedAt time.Time       `json:"saved_at"`
}

var (
	stateMarshal   = protojson.MarshalOptions{UseProtoNames: true}
	stateUnmarshal = protojson.UnmarshalOptions{DiscardUnknown: true}
)

// stateStore reads and writes the persisted state.
type stateStore struct {
	dir     string
	nodeRef string
}

func openStateStore(dir, nodeRef string) (*stateStore, error) {
	if dir == "" || !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("forward: state directory %q must be an absolute path", dir)
	}
	dir = filepath.Clean(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("forward: create state directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("forward: state directory permissions: %w", err)
	}
	return &stateStore{dir: dir, nodeRef: nodeRef}, nil
}

func (s *stateStore) path() string { return filepath.Join(s.dir, stateFileName) }

// load answers the persisted state, nil without one. A file of another
// node (the Agent was re-registered) or that does not parse is discarded:
// Control sends the node's state again.
func (s *stateStore) load() (*forwardv1.NodeForwardState, bool, error) {
	data, err := os.ReadFile(s.path())
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("forward: read the persisted state: %w", err)
	}
	var file persisted
	if err := json.Unmarshal(data, &file); err != nil || file.Version != stateFileVersion {
		_ = s.discard()
		return nil, false, fmt.Errorf("forward: the persisted state is unreadable; discarded it")
	}
	if file.NodeRef != s.nodeRef {
		_ = s.discard()
		return nil, false, fmt.Errorf("forward: the persisted state is node %q's, not %q's; discarded it", file.NodeRef, s.nodeRef)
	}
	state := &forwardv1.NodeForwardState{}
	if err := stateUnmarshal.Unmarshal(file.State, state); err != nil {
		_ = s.discard()
		return nil, false, fmt.Errorf("forward: the persisted state does not parse; discarded it: %w", err)
	}
	return state, file.Applied, nil
}

// save writes the state atomically: a temporary file in the same
// directory, synced, then renamed over the old one.
func (s *stateStore) save(state *forwardv1.NodeForwardState, applied bool, now time.Time) error {
	encoded, err := stateMarshal.Marshal(state)
	if err != nil {
		return fmt.Errorf("forward: encode the state: %w", err)
	}
	data, err := json.Marshal(persisted{Version: stateFileVersion, NodeRef: s.nodeRef, State: encoded, Applied: applied, SavedAt: now.UTC()})
	if err != nil {
		return fmt.Errorf("forward: encode the state file: %w", err)
	}
	tmp, err := os.CreateTemp(s.dir, ".state-*.json")
	if err != nil {
		return fmt.Errorf("forward: write the state: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("forward: write the state: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("forward: write the state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("forward: write the state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("forward: write the state: %w", err)
	}
	if err := os.Rename(name, s.path()); err != nil {
		return fmt.Errorf("forward: write the state: %w", err)
	}
	return nil
}

func (s *stateStore) discard() error {
	if err := os.Remove(s.path()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
