// Package state keeps what the Agent control stream's data plane delivered
// to a node (PROTOCOL.md, "Data plane"), so that an Agent restarted while
// Control is unreachable runs what it last applied and resumes the stream
// where it left off.
//
// Each node has its own directory under the root (DefaultRoot), named after
// the node (proxy-12):
//
//	<root>/proxy-12/state.json   the Control it belongs to, the last session's negotiated capabilities
//	<root>/proxy-12/config.pb    the last applied ConfigSnapshot (config.v1)
//
// The directories are mode 0700 and the files 0600, owned by the Agent's
// user: a configuration snapshot holds the node's protocol secrets (private
// keys, passwords). A file with wider permissions or another owner is
// refused (ErrInsecureFile) and the Agent asks Control for the state again.
package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"google.golang.org/protobuf/proto"
)

// DefaultRoot is where the data-plane state lives unless
// AgentStream.StateDir says otherwise.
const DefaultRoot = "/var/lib/anix-agent/stream"

const (
	stateFile  = "state.json"
	configFile = "config.pb"

	dirMode  fs.FileMode = 0o700
	fileMode fs.FileMode = 0o600

	// maxConfigFileBytes bounds config.pb: Control's messages are at most
	// 8 MiB (the client's receive limit).
	maxConfigFileBytes = 8 << 20
)

// ErrInsecureFile reports a state file others could read or replace.
var ErrInsecureFile = errors.New("insecure data-plane state file")

// ErrCorrupt reports a state file that does not decode or verify.
var ErrCorrupt = errors.New("corrupt data-plane state file")

// Store is the data-plane state directory of one node.
type Store struct {
	dir  string
	node agentcontrol.AgentNode
}

// Open returns the store of node under root (DefaultRoot when empty) and
// creates its directory, mode 0700. A missing root is created 0700 too; an
// existing one keeps the operator's mode.
func Open(root string, node agentcontrol.AgentNode) (*Store, error) {
	if !node.Valid() {
		return nil, fmt.Errorf("data-plane state: invalid node %q", node.String())
	}
	if root == "" {
		root = DefaultRoot
	}
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("data-plane state directory %q must be an absolute path", root)
	}
	store := &Store{dir: filepath.Join(filepath.Clean(root), node.String()), node: node}
	if err := createPrivateDir(filepath.Dir(store.dir)); err != nil {
		return nil, fmt.Errorf("data-plane state directory: %w", err)
	}
	if err := createPrivateDir(store.dir); err != nil {
		return nil, fmt.Errorf("data-plane state directory: %w", err)
	}
	if err := os.Chmod(store.dir, dirMode); err != nil {
		return nil, fmt.Errorf("data-plane state directory: %w", err)
	}
	return store, nil
}

// Dir is the node's state directory.
func (s *Store) Dir() string { return s.dir }

// Node is the node the store belongs to.
func (s *Store) Node() agentcontrol.AgentNode { return s.node }

// Session is state.json: which Control the state belongs to and what the
// last session negotiated.
type Session struct {
	// Control identifies the Control the state came from (its gRPC
	// target). State of another Control is discarded: its revisions and
	// cursors mean nothing here.
	Control string `json:"control"`
	// Negotiated lists the data-plane capabilities (config, users, ...)
	// the last session negotiated.
	Negotiated []string `json:"negotiated,omitempty"`
	// At is when that session started.
	At time.Time `json:"at,omitzero"`
}

// LoadSession reads state.json; a zero Session without one.
func (s *Store) LoadSession() (Session, error) {
	data, err := readPrivateFile(filepath.Join(s.dir, stateFile), 1<<20)
	if errors.Is(err, fs.ErrNotExist) {
		return Session{}, nil
	}
	if err != nil {
		return Session{}, err
	}
	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return Session{}, fmt.Errorf("%w: %s: %v", ErrCorrupt, stateFile, err)
	}
	return session, nil
}

// SaveSession writes state.json.
func (s *Store) SaveSession(session Session) error {
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFile(filepath.Join(s.dir, stateFile), append(data, '\n'))
}

// BindControl makes the store belong to control. State another Control
// left (a different target) is discarded, because its configuration
// revisions and user cursors would be read against the wrong history. It
// reports whether state was discarded.
func (s *Store) BindControl(control string) (bool, error) {
	control = strings.TrimSpace(control)
	session, err := s.LoadSession()
	if err == nil && session.Control == control {
		return false, nil
	}
	// Another Control's state, state without an owner, or a state file
	// that cannot be trusted (corrupt, insecure): what was delivered
	// cannot be attributed to this Control, so it is dropped.
	discarded, discardErr := s.discardDelivered()
	if discardErr != nil {
		return false, discardErr
	}
	if err != nil {
		if removeErr := os.Remove(filepath.Join(s.dir, stateFile)); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			return false, removeErr
		}
	}
	return discarded, s.SaveSession(Session{Control: control})
}

// discardDelivered removes what Control delivered (configuration, users),
// not what the Agent still has to report. It reports whether there was
// anything to remove.
func (s *Store) discardDelivered() (bool, error) {
	_, statErr := os.Lstat(filepath.Join(s.dir, configFile))
	existed := statErr == nil
	return existed, s.DiscardConfig()
}

// LoadConfig reads the last applied configuration snapshot: nil without
// one. A snapshot whose hash does not match its bytes is ErrCorrupt.
func (s *Store) LoadConfig() (*agentv1pb.ConfigSnapshot, error) {
	data, err := readPrivateFile(filepath.Join(s.dir, configFile), maxConfigFileBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	snapshot := &agentv1pb.ConfigSnapshot{}
	if err := proto.Unmarshal(data, snapshot); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCorrupt, configFile, err)
	}
	if snapshot.GetConfigRevision() == 0 || !HashMatches(snapshot) {
		return nil, fmt.Errorf("%w: %s does not verify", ErrCorrupt, configFile)
	}
	return snapshot, nil
}

// SaveConfig stores snapshot as the last applied configuration.
func (s *Store) SaveConfig(snapshot *agentv1pb.ConfigSnapshot) error {
	if snapshot == nil || snapshot.GetConfigRevision() == 0 {
		return errors.New("data-plane state: no configuration snapshot to save")
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(snapshot)
	if err != nil {
		return err
	}
	return writePrivateFile(filepath.Join(s.dir, configFile), data)
}

// DiscardConfig removes the stored configuration snapshot.
func (s *Store) DiscardConfig() error {
	if err := os.Remove(filepath.Join(s.dir, configFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// HashMatches reports whether snapshot's config_hash is the lowercase hex
// SHA-256 of its exact config_json bytes (PROTOCOL.md, "Configuration").
func HashMatches(snapshot *agentv1pb.ConfigSnapshot) bool {
	sum := sha256.Sum256(snapshot.GetConfigJson())
	return snapshot.GetConfigHash() == hex.EncodeToString(sum[:])
}

// readPrivateFile reads a file only when its permissions keep it private
// to the Agent's user, and refuses one larger than limit.
func readPrivateFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := checkPrivate(path, info); err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrCorrupt, path, limit)
	}
	var buffer bytes.Buffer
	if _, err := buffer.ReadFrom(file); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// checkPrivate refuses a regular file with group or other permissions, or
// owned by another user.
func checkPrivate(path string, info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrInsecureFile, path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s has mode %04o, want 0600", ErrInsecureFile, path, info.Mode().Perm())
	}
	if !ownedByCurrentUser(info) {
		return fmt.Errorf("%w: %s is not owned by the Agent's user", ErrInsecureFile, path)
	}
	return nil
}

// createPrivateDir creates dir with mode 0700 (whatever the umask) when it
// does not exist.
func createPrivateDir(dir string) error {
	info, err := os.Stat(dir)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", dir)
		}
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	return os.Chmod(dir, dirMode)
}

// writePrivateFile writes data to path with mode 0600 through a temporary
// file in the same directory, synced, then renamed over path.
func writePrivateFile(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer func() {
		if name != "" {
			_ = os.Remove(name)
		}
	}()
	if err := temporary.Chmod(fileMode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	name = ""
	syncDir(filepath.Dir(path))
	return nil
}

func syncDir(dir string) {
	if handle, err := os.Open(dir); err == nil {
		_ = handle.Sync()
		_ = handle.Close()
	}
}
