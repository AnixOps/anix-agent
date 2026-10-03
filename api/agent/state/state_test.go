package state

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

var testNode = agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: 12}

func snapshot(revision uint64, body string) *agentv1pb.ConfigSnapshot {
	sum := sha256.Sum256([]byte(body))
	return &agentv1pb.ConfigSnapshot{ConfigRevision: revision, ConfigHash: hex.EncodeToString(sum[:]), Format: "anixops.nodeconfig/v1", ConfigJson: []byte(body)}
}

func TestOpenCreatesPrivateDirectories(t *testing.T) {
	root := filepath.Join(t.TempDir(), "stream")
	store, err := Open(root, testNode)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(root, "proxy-12"), store.Dir())
	for _, dir := range []string{root, store.Dir()} {
		info, err := os.Stat(dir)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(), dir)
	}
	_, err = Open("relative", testNode)
	require.Error(t, err)
	_, err = Open(root, agentcontrol.AgentNode{})
	require.Error(t, err)
}

func TestConfigRoundTripIsPrivateAndVerified(t *testing.T) {
	store, err := Open(t.TempDir(), testNode)
	require.NoError(t, err)
	loaded, err := store.LoadConfig()
	require.NoError(t, err)
	assert.Nil(t, loaded)

	saved := snapshot(4, `{"kind":"proxy"}`)
	require.NoError(t, store.SaveConfig(saved))
	info, err := os.Stat(filepath.Join(store.Dir(), configFile))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	loaded, err = store.LoadConfig()
	require.NoError(t, err)
	assert.True(t, proto.Equal(saved, loaded))

	// A snapshot whose bytes no longer match its hash is refused.
	tampered := proto.Clone(saved).(*agentv1pb.ConfigSnapshot)
	tampered.ConfigJson = []byte(`{"kind":"forward"}`)
	data, err := proto.Marshal(tampered)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(store.Dir(), configFile), data, 0o600))
	_, err = store.LoadConfig()
	assert.True(t, errors.Is(err, ErrCorrupt), "%v", err)

	require.NoError(t, store.DiscardConfig())
	require.NoError(t, store.DiscardConfig())
	loaded, err = store.LoadConfig()
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestLoadRefusesFilesOthersCanRead(t *testing.T) {
	store, err := Open(t.TempDir(), testNode)
	require.NoError(t, err)
	require.NoError(t, store.SaveConfig(snapshot(1, `{}`)))
	require.NoError(t, os.Chmod(filepath.Join(store.Dir(), configFile), 0o644))
	_, err = store.LoadConfig()
	assert.True(t, errors.Is(err, ErrInsecureFile), "%v", err)
}

func TestBindControlKeepsStateOfTheSameControlAndDropsAnothers(t *testing.T) {
	root := t.TempDir()
	store, err := Open(root, testNode)
	require.NoError(t, err)
	discarded, err := store.BindControl("control-a:50051")
	require.NoError(t, err)
	assert.False(t, discarded)
	require.NoError(t, store.SaveConfig(snapshot(3, `{}`)))
	require.NoError(t, store.SaveSession(Session{Control: "control-a:50051", Negotiated: []string{"config"}}))

	discarded, err = store.BindControl("control-a:50051")
	require.NoError(t, err)
	assert.False(t, discarded)
	loaded, err := store.LoadConfig()
	require.NoError(t, err)
	require.NotNil(t, loaded)

	discarded, err = store.BindControl("control-b:50051")
	require.NoError(t, err)
	assert.True(t, discarded)
	loaded, err = store.LoadConfig()
	require.NoError(t, err)
	assert.Nil(t, loaded)
	session, err := store.LoadSession()
	require.NoError(t, err)
	assert.Equal(t, Session{Control: "control-b:50051"}, session)

	// A state file that cannot be read drops what it would vouch for.
	require.NoError(t, store.SaveConfig(snapshot(4, `{}`)))
	require.NoError(t, os.WriteFile(filepath.Join(store.Dir(), stateFile), []byte("{"), 0o600))
	discarded, err = store.BindControl("control-b:50051")
	require.NoError(t, err)
	assert.True(t, discarded)
	loaded, err = store.LoadConfig()
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestUsersRoundTrip(t *testing.T) {
	store, err := Open(t.TempDir(), testNode)
	require.NoError(t, err)
	loaded, err := store.LoadUsers()
	require.NoError(t, err)
	assert.Nil(t, loaded)

	users := []*agentv1pb.NodeUser{{UserId: 1, Uuid: "a"}, {UserId: 2, Uuid: "b", SpeedLimitMbps: 10, ExtraJson: []byte(`{"wireguard_peer_ip":"10.0.0.2"}`)}}
	require.NoError(t, store.SaveUsers(42, users))
	info, err := os.Stat(filepath.Join(store.Dir(), usersFile))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	loaded, err = store.LoadUsers()
	require.NoError(t, err)
	assert.Equal(t, uint64(42), loaded.Cursor)
	require.Len(t, loaded.Upserts, 2)
	assert.True(t, proto.Equal(users[1], loaded.Upserts[1]))

	require.NoError(t, store.SaveUsers(0, nil))
	loaded, err = store.LoadUsers()
	require.NoError(t, err)
	require.NotNil(t, loaded, "an empty set of an empty change log is a set")
	assert.Zero(t, loaded.Cursor)
	assert.Empty(t, loaded.Upserts)

	// Another Control's state goes, users included.
	require.NoError(t, store.SaveSession(Session{Control: "a"}))
	discarded, err := store.BindControl("b")
	require.NoError(t, err)
	assert.True(t, discarded)
	loaded, err = store.LoadUsers()
	require.NoError(t, err)
	assert.Nil(t, loaded)
}
