package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v4/api/agent/agenttest"
	"github.com/AnixOps/anix-agent/v4/api/agent/state"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingUsers records the user sets it applies; fail makes the next
// applies fail.
type recordingUsers struct {
	mu   sync.Mutex
	sets []UserSet
	fail int
}

func (r *recordingUsers) ApplyUsers(_ context.Context, set UserSet) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail > 0 {
		r.fail--
		return errors.New("core refused the users")
	}
	r.sets = append(r.sets, set)
	return nil
}

func (r *recordingUsers) last() (UserSet, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.sets) == 0 {
		return UserSet{}, 0
	}
	return r.sets[len(r.sets)-1], len(r.sets)
}

func userIDs(set UserSet) []uint64 {
	ids := make([]uint64, 0, len(set.Users))
	for _, user := range set.Users {
		ids = append(ids, user.UserId)
	}
	return ids
}

type nopConfig struct{}

func (nopConfig) ApplyConfig(context.Context, *agentv1pb.ConfigSnapshot) error { return nil }

func newUsersClient(t *testing.T, control *agenttest.Control, root string, users UsersApplier) *Client {
	t.Helper()
	store, err := state.Open(root, agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: control.NodeID})
	require.NoError(t, err)
	client, err := NewClient(Config{
		Target: control.Address, NodeID: int(control.NodeID), APIKey: control.APIKey, UseTLS: true, ServerName: control.ServerName,
		RootCAs: control.ServerCAs, AgentVersion: "test-agent", InstanceID: "instance-1",
		Capabilities: []*agentv1pb.Capability{{Name: "agent.control", Version: "v1"}},
		Heartbeat:    time.Second, ReconnectMin: 10 * time.Millisecond, ReconnectMax: 50 * time.Millisecond,
		DialTimeout: 2 * time.Second,
		DataPlane:   &DataPlaneConfig{State: store, Config: nopConfig{}, Users: users},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func nodeUsers(ids ...uint64) []*agentv1pb.NodeUser {
	users := make([]*agentv1pb.NodeUser, 0, len(ids))
	for _, id := range ids {
		users = append(users, &agentv1pb.NodeUser{UserId: id, Uuid: "uuid-" + string(rune('a'+id))})
	}
	return users
}

func startUsersClient(t *testing.T, client *Client) {
	t.Helper()
	require.NoError(t, client.Start())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.DataPlane().WaitSession(ctx)
	require.NoError(t, err)
	client.DataPlane().Activate()
}

func TestUsersFullResyncInPagesThenDeltasWithoutResync(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeOptional, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers)
	control.SetUserPageSize(2)
	control.UpsertUsers(nodeUsers(1, 2, 3, 4, 5)...)
	root := t.TempDir()
	users := &recordingUsers{}
	client := newUsersClient(t, control, root, users)
	startUsersClient(t, client)

	require.Eventually(t, func() bool { _, count := users.last(); return count == 1 }, 5*time.Second, 10*time.Millisecond)
	set, _ := users.last()
	assert.Equal(t, []uint64{1, 2, 3, 4, 5}, userIDs(set), "the three pages apply as one set")
	assert.Equal(t, uint64(5), set.Cursor)
	assert.Len(t, control.UserDeltas(), 3)
	assert.Zero(t, control.Hellos()[0].UsersCursor)
	assert.True(t, agentcontrol.HasCapabilityVersion(control.Hellos()[0].Capabilities, agentcontrol.CapabilityUsers, "v1"))

	// Changes: a ban, a new user, a speed limit.
	control.RemoveUsers(2)
	control.UpsertUsers(&agentv1pb.NodeUser{UserId: 6, Uuid: "uuid-new"}, &agentv1pb.NodeUser{UserId: 3, Uuid: "uuid-d", SpeedLimitMbps: 50})
	require.Eventually(t, func() bool {
		set, _ := users.last()
		return set.Cursor == 8
	}, 5*time.Second, 10*time.Millisecond)
	set, _ = users.last()
	assert.Equal(t, []uint64{1, 3, 4, 5, 6}, userIDs(set))
	assert.Equal(t, int64(50), set.Users[1].SpeedLimitMbps)

	// The set and cursor are stored (within the save interval).
	require.Eventually(t, func() bool {
		stored, err := client.DataPlane().config.State.LoadUsers()
		return err == nil && stored != nil && stored.Cursor == 8 && len(stored.Upserts) == 5
	}, 5*time.Second, 50*time.Millisecond)
	info, err := os.Stat(filepath.Join(root, "proxy-12", "users.pb"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	// A reconnect resumes from the cursor: no resync.
	control.DropSessions()
	require.Eventually(t, func() bool { return len(control.Hellos()) == 2 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, uint64(8), control.Hellos()[1].UsersCursor)
	control.UpsertUsers(&agentv1pb.NodeUser{UserId: 7, Uuid: "uuid-7"})
	require.Eventually(t, func() bool { set, _ := users.last(); return set.Cursor == 9 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, 1, control.Resyncs())
	assert.Equal(t, DataPlaneStream, client.DataPlane().Mode(agentcontrol.CapabilityUsers))
}

func TestUsersPagesOfASessionThatEndsBeforeTheLastPageAreDropped(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeOptional, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers)
	control.SetUserPageSize(2)
	control.UpsertUsers(nodeUsers(1, 2, 3, 4, 5)...)
	control.DropNextResyncAfter(2)
	users := &recordingUsers{}
	client := newUsersClient(t, control, t.TempDir(), users)
	startUsersClient(t, client)

	// The first session ends after two of three pages; the Agent keeps no
	// partial set and starts over without a cursor.
	require.Eventually(t, func() bool { _, count := users.last(); return count >= 1 }, 5*time.Second, 10*time.Millisecond)
	set, count := users.last()
	assert.Equal(t, 1, count, "only the complete set is applied")
	assert.Equal(t, []uint64{1, 2, 3, 4, 5}, userIDs(set))
	hellos := control.Hellos()
	require.GreaterOrEqual(t, len(hellos), 2)
	assert.Zero(t, hellos[1].UsersCursor)
	assert.Equal(t, 2, control.Resyncs())
}

func TestUsersResyncWhenTheLogNoLongerCoversTheCursorOrIsAhead(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeOptional, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers)
	control.UpsertUsers(nodeUsers(1, 2)...)
	users := &recordingUsers{}
	client := newUsersClient(t, control, t.TempDir(), users)
	startUsersClient(t, client)
	require.Eventually(t, func() bool { _, count := users.last(); return count == 1 }, 5*time.Second, 10*time.Millisecond)

	// Rows after the cursor were pruned while the Agent was away.
	control.DropSessions()
	control.Serve(agentcontrol.CapabilityUsers, false)
	require.Eventually(t, func() bool { return len(control.Hellos()) == 2 }, 5*time.Second, 10*time.Millisecond)
	control.UpsertUsers(nodeUsers(3)...)
	control.RemoveUsers(1)
	control.PruneUserLog()
	control.Serve(agentcontrol.CapabilityUsers, true)
	control.DropSessions()
	require.Eventually(t, func() bool { set, _ := users.last(); return set.Cursor == 4 }, 5*time.Second, 10*time.Millisecond)
	set, _ := users.last()
	assert.Equal(t, []uint64{2, 3}, userIDs(set))
	assert.Equal(t, 2, control.Resyncs())

	// A restored database: the Agent's cursor is ahead of the log.
	control.ResetUserLog()
	control.UpsertUsers(nodeUsers(9)...)
	control.DropSessions()
	require.Eventually(t, func() bool { return control.Resyncs() == 3 }, 5*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { set, _ := users.last(); return set.Cursor == 1 }, 5*time.Second, 10*time.Millisecond)
	set, _ = users.last()
	assert.Equal(t, []uint64{2, 3, 9}, userIDs(set), "a resync replaces the set")
}

func TestUsersRetriesASetTheNodeCouldNotApply(t *testing.T) {
	previous := usersRetryInterval
	usersRetryInterval = 100 * time.Millisecond
	t.Cleanup(func() { usersRetryInterval = previous })
	control := agenttest.New(t, agenttest.ModeOptional, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers)
	control.UpsertUsers(nodeUsers(1, 2)...)
	users := &recordingUsers{fail: 2}
	client := newUsersClient(t, control, t.TempDir(), users)
	startUsersClient(t, client)
	require.Eventually(t, func() bool { _, count := users.last(); return count == 1 }, 5*time.Second, 10*time.Millisecond)
	set, _ := users.last()
	assert.Equal(t, []uint64{1, 2}, userIDs(set))
	assert.Equal(t, uint64(2), client.dataPlane.counters.usersFailed.Load())
	assert.Empty(t, client.TransportStatus().DataPlane.UsersError)
}

func TestUsersRestartResumesFromTheStoredCursor(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeOptional, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers)
	control.UpsertUsers(nodeUsers(1, 2, 3)...)
	root := t.TempDir()
	first := newUsersClient(t, control, root, &recordingUsers{})
	startUsersClient(t, first)
	require.Eventually(t, func() bool { return first.TransportStatus().DataPlane.UsersCursor == 3 }, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, first.Close()) // stores the set

	control.RemoveUsers(3)
	users := &recordingUsers{}
	second := newUsersClient(t, control, root, users)
	persisted := second.DataPlane().PersistedUsers()
	require.NotNil(t, persisted)
	assert.Equal(t, uint64(3), persisted.Cursor)
	assert.Equal(t, []uint64{1, 2, 3}, userIDs(*persisted))
	second.DataPlane().RestoreUsers(*persisted)
	startUsersClient(t, second)
	require.Eventually(t, func() bool { set, _ := users.last(); return set.Cursor == 4 }, 5*time.Second, 10*time.Millisecond)
	set, _ := users.last()
	assert.Equal(t, []uint64{1, 2}, userIDs(set))
	assert.Equal(t, uint64(3), control.Hellos()[1].UsersCursor)
	assert.Equal(t, 1, control.Resyncs(), "the restart resumed from the cursor")
}

func TestUsersNotServedStayOnTheLegacyTransport(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeOptional, agentcontrol.CapabilityConfig)
	users := &recordingUsers{}
	client := newUsersClient(t, control, t.TempDir(), users)
	startUsersClient(t, client)
	assert.Equal(t, DataPlaneLegacy, client.DataPlane().Mode(agentcontrol.CapabilityUsers))
	assert.Equal(t, DataPlaneStream, client.DataPlane().Mode(agentcontrol.CapabilityConfig))
	_, count := users.last()
	assert.Zero(t, count)
}
