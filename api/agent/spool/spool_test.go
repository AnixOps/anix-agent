package spool

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func traffic(id string, created time.Time, users int) *agentv1pb.AgentToControl {
	report := &agentv1pb.TrafficReport{BatchId: id, WindowEndUnixMs: created.UnixMilli()}
	for index := 0; index < users; index++ {
		report.Users = append(report.Users, &agentv1pb.UserTraffic{UserId: uint64(index + 1), UploadBytes: 1, DownloadBytes: 2})
	}
	return &agentv1pb.AgentToControl{SentAtUnixMs: created.UnixMilli(), Payload: &agentv1pb.AgentToControl_Traffic{Traffic: report}}
}

func ids(entries []Entry) []string {
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		result = append(result, entry.BatchID)
	}
	return result
}

func TestSpoolKeepsBatchesInOrderAcrossRestartsAndDedupes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "traffic")
	at := &clock{now: time.Unix(1_800_000_000, 0)}
	spool, err := Open(dir, Limits{MaxBytes: 1 << 20, MaxAge: time.Hour}, at.Now)
	require.NoError(t, err)
	for _, id := range []string{"b1", "b2", "b3"} {
		require.NoError(t, spool.Append(traffic(id, at.now, 2)))
	}
	require.NoError(t, spool.Append(traffic("b2", at.now, 2)), "a batch id is spooled once")
	assert.Equal(t, []string{"b1", "b2", "b3"}, ids(spool.Pending()))

	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	files, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, files, 3)
	for _, file := range files {
		fileInfo, err := file.Info()
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), fileInfo.Mode().Perm())
	}

	assert.True(t, spool.Remove("b1"))
	assert.False(t, spool.Remove("b1"))
	message, ok, err := spool.Read("b2")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "b2", message.GetTraffic().GetBatchId())

	// A restart: the order holds and new batches come after.
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".0000000000000009.pb.tmp-1"), []byte("partial"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "0000000000000008.pb"), []byte("not a batch"), 0o600))
	reopened, err := Open(dir, Limits{MaxBytes: 1 << 20, MaxAge: time.Hour}, at.Now)
	require.NoError(t, err)
	assert.Equal(t, []string{"b2", "b3"}, ids(reopened.Pending()))
	require.NoError(t, reopened.Append(traffic("b4", at.now, 2)))
	assert.Equal(t, []string{"b2", "b3", "b4"}, ids(reopened.Pending()))
	files, err = os.ReadDir(dir)
	require.NoError(t, err)
	for _, file := range files {
		assert.False(t, strings.HasPrefix(file.Name(), "."), "interrupted writes are cleaned up")
	}
	count, _, _ := reopened.Stats()
	assert.Equal(t, 3, count)
}

func TestSpoolDropsTheOldestBatchesBeyondItsBounds(t *testing.T) {
	at := &clock{now: time.Unix(1_800_000_000, 0)}
	probe := traffic("b0", at.now, 50)
	data, err := Open(filepath.Join(t.TempDir(), "probe"), Limits{MaxBytes: 1 << 20, MaxAge: time.Hour}, at.Now)
	require.NoError(t, err)
	require.NoError(t, data.Append(probe))
	_, size, _ := data.Stats()

	spool, err := Open(filepath.Join(t.TempDir(), "traffic"), Limits{MaxBytes: size * 3, MaxAge: time.Hour, MaxEntries: 10}, at.Now)
	require.NoError(t, err)
	for _, id := range []string{"b1", "b2", "b3", "b4"} {
		require.NoError(t, spool.Append(traffic(id, at.now, 50)))
	}
	assert.Equal(t, []string{"b2", "b3", "b4"}, ids(spool.Pending()), "the oldest goes when the spool is full")
	_, bytes, drops := spool.Stats()
	assert.LessOrEqual(t, bytes, size*3)
	assert.Equal(t, uint64(1), drops.Size)

	// Age: batches older than MaxAge are dropped.
	at.now = at.now.Add(30 * time.Minute)
	require.NoError(t, spool.Append(traffic("b5", at.now, 50)))
	at.now = at.now.Add(45 * time.Minute)
	assert.Equal(t, []string{"b5"}, ids(spool.Pending()))
	_, _, drops = spool.Stats()
	assert.Equal(t, uint64(2), drops.Size, "b1, then b2 to fit b5")
	assert.Equal(t, uint64(2), drops.Age, "b3 and b4")

	// Count.
	counted, err := Open(filepath.Join(t.TempDir(), "count"), Limits{MaxBytes: 1 << 20, MaxAge: time.Hour, MaxEntries: 2}, at.Now)
	require.NoError(t, err)
	for _, id := range []string{"c1", "c2", "c3"} {
		require.NoError(t, counted.Append(traffic(id, at.now, 1)))
	}
	assert.Equal(t, []string{"c2", "c3"}, ids(counted.Pending()))
	_, _, drops = counted.Stats()
	assert.Equal(t, uint64(1), drops.Count)

	// A batch larger than the spool is refused, not stored.
	tiny, err := Open(filepath.Join(t.TempDir(), "tiny"), Limits{MaxBytes: 10, MaxAge: time.Hour}, at.Now)
	require.NoError(t, err)
	require.ErrorIs(t, tiny.Append(traffic("big", at.now, 50)), ErrTooLarge)
}

func TestOpenRefusesUnsafeBounds(t *testing.T) {
	_, err := Open("relative", Limits{MaxBytes: 1, MaxAge: time.Hour}, nil)
	require.Error(t, err)
	_, err = Open(t.TempDir(), Limits{MaxBytes: 1, MaxAge: 7 * 24 * time.Hour}, nil)
	require.Error(t, err, "Control forgets batch ids after 7 days")
	_, err = Open(t.TempDir(), Limits{MaxAge: time.Hour}, nil)
	require.Error(t, err)
}
