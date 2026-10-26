package destinations

import (
	"sort"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNameKeepsTheRegistrableDomainOrTheAddressNetwork(t *testing.T) {
	for host, want := range map[string]string{
		"www.YouTube.com":             "youtube.com",
		"rr3---sn-x.googlevideo.com.": "googlevideo.com",
		"api.telegram.org:443":        "telegram.org",
		"a.b.example.co.uk":           "example.co.uk",
		"youtube.com":                 "youtube.com",
		"localhost":                   "localhost",
		"149.154.167.51":              "149.154.167.0/24",
		"149.154.167.51:443":          "149.154.167.0/24",
		"::ffff:1.2.3.4":              "1.2.3.0/24",
		"[2001:db8:1:2::1]:443":       "2001:db8:1::/48",
		"2001:db8:1:2::1":             "2001:db8:1::/48",
		"":                            "",
		"  ":                          "",
	} {
		assert.Equal(t, want, Name(host), host)
	}
}

func sorted(entries []Entry) []Entry {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].User != entries[j].User {
			return entries[i].User < entries[j].User
		}
		return entries[i].Domain+entries[i].Protocol < entries[j].Domain+entries[j].Protocol
	})
	return entries
}

func TestCollectorSumsAWindowAndStartsTheNext(t *testing.T) {
	c := NewCollector()
	assert.Nil(t, c.Open("", "youtube.com", "tls"), "a connection without a user counts nowhere")

	first := c.Open("alice", "www.youtube.com", "TLS")
	second := c.Open("alice", "m.youtube.com:443", "tls")
	require.Same(t, first, second, "one destination of a user")
	first.Upload.Add(10)
	second.Download.Add(1000)
	other := c.Open("bob", "1.2.3.4", "quic")
	other.Download.Add(5)

	assert.Equal(t, []Entry{
		{User: "alice", Domain: "youtube.com", Protocol: "tls", Upload: 10, Download: 1000, Connections: 2},
		{User: "bob", Domain: "1.2.3.0/24", Protocol: "quic", Download: 5, Connections: 1},
	}, sorted(c.Snapshot()))

	// The next window has only what came after.
	first.Download.Add(7)
	assert.Equal(t, []Entry{{User: "alice", Domain: "youtube.com", Protocol: "tls", Download: 7}}, c.Snapshot())
	assert.Empty(t, c.Snapshot())
}

func TestCollectorKeepsAnOpenDestinationAndDropsAnIdleOne(t *testing.T) {
	c := NewCollector()
	open := c.Open("alice", "netflix.com", "tls")
	closed := c.Open("alice", "github.com", "tls")
	closed.Release()
	c.Snapshot()
	c.Snapshot()
	c.mu.Lock()
	assert.Len(t, c.stats, 1, "github.com was idle a window with no connection open")
	assert.Equal(t, 1, c.perUser["alice"])
	c.mu.Unlock()

	// A long connection still counts after idle windows.
	open.Download.Add(3)
	assert.Equal(t, []Entry{{User: "alice", Domain: "netflix.com", Protocol: "tls", Download: 3}}, c.Snapshot())
	open.Release()
	c.Snapshot()
	c.mu.Lock()
	assert.Empty(t, c.stats)
	assert.Empty(t, c.perUser)
	c.mu.Unlock()
}

func TestCollectorCountsAUsersDestinationsBeyondItsBoundAsOther(t *testing.T) {
	c := NewCollector()
	for i := range MaxPerUser {
		c.Open("alice", "site"+strconv.Itoa(i)+".com", "tls").Download.Add(1)
	}
	c.Open("alice", "one-more.com", "tls").Download.Add(5)
	c.Open("alice", "another.com", "http").Download.Add(6)
	c.Open("alice", "site0.com", "tls").Download.Add(1)
	c.Open("bob", "one-more.com", "tls").Download.Add(1)

	entries := c.Snapshot()
	byKey := map[string]Entry{}
	for _, entry := range entries {
		byKey[entry.User+"|"+entry.Domain] = entry
	}
	assert.Len(t, entries, MaxPerUser+2)
	assert.Equal(t, Entry{User: "alice", Download: 11, Connections: 2}, byKey["alice|"], "other: no domain, no protocol")
	assert.Equal(t, int64(2), byKey["alice|site0.com"].Download)
	assert.Equal(t, int64(1), byKey["bob|one-more.com"].Download)
}

func TestResolveKeepsTheUsersTheCoreKnows(t *testing.T) {
	entries := []Entry{{User: "a", Domain: "x.com", Download: 1}, {User: "gone", Domain: "y.com"}}
	assert.Equal(t, []Traffic{{UID: 7, Entry: entries[0]}}, Resolve(entries, func(user string) int {
		if user == "a" {
			return 7
		}
		return 0
	}))
}

func TestCollectorsByTag(t *testing.T) {
	var c Collectors
	assert.Nil(t, c.Snapshot("in"))
	c.Get("in").Open("alice", "x.com", "").Upload.Add(1)
	assert.Same(t, c.Get("in"), c.Get("in"))
	assert.Len(t, c.Snapshot("in"), 1)
	c.Delete("in")
	assert.Nil(t, c.Snapshot("in"))
}
