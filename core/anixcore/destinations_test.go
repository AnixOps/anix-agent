package anixcore

import (
	"reflect"
	"testing"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/common/destinations"
	"github.com/AnixOps/anix-agent/v5/conf"
	vCore "github.com/AnixOps/anix-agent/v5/core"
)

func destinationsCore(t *testing.T, features []string) (*fakeAPI, *Core) {
	t.Helper()
	api, server := newFakeAPI(t)
	api.features = features
	core := externalCore(t, server)
	t.Cleanup(func() { _ = core.Close() })
	info := shadowsocksNode()
	if err := core.AddNode("ss", info, &conf.Options{}); err != nil {
		t.Fatal(err)
	}
	user := panel.UserInfo{Id: 7, Uuid: "0123456789abcdef0123456789abcdef"}
	if _, err := core.AddUsers(&vCore.AddUsersParams{Tag: "ss", Users: []panel.UserInfo{user}, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}
	return api, core
}

func TestDestinationTrafficFoldsKernelHostsIntoDomains(t *testing.T) {
	api, core := destinationsCore(t, []string{destinationsFeature})
	got, err := core.GetDestinationTraffic("ss")
	if err != nil {
		t.Fatal(err)
	}
	want := []destinations.Traffic{
		{UID: 7, Entry: destinations.Entry{User: "7", Domain: "youtube.com", Protocol: "tls", Upload: 15, Download: 150, Connections: 3}},
		{UID: 7, Entry: destinations.Entry{User: "7", Domain: "ytimg.com", Protocol: "tls", Upload: 1, Download: 2, Connections: 1}},
		{UID: 7, Entry: destinations.Entry{User: "7", Domain: "198.51.100.0/24", Upload: 3, Download: 4, Connections: 1}},
		{UID: 8, Entry: destinations.Entry{User: "8", Upload: 1, Download: 1, Connections: 1}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("traffic = %+v\nwant %+v", got, want)
	}
	last := api.calls[len(api.calls)-1]
	if last != "GET /v1/inbounds/ss/destinations?reset=true" {
		t.Fatalf("last call = %q", last)
	}
}

func TestDestinationTrafficNeedsTheKernelFeature(t *testing.T) {
	api, core := destinationsCore(t, nil)
	got, err := core.GetDestinationTraffic("ss")
	if err != nil || got != nil {
		t.Fatalf("GetDestinationTraffic = %v, %v", got, err)
	}
	for _, call := range api.calls {
		if call == "GET /v1/inbounds/ss/destinations?reset=true" {
			t.Fatal("destinations read from a kernel without the feature")
		}
	}
	if got, err := core.GetDestinationTraffic("missing"); err != nil || got != nil {
		t.Fatalf("missing tag = %v, %v", got, err)
	}
}

// TestFoldDestinationsCountsUDPQUICAndMux folds what anx-node reports for
// UDP (protocol udp), QUIC (quic, from the Initial's SNI) and Mux.Cool
// sessions (each sub-stream as its own entry: TCP as tls, http or empty,
// UDP as udp or quic).
func TestFoldDestinationsCountsUDPQUICAndMux(t *testing.T) {
	for _, c := range []struct {
		name    string
		entries []apiDestination
		want    []destinations.Traffic
	}{
		{
			name: "quic is a row of its own next to tls",
			entries: []apiDestination{
				{Name: "7", Host: "www.youtube.com", Protocol: "quic", Up: 10, Down: 100, Connections: 1},
				{Name: "7", Host: "rr1.youtube.com", Protocol: "quic", Up: 1, Down: 10, Connections: 1},
				{Name: "7", Host: "www.youtube.com", Protocol: "tls", Up: 2, Down: 20, Connections: 1},
			},
			want: []destinations.Traffic{
				{UID: 7, Entry: destinations.Entry{User: "7", Domain: "youtube.com", Protocol: "quic", Upload: 11, Download: 110, Connections: 2}},
				{UID: 7, Entry: destinations.Entry{User: "7", Domain: "youtube.com", Protocol: "tls", Upload: 2, Download: 20, Connections: 1}},
			},
		},
		{
			name: "a udp address target becomes its network",
			entries: []apiDestination{
				{Name: "7", Host: "203.0.113.53", Protocol: "udp", Up: 1, Down: 2, Connections: 1},
				{Name: "7", Host: "203.0.113.54:53", Protocol: "udp", Up: 3, Down: 4, Connections: 1},
			},
			want: []destinations.Traffic{
				{UID: 7, Entry: destinations.Entry{User: "7", Domain: "203.0.113.0/24", Protocol: "udp", Upload: 4, Download: 6, Connections: 2}},
			},
		},
		{
			name: "udp to an unknown host is kept as other",
			entries: []apiDestination{
				{Name: "8", Host: "", Protocol: "udp", Up: 5, Down: 6, Connections: 1},
			},
			want: []destinations.Traffic{
				{UID: 8, Entry: destinations.Entry{User: "8", Protocol: "udp", Upload: 5, Download: 6, Connections: 1}},
			},
		},
		{
			name: "mux sub-streams count by their own protocol",
			entries: []apiDestination{
				{Name: "9", Host: "api.example.com", Protocol: "tls", Up: 1, Down: 1, Connections: 1},
				{Name: "9", Host: "www.example.com", Protocol: "http", Up: 1, Down: 1, Connections: 1},
				{Name: "9", Host: "cdn.example.com", Protocol: "", Up: 1, Down: 1, Connections: 1},
				{Name: "9", Host: "dns.example.com", Protocol: "udp", Up: 1, Down: 1, Connections: 1},
				{Name: "9", Host: "media.example.com", Protocol: "quic", Up: 1, Down: 1, Connections: 1},
			},
			want: []destinations.Traffic{
				{UID: 9, Entry: destinations.Entry{User: "9", Domain: "example.com", Protocol: "tls", Upload: 1, Download: 1, Connections: 1}},
				{UID: 9, Entry: destinations.Entry{User: "9", Domain: "example.com", Protocol: "http", Upload: 1, Download: 1, Connections: 1}},
				{UID: 9, Entry: destinations.Entry{User: "9", Domain: "example.com", Upload: 1, Download: 1, Connections: 1}},
				{UID: 9, Entry: destinations.Entry{User: "9", Domain: "example.com", Protocol: "udp", Upload: 1, Download: 1, Connections: 1}},
				{UID: 9, Entry: destinations.Entry{User: "9", Domain: "example.com", Protocol: "quic", Upload: 1, Download: 1, Connections: 1}},
			},
		},
		{
			name: "all-zero entries are dropped",
			entries: []apiDestination{
				{Name: "7", Host: "example.com", Protocol: "udp"},
			},
		},
		{
			name: "the issued-key user folds into the panel user",
			entries: []apiDestination{
				{Name: "7", Host: "www.youtube.com", Protocol: "quic", Up: 1, Down: 1, Connections: 1},
				{Name: "7.k", Host: "m.youtube.com", Protocol: "quic", Up: 2, Down: 2, Connections: 1},
			},
			want: []destinations.Traffic{
				{UID: 7, Entry: destinations.Entry{User: "7", Domain: "youtube.com", Protocol: "quic", Upload: 3, Download: 3, Connections: 2}},
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := foldDestinations(c.entries); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("foldDestinations = %+v\nwant %+v", got, c.want)
			}
		})
	}
}
