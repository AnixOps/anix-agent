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
