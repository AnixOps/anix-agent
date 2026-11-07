package node

import (
	"testing"

	"github.com/AnixOps/anix-agent/v5/api/panel"
)

func TestMergeOnlineDevicesDeduplicatesAndSkipsEmptyEntries(t *testing.T) {
	merged := mergeOnlineDevices([]panel.OnlineUser{
		{UID: 7, IP: "203.0.113.10"},
		{UID: 7, IP: "203.0.113.10"},
		{UID: 8, IP: "203.0.113.10"},
		{UID: 0, IP: "203.0.113.11"},
		{UID: 9},
	})

	if len(merged) != 2 {
		t.Fatalf("merged online devices = %#v", merged)
	}
	if merged[0].UID != 7 || merged[0].IP != "203.0.113.10" {
		t.Fatalf("first merged device = %#v", merged[0])
	}
	if merged[1].UID != 8 || merged[1].IP != "203.0.113.10" {
		t.Fatalf("second merged device = %#v", merged[1])
	}
}

func TestCompareUserListReaddsAUserWithANewlyIssuedKey(t *testing.T) {
	old := []panel.UserInfo{{Id: 7, Uuid: "user-7"}}
	issued := []panel.UserInfo{{Id: 7, Uuid: "user-7", Extra: map[string]string{"ss2022_key": "key"}}}
	deleted, added := compareUserList(old, issued)
	if len(deleted) != 1 || len(added) != 1 || added[0].Extra["ss2022_key"] != "key" {
		t.Fatalf("deleted = %v, added = %v", deleted, added)
	}
}
