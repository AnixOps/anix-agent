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
