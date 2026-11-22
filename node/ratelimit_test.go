package node

import (
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
)

func TestRateLimitsTakeTheLowestLimitThatIsSet(t *testing.T) {
	r := newRateLimits(100, []panel.UserInfo{{Uuid: "own-10", SpeedLimit: 10}, {Uuid: "none"}})
	if got := r.rate("own-10"); got != 1_250_000 {
		t.Fatalf("own limit: rate = %d", got)
	}
	if got := r.rate("none"); got != 12_500_000 {
		t.Fatalf("node limit: rate = %d", got)
	}
	r.penalize("none", 1, time.Now().Add(time.Minute))
	if got := r.rate("none"); got != 125_000 {
		t.Fatalf("penalty: rate = %d", got)
	}
	r.penalize("own-10", 50, time.Now().Add(-time.Second))
	if got := r.rate("own-10"); got != 1_250_000 {
		t.Fatalf("expired penalty: rate = %d", got)
	}
	r.update([]panel.UserInfo{{Uuid: "none"}}, []panel.UserInfo{{Uuid: "own-10"}})
	if got := r.rate("none"); got != 12_500_000 {
		t.Fatalf("re-added user keeps its penalty: rate = %d", got)
	}
	if got := newRateLimits(0, nil).rate("unknown"); got != 0 {
		t.Fatalf("no limits: rate = %d", got)
	}
}
