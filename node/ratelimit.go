package node

import (
	"sync"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
)

// rateLimits are the speed limits of one node's users, in bytes per second:
// the node's limit, each user's own and a temporary penalty for a user who
// went over the dynamic speed limit's traffic. A user's rate is the lowest
// of those that are set; 0 is no limit.
type rateLimits struct {
	mu    sync.Mutex
	node  int
	users map[string]*userRate // by uuid
}

type userRate struct {
	own, penalty int
	penaltyEnds  time.Time
}

func newRateLimits(nodeMbps int, users []panel.UserInfo) *rateLimits {
	r := &rateLimits{node: mbpsToBytes(nodeMbps), users: make(map[string]*userRate, len(users))}
	r.update(users, nil)
	return r
}

// update removes deleted and (re)adds added with their own limit; a
// re-added user loses a penalty.
func (r *rateLimits) update(added, deleted []panel.UserInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range deleted {
		delete(r.users, u.Uuid)
	}
	for _, u := range added {
		r.users[u.Uuid] = &userRate{own: mbpsToBytes(u.SpeedLimit)}
	}
}

// penalize limits uuid to mbps until ends.
func (r *rateLimits) penalize(uuid string, mbps int, ends time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if u, ok := r.users[uuid]; ok {
		u.penalty, u.penaltyEnds = mbpsToBytes(mbps), ends
	}
}

// rate is uuid's effective limit now.
func (r *rateLimits) rate(uuid string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	rate := r.node
	if u, ok := r.users[uuid]; ok {
		rate = lowestLimit(rate, u.own)
		if time.Now().Before(u.penaltyEnds) {
			rate = lowestLimit(rate, u.penalty)
		}
	}
	return rate
}

// lowestLimit is the lower of two limits where 0 is none.
func lowestLimit(a, b int) int {
	if a == 0 || (b != 0 && b < a) {
		return b
	}
	return a
}

func mbpsToBytes(mbps int) int {
	if mbps <= 0 {
		return 0
	}
	return int(int64(mbps) * 1_000_000 / 8)
}
