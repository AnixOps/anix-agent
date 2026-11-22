package node

import (
	"sync"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
)

// rateLimits holds a node's speed limits per user, in bytes per second
// (0 is no limit).
type rateLimits struct {
	mu    sync.Mutex
	node  int
	users map[string]*userRate
}

// userRate is a user's own limit and a penalty of the dynamic speed limit
// that holds until until.
type userRate struct {
	own     int
	penalty int
	until   time.Time
}

// bytesPerSecond converts Mbps to bytes per second.
func bytesPerSecond(mbps int) int {
	if mbps <= 0 {
		return 0
	}
	return mbps * 1_000_000 / 8
}

func newRateLimits(nodeMbps int, users []panel.UserInfo) *rateLimits {
	r := &rateLimits{node: bytesPerSecond(nodeMbps), users: make(map[string]*userRate, len(users))}
	r.update(users, nil)
	return r
}

// update drops removed and (re)adds added, without penalty.
func (r *rateLimits) update(added, removed []panel.UserInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, user := range removed {
		delete(r.users, user.Uuid)
	}
	for _, user := range added {
		r.users[user.Uuid] = &userRate{own: bytesPerSecond(user.SpeedLimit)}
	}
}

// penalize limits uuid to mbps until until.
func (r *rateLimits) penalize(uuid string, mbps int, until time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if user, ok := r.users[uuid]; ok {
		user.penalty, user.until = bytesPerSecond(mbps), until
	}
}

// rate is the lowest non-zero of the node limit, the user's own limit and
// an unexpired penalty.
func (r *rateLimits) rate(uuid string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	rate := r.node
	user, ok := r.users[uuid]
	if !ok {
		return rate
	}
	rate = lowerLimit(rate, user.own)
	if time.Now().Before(user.until) {
		rate = lowerLimit(rate, user.penalty)
	}
	return rate
}

// lowerLimit is the lower of two limits, 0 being none.
func lowerLimit(a, b int) int {
	if a == 0 || (b != 0 && b < a) {
		return b
	}
	return a
}
