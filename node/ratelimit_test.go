package node

import (
	"sync"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/stretchr/testify/assert"
)

func TestRateLimits(t *testing.T) {
	assert.Equal(t, 0, bytesPerSecond(-1))
	assert.Equal(t, 0, bytesPerSecond(0))
	assert.Equal(t, 125_000, bytesPerSecond(1))

	rates := newRateLimits(0, []panel.UserInfo{{Uuid: "free"}, {Uuid: "own", SpeedLimit: 8}})
	assert.Equal(t, 0, rates.rate("free"), "no limit")
	assert.Equal(t, 1_000_000, rates.rate("own"))
	assert.Equal(t, 0, rates.rate("unknown"))

	rates = newRateLimits(16, []panel.UserInfo{{Uuid: "free"}, {Uuid: "own", SpeedLimit: 8}, {Uuid: "fast", SpeedLimit: 80}})
	assert.Equal(t, 2_000_000, rates.rate("free"), "the node limit")
	assert.Equal(t, 1_000_000, rates.rate("own"), "the lower own limit")
	assert.Equal(t, 2_000_000, rates.rate("fast"), "the lower node limit")
	assert.Equal(t, 2_000_000, rates.rate("unknown"))

	// Penalties hold until they expire; an unknown user is ignored.
	rates.penalize("fast", 4, time.Now().Add(time.Hour))
	rates.penalize("own", 4, time.Now().Add(-time.Second))
	rates.penalize("unknown", 1, time.Now().Add(time.Hour))
	assert.Equal(t, 500_000, rates.rate("fast"))
	assert.Equal(t, 1_000_000, rates.rate("own"), "an expired penalty")
	assert.Equal(t, 2_000_000, rates.rate("unknown"))
	rates.penalize("free", 0, time.Now().Add(time.Hour))
	assert.Equal(t, 2_000_000, rates.rate("free"), "a penalty of 0 is no limit")

	// Removed users go; a re-added user has no penalty.
	rates.update([]panel.UserInfo{{Uuid: "fast", SpeedLimit: 80}, {Uuid: "new", SpeedLimit: 1}}, []panel.UserInfo{{Uuid: "fast"}, {Uuid: "own"}})
	assert.Equal(t, 2_000_000, rates.rate("fast"))
	assert.Equal(t, 125_000, rates.rate("new"))
	assert.NotContains(t, rates.users, "own")
}

func TestRateLimitsAreSafeForConcurrentUse(t *testing.T) {
	rates := newRateLimits(1, nil)
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() {
			user := panel.UserInfo{Uuid: string(rune('a' + i)), SpeedLimit: i}
			for range 100 {
				rates.update([]panel.UserInfo{user}, nil)
				rates.penalize(user.Uuid, 1, time.Now().Add(time.Second))
				_ = rates.rate(user.Uuid)
			}
		})
	}
	wg.Wait()
	assert.Len(t, rates.users, 4)
}
