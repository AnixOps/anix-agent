package forward

import (
	"sync"
	"time"

	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"google.golang.org/protobuf/proto"
)

// DefaultRetiredKeep is how long the last counters of an ended counter
// epoch ride in the reports. A PackageReport is never acknowledged, so the
// final values go out in every report for a while: Control keeps the
// largest value per (node, route, hop, epoch), so repeating them counts
// nothing twice, and a lost report loses nothing.
const DefaultRetiredKeep = 10 * time.Minute

// Retired collects the last counters of the counter epochs a driver's Apply
// ended (removed hops, a gost reload): the drivers' WithRetiredCounters
// hook. The drivers call it from inside Apply, so it takes only its own
// lock. It is safe for concurrent use.
type Retired struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[counterKey]retiredEntry
}

type counterKey struct {
	route string
	hop   uint32
	epoch string
}

type retiredEntry struct {
	counters *forwardv1.Counters
	at       time.Time
}

// NewRetired answers an empty buffer.
func NewRetired() *Retired {
	return &Retired{now: time.Now, entries: map[counterKey]retiredEntry{}}
}

// Add records counters; pass it to the drivers' WithRetiredCounters.
func (r *Retired) Add(counters []*forwardv1.Counters) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for _, c := range counters {
		if c == nil || c.GetCounterEpoch() == "" {
			continue
		}
		k := keyOfCounters(c)
		if old, ok := r.entries[k]; ok && total(old.counters) > total(c) {
			continue
		}
		r.entries[k] = retiredEntry{counters: proto.Clone(c).(*forwardv1.Counters), at: now}
	}
}

// take answers the counters still kept, dropping those older than keep.
func (r *Retired) take(keep time.Duration) []*forwardv1.Counters {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	out := make([]*forwardv1.Counters, 0, len(r.entries))
	for k, e := range r.entries {
		if now.Sub(e.at) > keep {
			delete(r.entries, k)
			continue
		}
		out = append(out, proto.Clone(e.counters).(*forwardv1.Counters))
	}
	return out
}

func keyOfCounters(c *forwardv1.Counters) counterKey {
	return counterKey{route: c.GetRouteId(), hop: c.GetHopIndex(), epoch: c.GetCounterEpoch()}
}

// total orders two readings of one epoch: cumulative fields never
// decrease within it.
func total(c *forwardv1.Counters) uint64 {
	return c.GetUpBytes() + c.GetDownBytes() + c.GetUpPackets() + c.GetDownPackets() + c.GetTotalConns()
}
