package agent

import (
	"context"
	"maps"
	"sync/atomic"
	"time"

	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	log "github.com/sirupsen/logrus"
)

// The alive list from the stream (alive.v1; PROTOCOL.md, "Alive list"):
// every user's number of online devices across all nodes, what UniProxy
// alivelist answers. One list may span several AliveList pages of the same
// revision; the data plane buffers them and replaces its whole list when the
// page with last_page arrives (a user missing from it has no device
// online). Pages of a session that ended before last_page are dropped: a
// reconnect starts with a new list.

// maxAliveEntries bounds the entries of one list held until its last page.
const maxAliveEntries = 10_000_000

// Heartbeat metric keys of the alive list.
const (
	// MetricAliveRevision is the revision of the last complete list.
	MetricAliveRevision = "agent_dataplane_alive_revision"
	// MetricAliveUsers is the number of users with a device online in it.
	MetricAliveUsers = "agent_dataplane_alive_users"
)

// AliveApplier applies alive lists (alive.v1).
type AliveApplier interface {
	// ApplyAlive makes the node's device limits count alive: online device
	// counts by user id, every user missing from it at 0. Calls come from
	// one goroutine, newest list only.
	ApplyAlive(ctx context.Context, alive map[uint64]uint32)
}

// aliveState is the alive-list part of the data plane, guarded by
// DataPlane.mu.
type aliveState struct {
	// pages buffers the list being received on pagesSession at
	// pagesRevision.
	pages         map[uint64]uint32
	pagesSession  string
	pagesRevision uint64
	pagesOverflow bool
	// list is the last complete list, has once there is one.
	list     map[uint64]uint32
	has      bool
	revision uint64
	// pending is set when list was not handed to the applier yet.
	pending bool
	arrived chan struct{}
	lists   atomic.Uint64
}

// receiveAlive takes an AliveList page from the session's receive loop.
func (d *DataPlane) receiveAlive(sessionID string, page *agentv1pb.AliveList) {
	if page == nil || d.config.Alive == nil {
		return
	}
	d.mu.Lock()
	alive := &d.alive
	if alive.pages == nil || alive.pagesSession != sessionID || alive.pagesRevision != page.GetRevision() {
		// A new list: a half-received one of another revision is dropped.
		alive.pages, alive.pagesSession, alive.pagesRevision, alive.pagesOverflow = map[uint64]uint32{}, sessionID, page.GetRevision(), false
	}
	for _, entry := range page.GetEntries() {
		if entry.GetUserId() == 0 || entry.GetAliveCount() == 0 {
			continue
		}
		if len(alive.pages) >= maxAliveEntries {
			alive.pagesOverflow = true
			break
		}
		alive.pages[entry.GetUserId()] = entry.GetAliveCount()
	}
	if !page.GetLastPage() {
		d.mu.Unlock()
		return
	}
	complete, overflow, revision := alive.pages, alive.pagesOverflow, alive.pagesRevision
	alive.pages, alive.pagesSession, alive.pagesRevision, alive.pagesOverflow = nil, "", 0, false
	if overflow {
		d.mu.Unlock()
		d.logger().WithFields(log.Fields{"revision": revision, "limit": maxAliveEntries}).
			Warn("Dropping an alive list from Control that exceeds the Agent's bound; the previous list stays in force")
		return
	}
	alive.list, alive.has, alive.revision, alive.pending = complete, true, revision, true
	close(alive.arrived)
	alive.arrived = make(chan struct{})
	d.mu.Unlock()
	d.alive.lists.Add(1)
	d.signal()
}

// dropAlivePagesLocked drops the pages of a list sessionID did not finish.
// d.mu is held.
func (d *DataPlane) dropAlivePagesLocked(sessionID string) {
	if d.alive.pagesSession == sessionID {
		d.alive.pages, d.alive.pagesSession, d.alive.pagesRevision, d.alive.pagesOverflow = nil, "", 0, false
	}
}

// AliveList returns a copy of the last complete alive list from Control,
// ok false before the first one.
func (d *DataPlane) AliveList() (map[uint64]uint32, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.alive.has {
		return nil, false
	}
	return maps.Clone(d.alive.list), true
}

// WaitAlive waits up to timeout for a complete alive list, for a node
// starting on the stream; ok false without one.
func (d *DataPlane) WaitAlive(ctx context.Context, timeout time.Duration) (map[uint64]uint32, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		d.mu.Lock()
		has, arrived := d.alive.has, d.alive.arrived
		d.mu.Unlock()
		if has {
			return d.AliveList()
		}
		select {
		case <-ctx.Done():
			return nil, false
		case <-d.ctx.Done():
			return nil, false
		case <-timer.C:
			return nil, false
		case <-arrived:
		}
	}
}

// applyPendingAlive hands a new complete list to the applier.
func (d *DataPlane) applyPendingAlive() {
	if d.config.Alive == nil {
		return
	}
	d.mu.Lock()
	if !d.alive.pending {
		d.mu.Unlock()
		return
	}
	d.alive.pending = false
	list := maps.Clone(d.alive.list)
	d.mu.Unlock()
	d.config.Alive.ApplyAlive(d.ctx, list)
}

// aliveMetrics are the alive list's heartbeat metrics.
func (d *DataPlane) aliveMetrics(metrics map[string]float64) {
	if d.config.Alive == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	metrics[MetricAliveRevision] = float64(d.alive.revision)
	metrics[MetricAliveUsers] = float64(len(d.alive.list))
}
