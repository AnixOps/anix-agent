package hy2

import (
	"sync"

	"github.com/AnixOps/anix-agent/v5/common/destinations"
	"github.com/apernet/hysteria/core/v2/server"
)

// Destination statistics (destinations.v1): Hysteria traces each TCP
// stream with its request address (the sniffed domain when sniffing
// rewrote it) and byte counters; the window's bytes of every stream are
// read into the node's collector when it is read and when the stream ends.
// UDP sessions are not traced and count nowhere.

type tracedStream struct {
	mu     sync.Mutex
	stats  *server.StreamStats
	stat   *destinations.Stat
	tx, rx uint64
	ended  bool
}

// drain adds the stream's bytes since the last drain to its destination.
func (t *tracedStream) drain(collector *destinations.Collector) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ended {
		return
	}
	if t.stat == nil {
		addr := t.stats.HookedReqAddr.Load()
		if addr == "" {
			addr = t.stats.ReqAddr.Load()
		}
		if addr == "" {
			return
		}
		if t.stat = collector.Open(t.stats.AuthID, addr, ""); t.stat == nil {
			return
		}
	}
	tx, rx := t.stats.Tx.Load(), t.stats.Rx.Load()
	t.stat.Upload.Add(int64(tx - t.tx))   // #nosec G115 -- a window's bytes.
	t.stat.Download.Add(int64(rx - t.rx)) // #nosec G115 -- a window's bytes.
	t.tx, t.rx = tx, rx
}

func (t *tracedStream) end(collector *destinations.Collector) {
	t.drain(collector)
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.ended && t.stat != nil {
		t.stat.Release()
	}
	t.ended = true
}

func (h *HookServer) TraceStream(stream server.HyStream, stats *server.StreamStats) {
	if h.destinations != nil && stats != nil {
		h.streams.Store(stream, &tracedStream{stats: stats})
	}
}

func (h *HookServer) UntraceStream(stream server.HyStream) {
	if traced, ok := h.streams.LoadAndDelete(stream); ok {
		traced.(*tracedStream).end(h.destinations)
	}
}

// destinationSnapshot returns the node's traffic by destination since the
// last call.
func (h *HookServer) destinationSnapshot() []destinations.Entry {
	if h.destinations == nil {
		return nil
	}
	h.streams.Range(func(_, traced any) bool {
		traced.(*tracedStream).drain(h.destinations)
		return true
	})
	return h.destinations.Snapshot()
}

// GetDestinationTraffic returns tag's traffic by destination since the last
// call, for the users the core knows.
func (h *Hysteria2) GetDestinationTraffic(tag string) ([]destinations.Traffic, error) {
	h.Auth.mutex.RLock()
	node, ok := h.Hy2nodes[tag]
	h.Auth.mutex.RUnlock()
	if !ok {
		return nil, nil
	}
	hook, ok := node.TrafficLogger.(*HookServer)
	if !ok {
		return nil, nil
	}
	entries := hook.destinationSnapshot()
	if len(entries) == 0 {
		return nil, nil
	}
	h.Auth.mutex.RLock()
	defer h.Auth.mutex.RUnlock()
	return destinations.Resolve(entries, func(user string) int { return h.Auth.usersMap[user] }), nil
}
