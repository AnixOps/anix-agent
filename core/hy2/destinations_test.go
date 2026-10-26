package hy2

import (
	"testing"

	"github.com/AnixOps/anix-agent/v5/common/destinations"
	"github.com/apernet/hysteria/core/v2/server"
	"github.com/stretchr/testify/assert"
)

func TestTracedStreamsCountTowardTheirDestinationEachWindow(t *testing.T) {
	hook := &HookServer{Tag: "in", destinations: destinations.NewCollector()}
	stats := &server.StreamStats{AuthID: "alice"}
	var stream server.HyStream
	hook.TraceStream(stream, stats)

	// No request yet: nothing to count.
	assert.Empty(t, hook.destinationSnapshot())
	stats.ReqAddr.Store("1.2.3.4:443")
	stats.HookedReqAddr.Store("www.youtube.com:443")
	stats.Tx.Add(10)
	stats.Rx.Add(1000)
	assert.Equal(t, []destinations.Entry{{User: "alice", Domain: "youtube.com", Upload: 10, Download: 1000, Connections: 1}}, hook.destinationSnapshot())

	stats.Rx.Add(5)
	hook.UntraceStream(stream)
	hook.UntraceStream(stream)
	assert.Equal(t, []destinations.Entry{{User: "alice", Domain: "youtube.com", Download: 5}}, hook.destinationSnapshot())
	assert.Empty(t, hook.destinationSnapshot())
	assert.Empty(t, (&HookServer{}).destinationSnapshot())
}
