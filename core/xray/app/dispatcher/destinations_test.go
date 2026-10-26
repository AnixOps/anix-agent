package dispatcher

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/AnixOps/anix-agent/v5/common/destinations"
	"github.com/stretchr/testify/assert"
)

func TestDestinationCounterHoldsTheBytesUntilTheLinkIsBound(t *testing.T) {
	d := &DefaultDispatcher{}
	ctx := contextWithDestinationBinding(context.Background())
	binding := destinationBindingFromContext(ctx)
	var userUp, userDown atomic.Int64
	up := &destinationCounter{user: &userUp, binding: binding}
	down := &destinationCounter{user: &userDown, binding: binding, download: true}

	// The sniffed first bytes, before the destination is known.
	up.Add(40)
	down.Add(0)
	assert.Nil(t, d.openDestination(context.Background(), "in", "alice", "www.youtube.com", "tls"), "no binding: no user link")
	assert.Nil(t, d.openDestination(ctx, "in", "", "www.youtube.com", "tls"))
	bound := d.openDestination(ctx, "in", "alice", "www.youtube.com", "tls")
	assert.Same(t, binding, bound)
	up.Add(60)
	down.Add(1000)
	bound.release()

	assert.Equal(t, int64(100), userUp.Load(), "the user's counter counts every byte")
	assert.Equal(t, int64(1000), down.Value())
	assert.Equal(t, []destinations.Entry{{User: "alice", Domain: "youtube.com", Protocol: "tls", Upload: 100, Download: 1000, Connections: 1}}, d.Destinations.Snapshot("in"))
	assert.Empty(t, d.Destinations.Snapshot("in"))
}
