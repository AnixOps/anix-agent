package dispatcher

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/common/destinations"
	"github.com/AnixOps/anix-agent/v5/conf"
	"github.com/AnixOps/anix-agent/v5/limiter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
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

// The link's counters and routedDispatch must share one binding: Dispatch
// puts it on the context, getLink counts into it, and the routing binds it.
func TestDispatchLinkCountsIntoTheBindingTheRoutingBinds(t *testing.T) {
	limiter.Init()
	limiter.AddLimiter("in", &conf.LimitConfig{}, []panel.UserInfo{{Id: 1, Uuid: "alice"}}, nil)
	defer limiter.DeleteLimiter("in")
	d := &DefaultDispatcher{}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:    "in",
		User:   &protocol.MemoryUser{Email: "in|alice"},
		Source: net.TCPDestination(net.ParseAddress("192.0.2.1"), 40000),
	})
	ctx = contextWithDestinationBinding(ctx)

	inbound, outbound, _, err := d.getLink(ctx, net.Network_TCP)
	require.NoError(t, err)
	// The client's first bytes, read before the destination is sniffed.
	require.NoError(t, inbound.Writer.WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, 40))))
	bound := d.openDestination(ctx, "in", "in|alice", "www.youtube.com", "tls")
	require.NotNil(t, bound)
	require.NoError(t, outbound.Writer.WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, 1000))))
	bound.release()

	assert.Equal(t, []destinations.Entry{{User: "in|alice", Domain: "youtube.com", Protocol: "tls", Upload: 40, Download: 1000, Connections: 1}}, d.Destinations.Snapshot("in"))
}
