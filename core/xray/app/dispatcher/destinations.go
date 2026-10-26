package dispatcher

import (
	"context"
	"sync/atomic"

	"github.com/AnixOps/anix-agent/v5/common/destinations"
	fstats "github.com/xtls/xray-core/features/stats"
)

// Destination statistics (destinations.v1). A user's link counts its bytes
// before its destination is known (the sniffing reads the first bytes), so
// its counters go through a destinationBinding that holds them until
// routedDispatch, past the sniffing, binds the link to the destination's
// Stat. The binding rides the dispatch's context.

type destinationBindingKey struct{}

// destinationBinding forwards a link's bytes to its destination Stat once
// bound, and keeps them until then.
type destinationBinding struct {
	stat     atomic.Pointer[destinations.Stat]
	upload   atomic.Int64
	download atomic.Int64
}

func contextWithDestinationBinding(ctx context.Context) context.Context {
	return context.WithValue(ctx, destinationBindingKey{}, &destinationBinding{})
}

func destinationBindingFromContext(ctx context.Context) *destinationBinding {
	binding, _ := ctx.Value(destinationBindingKey{}).(*destinationBinding)
	return binding
}

func (b *destinationBinding) add(delta int64, download bool) {
	if b == nil || delta <= 0 {
		return
	}
	stat := b.stat.Load()
	switch {
	case stat != nil && download:
		stat.Download.Add(delta)
	case stat != nil:
		stat.Upload.Add(delta)
	case download:
		b.download.Add(delta)
	default:
		b.upload.Add(delta)
	}
}

// flush moves the bytes held before the binding to the Stat.
func (b *destinationBinding) flush(stat *destinations.Stat) {
	stat.Upload.Add(b.upload.Swap(0))
	stat.Download.Add(b.download.Swap(0))
}

func (b *destinationBinding) bind(stat *destinations.Stat) {
	b.stat.Store(stat)
	b.flush(stat)
}

// release ends the link's connection on its Stat: bytes that raced the
// binding are moved to it first.
func (b *destinationBinding) release() {
	if stat := b.stat.Load(); stat != nil {
		b.flush(stat)
		stat.Release()
	}
}

var _ fstats.Counter = (*destinationCounter)(nil)

// destinationCounter is a user's upload or download counter that also
// counts toward the link's destination.
type destinationCounter struct {
	user     *atomic.Int64
	binding  *destinationBinding
	download bool
}

func (c *destinationCounter) Value() int64 {
	return c.user.Load()
}

func (c *destinationCounter) Set(newValue int64) int64 {
	return c.user.Swap(newValue)
}

func (c *destinationCounter) Add(delta int64) int64 {
	c.binding.add(delta, c.download)
	return c.user.Add(delta)
}

// openDestination binds the dispatch's link to the destination's Stat;
// the caller releases the binding when the link ends. nil without a
// binding (a link without a user).
func (d *DefaultDispatcher) openDestination(ctx context.Context, tag, user, host, protocol string) *destinationBinding {
	binding := destinationBindingFromContext(ctx)
	if binding == nil || user == "" {
		return nil
	}
	stat := d.Destinations.Get(tag).Open(user, host, protocol)
	if stat == nil {
		return nil
	}
	binding.bind(stat)
	return binding
}
