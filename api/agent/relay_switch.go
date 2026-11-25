package agent

import (
	"context"
	"sync/atomic"

	"google.golang.org/grpc"
)

// RelaySwitch carries a client's connections to Control through region
// relays that can change while the client runs: Control pushes a node's
// route in its desired configuration (the member "control_route", anix-control
// docs/design/region-relay). Every new connection takes the relays current at
// that moment; a connection already open stays on the relays it took. Nil
// relays dial Control directly.
type RelaySwitch struct {
	current atomic.Pointer[Relays]
}

// NewRelaySwitch answers a switch that starts with relays (nil: direct).
func NewRelaySwitch(relays *Relays) *RelaySwitch {
	s := &RelaySwitch{}
	s.current.Store(relays)
	return s
}

// Set makes relays (nil: direct) carry the next connections.
func (s *RelaySwitch) Set(relays *Relays) { s.current.Store(relays) }

// Current answers the relays that carry new connections, nil for direct.
func (s *RelaySwitch) Current() *Relays { return s.current.Load() }

// DialContext wraps dial so that every gRPC connection it opens goes
// through the relays current when it opens. The target and every option
// stay as they are.
func (s *RelaySwitch) DialContext(dial DialContextFunc) DialContextFunc {
	if dial == nil {
		dial = grpc.DialContext
	}
	return func(ctx context.Context, target string, options ...grpc.DialOption) (*grpc.ClientConn, error) {
		relays := s.Current()
		if relays == nil {
			return dial(ctx, target, options...)
		}
		return dial(ctx, target, append(append([]grpc.DialOption(nil), options...), grpc.WithContextDialer(relays.Dial))...)
	}
}
