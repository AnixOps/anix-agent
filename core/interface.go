package core

import (
	"context"
	"encoding/json"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/common/destinations"
	"github.com/AnixOps/anix-agent/v5/conf"
	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
)

// Core runs nodes (each under a tag the controller picks) and their users.
type Core interface {
	Start() error
	Close() error
	// Type names the core; Protocols are the node types it serves.
	Type() string
	Protocols() []string

	AddNode(tag string, info *panel.NodeInfo, options *conf.Options) error
	DelNode(tag string) error
	// AddUsers adds or updates users and answers how many it added.
	AddUsers(tag string, info *panel.NodeInfo, users []panel.UserInfo) (int, error)
	DelUsers(tag string, info *panel.NodeInfo, users []panel.UserInfo) error
	// UserTraffic is each user's traffic since the last call that reset.
	UserTraffic(tag string, reset bool) ([]panel.UserTraffic, error)
}

// The optional interfaces below are implemented by the cores that can.

// OnlineDeviceProvider reports the IPs users are connected from.
type OnlineDeviceProvider interface {
	GetOnlineDevice(tag string) ([]panel.OnlineUser, error)
}

// RuntimeHealthProvider exposes process-level health for cores that supervise
// external runtime components. WireGuard uses it for the GOST relay process.
type RuntimeHealthProvider interface {
	RuntimeHealth(tag string) (healthy bool, message string)
}

// RateLimitUpdater sets a user's rate (bytes per second, 0 for none)
// outside the protocol: WireGuard shapes each peer address with tc.
type RateLimitUpdater interface {
	UpdateUserRateLimit(tag, uuid string, speedLimit int) error
}

// TrafficRollbacker gives a traffic window that Control did not take back
// to the core's counters, for the next report.
type TrafficRollbacker interface {
	RollbackUserTraffic(tag string, traffic []panel.UserTraffic) error
}

// DestinationProvider is implemented by cores that count each user's
// traffic by destination (destinations.v1): anixcore, when the kernel has
// the `destinations` feature. GetDestinationTraffic returns tag's traffic since the
// last call.
type DestinationProvider interface {
	GetDestinationTraffic(tag string) ([]destinations.Traffic, error)
}

// EgressApplier is implemented by cores that run a node's egress routes
// (panel.EgressConfig): the anixcore core. ApplyEgress replaces what the core
// ran from the previous call; an empty configuration removes it all.
type EgressApplier interface {
	ApplyEgress(config *panel.EgressConfig) error
}

// QoSApplier is implemented by cores that run Control's traffic
// priorities and per-user class caps (the member "qos" of a node's
// configuration, panel.ParseQoS): the anixcore core. ApplyQoS replaces
// what the previous call set; nil turns them off.
type QoSApplier interface {
	ApplyQoS(config json.RawMessage) error
}

// ExitPolicyApplier is implemented by cores that run Control's exit policy
// (the member "exit_policy" of a node's configuration,
// panel.ParseExitPolicy): the anixcore core. ApplyExitPolicy replaces what
// the previous call set; the zero policy turns it off.
type ExitPolicyApplier interface {
	ApplyExitPolicy(policy panel.ExitPolicy) error
}

// MainlandCounter is implemented by cores that count the connections their
// exit policy refused to mainland-China addresses; MainlandBlocked reads
// and resets the count.
type MainlandCounter interface {
	MainlandBlocked(ctx context.Context) (uint64, error)
}

// NetworkApplier is implemented by cores that run the device network model
// (anixops.network.v1, anix-control docs/design/network-model): the anixcore
// core. NetworkKinds lists the components the core runs, empty when it runs
// none. ApplyNetwork replaces the device's plan (nil removes it) and
// answers the core's status of it; NetworkStatus reads that status again.
type NetworkApplier interface {
	NetworkKinds() []*networkv1.KindSupport
	ApplyNetwork(plan *networkv1.NetworkPlan) (*networkv1.NetworkStatus, error)
	NetworkStatus() (*networkv1.NetworkStatus, error)
}
