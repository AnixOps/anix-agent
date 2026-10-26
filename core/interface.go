package core

import (
	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/common/destinations"
	"github.com/AnixOps/anix-agent/v5/conf"
)

type AddUsersParams struct {
	Tag   string
	Users []panel.UserInfo
	*panel.NodeInfo
}

type Core interface {
	Start() error
	Close() error
	AddNode(tag string, info *panel.NodeInfo, config *conf.Options) error
	DelNode(tag string) error
	AddUsers(p *AddUsersParams) (added int, err error)
	GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error)
	DelUsers(users []panel.UserInfo, tag string, info *panel.NodeInfo) error
	Protocols() []string
	Type() string
}

type OnlineDeviceProvider interface {
	GetOnlineDevice(tag string) ([]panel.OnlineUser, error)
}

// RuntimeHealthProvider exposes process-level health for cores that supervise
// external runtime components. WireGuard uses it for the GOST relay process.
type RuntimeHealthProvider interface {
	RuntimeHealth(tag string) (healthy bool, message string)
}

// RateLimitUpdater is implemented by cores whose runtime can enforce a
// per-user rate outside the protocol parser. WireGuard uses Linux tc rules
// keyed by each peer address; the existing proxy cores keep their own limiter
// hooks and do not need to implement this optional interface.
type RateLimitUpdater interface {
	UpdateUserRateLimit(tag, uuid string, speedLimit int) error
}

// TrafficRollbacker lets a core restore a traffic cursor when the panel
// rejected an otherwise successfully sampled report. It is optional because
// existing proxy cores do not expose reversible counters.
type TrafficRollbacker interface {
	RollbackUserTrafficSlice(tag string, traffic []panel.UserTraffic) error
}

// DestinationProvider is implemented by cores that count each user's
// traffic by destination (destinations.v1): the sing-box, Xray and
// Hysteria 2 cores. GetDestinationTraffic returns tag's traffic since the
// last call.
type DestinationProvider interface {
	GetDestinationTraffic(tag string) ([]destinations.Traffic, error)
}

// EgressApplier is implemented by cores that run a node's egress routes
// (panel.EgressConfig): the Xray core. ApplyEgress replaces what the core
// ran from the previous call; an empty configuration removes it all.
type EgressApplier interface {
	ApplyEgress(config *panel.EgressConfig) error
}
