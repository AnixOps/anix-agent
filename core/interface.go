package core

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/common/destinations"
	"github.com/AnixOps/anix-agent/v5/conf"
	networkv1 "github.com/AnixOps/anix-control/sdk/api/network/v1"
)

// ErrNodeNotFound is answered for a tag the core does not run.
var ErrNodeNotFound = errors.New("the node is not have")

// Core is a proxy kernel that runs nodes and their users.
type Core interface {
	Start() error
	Close() error
	Type() string
	Protocols() []string
	AddNode(tag string, info *panel.NodeInfo, options *conf.Options) error
	DelNode(tag string) error
	AddUsers(tag string, info *panel.NodeInfo, users []panel.UserInfo) (added int, err error)
	DelUsers(tag string, info *panel.NodeInfo, users []panel.UserInfo) error
	UserTraffic(tag string, reset bool) ([]panel.UserTraffic, error)
}

// OnlineDeviceProvider reports a node's online devices.
type OnlineDeviceProvider interface {
	GetOnlineDevice(tag string) ([]panel.OnlineUser, error)
}

// RuntimeHealthProvider reports whether a node runs as configured.
type RuntimeHealthProvider interface {
	RuntimeHealth(tag string) (healthy bool, message string)
}

// RateLimitUpdater applies a user's speed limit inside the core.
type RateLimitUpdater interface {
	UpdateUserRateLimit(tag, uuid string, bytesPerSecond int) error
}

// DestinationProvider reports per-user destination statistics.
type DestinationProvider interface {
	GetDestinationTraffic(tag string) ([]destinations.Traffic, error)
}

// EgressApplier runs the device's egress routes.
type EgressApplier interface {
	ApplyEgress(config *panel.EgressConfig) error
}

// QoSApplier runs the device's traffic shaping.
type QoSApplier interface {
	ApplyQoS(config json.RawMessage) error
}

// ExitPolicyApplier runs the device's exit policy.
type ExitPolicyApplier interface {
	ApplyExitPolicy(policy panel.ExitPolicy) error
}

// MainlandCounter counts the connections the exit policy blocked.
type MainlandCounter interface {
	MainlandBlocked(ctx context.Context) (uint64, error)
}

// NetworkApplier runs the device network model.
type NetworkApplier interface {
	NetworkKinds() []*networkv1.KindSupport
	ApplyNetwork(plan *networkv1.NetworkPlan) (*networkv1.NetworkStatus, error)
	NetworkStatus() (*networkv1.NetworkStatus, error)
}

// TemporaryProxyApplier runs the node's temporary internal proxies (the
// member "temporary_proxies"): it replaces the set it runs with proxies,
// skipping the expired ones.
type TemporaryProxyApplier interface {
	ApplyTemporaryProxies(proxies []panel.TemporaryProxy) error
}

// MeshApplier runs the node's intranet mesh networks (the member "mesh").
type MeshApplier interface {
	// MeshSupported tells whether the running kernel has the mesh.
	MeshSupported() bool
	// MeshNativeKeysSupported tells whether it takes native_keys, without
	// which it cannot hold a managed network to the operator's own nodes.
	MeshNativeKeysSupported() bool
	// MeshExternalBridgeSupported tells whether it takes a network's
	// external_bridge.
	MeshExternalBridgeSupported() bool
	// MeshPathsSupported tells whether it applies a network's
	// routing.paths (feature mesh_paths).
	MeshPathsSupported() bool
	// MeshRegionProbeSupported tells whether it takes the top-level region
	// of its mesh configuration and answers region_probe (feature
	// mesh_region_probe).
	MeshRegionProbeSupported() bool
	// SetMeshRegion sets the region sent with the next ApplyMesh and with
	// each replay; nil or null sends none. It is sent only to a kernel
	// that takes it.
	SetMeshRegion(region json.RawMessage)
	// ApplyMesh replaces the networks the kernel runs; none stops them.
	ApplyMesh(networks []panel.MeshNetwork) error
	// MeshStatus answers the kernel's instance id, each network as the
	// kernel runs it (by ID) and the region requests it holds.
	MeshStatus(ctx context.Context) (panel.MeshState, error)
	// DoneMeshRegionRequest drops a region request from the kernel once
	// it went to Control or can never go.
	DoneMeshRegionRequest(ctx context.Context, id string) error
}
