package client

import (
	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/common/monitor"
)

// NodeAPI defines the contract required by node controllers regardless of transport.
// Implementations can be REST (api/panel) or gRPC (api/grpc).
type NodeAPI interface {
	GetNodeInfo() (*panel.NodeInfo, error)
	GetUserList() ([]panel.UserInfo, error)
	GetUserAlive() (map[int]int, error)
	ReportUserTraffic([]panel.UserTraffic) error
	ReportNodeOnlineUsers(*map[int][]string) error
	ReportNodeStatus(*monitor.SystemInfo, int, int64, int64) error
	ReportNodeLogs([]panel.NodeLogEntry) error

	GetNodeID() int
	GetAPIHost() string
	GetAPIKey() string
	GetSecret() string
	IsSignEnabled() bool
	SetNodeType(string)
	SupportsSync() bool
	Close() error
}

// RuntimeHealthReporter is implemented by transports that can report a
// supervised core's process health without changing the legacy heartbeat
// payload contract.
type RuntimeHealthReporter interface {
	ReportNodeRuntimeHealth(healthy bool, message string) error
}
