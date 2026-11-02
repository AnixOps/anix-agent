package forward

import (
	"context"
	"os"
	"slices"
	"strings"
	"time"

	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"github.com/AnixOps/anix-control/sdk/forward/wire"
)

// HostInfo is what NodeCapabilities says about the host besides the
// engines.
type HostInfo struct {
	KernelVersion string
	// Cgroup is "v1" or "v2".
	Cgroup string
	IPv6   bool
}

// ProbeHost reads HostInfo from /proc and /sys.
func ProbeHost() HostInfo {
	info := HostInfo{Cgroup: "v1"}
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		info.KernelVersion = truncate(strings.TrimSpace(string(data)), 128)
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		info.Cgroup = "v2"
	}
	if _, err := os.Stat("/proc/net/if_inet6"); err == nil {
		info.IPv6 = true
	}
	return info
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// capabilitiesTimeout bounds the drivers' Capabilities calls.
const capabilitiesTimeout = 10 * time.Second

// NodeCapabilities answers what the node can forward: no engine (every
// forward driver was removed; the retired engines are listed with available
// false and the reason), the host and the Agent's version.
func (c *Component) NodeCapabilities(context.Context) (*forwardv1.NodeCapabilities, error) {
	caps := &forwardv1.NodeCapabilities{
		NodeRef:       c.nodeRef,
		KernelVersion: c.opts.Host.KernelVersion,
		Cgroup:        c.opts.Host.Cgroup,
		Ipv6:          c.opts.Host.IPv6,
		AgentVersion:  truncate(c.opts.AgentVersion, wire.MaxTextBytes),
	}
	for _, retired := range retiredEngines {
		caps.Engines = append(caps.Engines, &forwardv1.EngineCapabilities{Engine: retired.engine, UnavailableReason: retired.reason})
	}
	slices.SortFunc(caps.Engines, func(a, b *forwardv1.EngineCapabilities) int { return int(a.GetEngine()) - int(b.GetEngine()) })
	return caps, nil
}

// HelloCapability implements agent.ForwardHandler: forward.v1 with the
// node's capabilities in its attribute (wire.HelloCapability).
func (c *Component) HelloCapability() (*agentv1pb.Capability, error) {
	caps, err := c.NodeCapabilities(c.ctx)
	if err != nil {
		return nil, err
	}
	return wire.HelloCapability(caps)
}
