package agent

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/status"
)

// Heartbeat metric keys the client adds next to the MetricsProvider's. The
// Agent has no metrics endpoint of its own; Control records heartbeat metrics
// per node.
const (
	// MetricUnnegotiatedPayloads counts the data-plane payloads Control sent
	// without the capability negotiated on the session; the Agent drops them.
	MetricUnnegotiatedPayloads = "agent_control_unnegotiated_payloads_total"
)

// dataPlaneCapabilities are the HelloAck.server_capabilities names of
// PROTOCOL.md, "Data plane". Advertising one in Hello makes Control send its
// payloads (users.v1 is offered to every proxy node), so the Agent lists one
// only once it implements it.
var dataPlaneCapabilities = []string{
	agentcontrol.CapabilityConfig,
	agentcontrol.CapabilityUsers,
	agentcontrol.CapabilityReports,
	agentcontrol.CapabilityPackageReports,
	agentcontrol.CapabilityDiag,
	agentcontrol.CapabilityForward,
	agentcontrol.CapabilityNetwork,
	agentcontrol.CapabilityMaintenance,
	agentcontrol.CapabilityAlive,
	agentcontrol.CapabilityArtifacts,
	agentcontrol.CapabilityUpgrade,
	agentcontrol.CapabilityDestinations,
}

// implementedDataPlane lists the data-plane capabilities this Agent
// implements and may advertise. Each feature (AG-3 configuration, AG-4
// users, AG-5 reports, AG-5b maintenance, alive list and artifacts, F3b
// forwarding, F3c diagnostics, O4 upgrades, destination statistics) adds
// its name with its payload handling. A Hello lists one only when the
// client's DataPlane has a handler for it.
var implementedDataPlane = map[string]bool{
	agentcontrol.CapabilityConfig:         true,
	agentcontrol.CapabilityUsers:          true,
	agentcontrol.CapabilityReports:        true,
	agentcontrol.CapabilityPackageReports: true,
	agentcontrol.CapabilityMaintenance:    true,
	agentcontrol.CapabilityAlive:          true,
	agentcontrol.CapabilityArtifacts:      true,
	agentcontrol.CapabilityForward:        true,
	agentcontrol.CapabilityNetwork:        true,
	agentcontrol.CapabilityDiag:           true,
	agentcontrol.CapabilityUpgrade:        true,
	agentcontrol.CapabilityDestinations:   true,
}

// grpcStatus returns the gRPC status err wraps, with Control's own message
// (status.FromError prefixes the wrapping context to it).
func grpcStatus(err error) (*status.Status, bool) {
	var carrier interface{ GRPCStatus() *status.Status }
	if !errors.As(err, &carrier) {
		return nil, false
	}
	st := carrier.GRPCStatus()
	return st, st != nil
}

// validateAdvertisedCapabilities refuses a Hello that would advertise a
// data-plane capability this Agent does not implement, or one its data
// plane has no handler for: Control would send payloads nobody applies.
func validateAdvertisedCapabilities(capabilities []*agentv1pb.Capability, plane *DataPlane) error {
	handled := map[string]bool{}
	if plane != nil {
		for _, name := range plane.capabilities() {
			handled[name] = true
		}
	}
	for _, name := range dataPlaneCapabilities {
		if !agentcontrol.HasCapability(capabilities, name) {
			continue
		}
		if !implementedDataPlane[name] {
			return fmt.Errorf("agent capability %s.%s is not implemented by this Agent and must not be advertised", name, agentcontrol.CapabilityVersionV1)
		}
		if !handled[name] {
			return fmt.Errorf("agent capability %s.%s needs a DataPlane handler and must not be advertised without one", name, agentcontrol.CapabilityVersionV1)
		}
	}
	return nil
}

// payloadCapability names the data-plane capability a Control payload
// belongs to, and whether it is a data-plane payload.
func payloadCapability(payload any) (kind, capability string, ok bool) {
	switch payload.(type) {
	case *agentv1pb.ControlToAgent_Config:
		return "config", agentcontrol.CapabilityConfig, true
	case *agentv1pb.ControlToAgent_Users:
		return "users", agentcontrol.CapabilityUsers, true
	case *agentv1pb.ControlToAgent_ReportAck:
		return "report_ack", agentcontrol.CapabilityReports, true
	case *agentv1pb.ControlToAgent_MaintenanceAck:
		return "maintenance_ack", agentcontrol.CapabilityMaintenance, true
	case *agentv1pb.ControlToAgent_AliveList:
		return "alive_list", agentcontrol.CapabilityAlive, true
	default:
		return "", "", false
	}
}

// capabilityNames renders capabilities as name.version, sorted.
func capabilityNames(capabilities []*agentv1pb.Capability) []string {
	names := make([]string, 0, len(capabilities))
	for _, capability := range capabilities {
		if capability == nil || strings.TrimSpace(capability.Name) == "" {
			continue
		}
		names = append(names, capability.Name+"."+capability.Version)
	}
	sort.Strings(names)
	return names
}

// negotiatedNames lists the data-plane capabilities in use on a session.
func negotiatedNames(agent, server []*agentv1pb.Capability) []string {
	var names []string
	for _, name := range negotiatedCapabilities(agent, server) {
		names = append(names, name+"."+agentcontrol.CapabilityVersionV1)
	}
	return names
}

// negotiatedCapabilities lists the names (config, users, ...) of the
// data-plane capabilities in use on a session.
func negotiatedCapabilities(agent, server []*agentv1pb.Capability) []string {
	var names []string
	for _, name := range dataPlaneCapabilities {
		if agentcontrol.Negotiated(agent, server, name) {
			names = append(names, name)
		}
	}
	return names
}

// transportCounters are the client's process-lifetime transport counters.
type transportCounters struct {
	unnegotiatedPayloads atomic.Uint64
	unnegotiatedLogged   [16]atomic.Bool
}

// TransportStatus describes the client's control stream for status output.
type TransportStatus struct {
	Connected bool   `json:"connected"`
	SessionID string `json:"session_id,omitempty"`
	// ServerCapabilities is HelloAck.server_capabilities of the current
	// session, as name.version.
	ServerCapabilities []string `json:"server_capabilities,omitempty"`
	// Negotiated lists the data-plane capabilities in use on the current
	// session; empty while disconnected.
	Negotiated           []string `json:"negotiated,omitempty"`
	UnnegotiatedPayloads uint64   `json:"unnegotiated_payloads"`
	// LastError is the last session error, if any.
	LastError string `json:"last_error,omitempty"`
	// Identity is the Agent's mTLS identity.
	Identity *IdentityStatus `json:"identity,omitempty"`
	// DataPlane is the stream's data plane, nil when it is off.
	DataPlane *DataPlaneStatus `json:"data_plane,omitempty"`
}

// dropUnnegotiatedPayload counts and drops a data-plane payload Control sent
// without the capability negotiated on the session. Ending the stream would
// only reconnect into the same message.
func (c *Client) dropUnnegotiatedPayload(kind, capability string) {
	c.counters.unnegotiatedPayloads.Add(1)
	index := 0
	for position, name := range dataPlaneCapabilities {
		if name == capability && position < len(c.counters.unnegotiatedLogged) {
			index = position
		}
	}
	if c.counters.unnegotiatedLogged[index].Swap(true) {
		return
	}
	log.WithFields(log.Fields{
		"component":  "agent-control",
		"node_id":    c.config.NodeID,
		"payload":    kind,
		"capability": capability + "." + agentcontrol.CapabilityVersionV1,
	}).Warn("Control sent a data-plane payload that was not negotiated on this session; dropping it")
}
