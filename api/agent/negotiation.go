package agent

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Heartbeat metric keys the client adds next to the MetricsProvider's. The
// Agent has no metrics endpoint of its own; Control records heartbeat metrics
// per node.
const (
	// MetricLegacyAuthDeprecated is 1 while the session authenticated with
	// the node API key and Control answered the deprecation signal
	// (agent_control.mtls: preferred), else 0.
	MetricLegacyAuthDeprecated = "agent_control_legacy_auth_deprecated"
	// MetricMTLSRequiredRefusals counts the streams Control refused with
	// agent_mtls_required since the Agent started.
	MetricMTLSRequiredRefusals = "agent_control_mtls_required_refusals_total"
	// MetricUnnegotiatedPayloads counts the data-plane payloads Control sent
	// without the capability negotiated on the session; the Agent drops them.
	MetricUnnegotiatedPayloads = "agent_control_unnegotiated_payloads_total"
)

// mtlsRequiredLogInterval spaces out the error logged for each refused
// reconnect, which would otherwise repeat at every backoff step.
const mtlsRequiredLogInterval = 10 * time.Minute

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
}

// implementedDataPlane lists the data-plane capabilities this Agent
// implements and may advertise. Each feature (AG-3 configuration, AG-4
// users, AG-5 reports) adds its name with its payload handling. A Hello
// lists one only when the client's DataPlane has a handler for it.
var implementedDataPlane = map[string]bool{
	agentcontrol.CapabilityConfig: true,
}

// ErrMTLSRequired reports that Control refused the node credential because
// agent_control.mtls is required: only an enrolled Agent presenting its
// client certificate may open the stream.
var ErrMTLSRequired = errors.New(agentcontrol.ErrorCodeMTLSRequired)

// MTLSRequiredError is the refusal of a stream or an enrollment that
// authenticated with the node API key while Control requires client
// certificates.
type MTLSRequiredError struct {
	// Operation is what Control refused ("control stream", "enrollment").
	Operation string
	// Message is Control's status message.
	Message string
}

func (e *MTLSRequiredError) Error() string {
	hint := "the Agent must enroll and present its client certificate"
	if e.Operation == "enrollment" {
		hint = "enrolling now needs a one-time enrollment credential"
	}
	return fmt.Sprintf("%s: Control refused the node API key for the %s (agent_control.mtls: required); %s: %s",
		agentcontrol.ErrorCodeMTLSRequired, e.Operation, hint, e.Message)
}

func (e *MTLSRequiredError) Unwrap() error { return ErrMTLSRequired }

// mtlsRequiredError returns an MTLSRequiredError when err is Control's
// agent_mtls_required refusal: Unauthenticated with the x-anix-error-code
// trailer, or a message starting with the code (older trailers can be lost
// by proxies), else nil.
func mtlsRequiredError(operation string, err error, trailer metadata.MD) error {
	if err == nil {
		return nil
	}
	st, ok := grpcStatus(err)
	if !ok || st.Code() != codes.Unauthenticated {
		return nil
	}
	coded := false
	for _, value := range trailer.Get(agentcontrol.MetadataErrorCode) {
		if strings.TrimSpace(value) == agentcontrol.ErrorCodeMTLSRequired {
			coded = true
		}
	}
	if !coded && !strings.HasPrefix(st.Message(), agentcontrol.ErrorCodeMTLSRequired) {
		return nil
	}
	return &MTLSRequiredError{Operation: operation, Message: st.Message()}
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

// AuthDeprecation is the deprecation signal Control answers a node API key
// with in agent_control.mtls: preferred.
type AuthDeprecation struct {
	Message string `json:"message"`
	Link    string `json:"link,omitempty"`
	Sunset  string `json:"sunset,omitempty"`
}

// authDeprecation reads the deprecation signal from stream header or
// trailer metadata, nil without one.
func authDeprecation(md metadata.MD) *AuthDeprecation {
	values := md.Get(agentcontrol.MetadataAuthDeprecated)
	if len(values) == 0 {
		return nil
	}
	first := func(key string) string {
		if values := md.Get(key); len(values) > 0 {
			return strings.TrimSpace(values[0])
		}
		return ""
	}
	return &AuthDeprecation{
		Message: strings.TrimSpace(values[0]),
		Link:    first(agentcontrol.MetadataAuthDeprecationLink),
		Sunset:  first(agentcontrol.MetadataAuthSunset),
	}
}

// transportCounters are the client's process-lifetime transport counters.
type transportCounters struct {
	mtlsRequiredRefusals  atomic.Uint64
	unnegotiatedPayloads  atomic.Uint64
	deprecationLogged     atomic.Bool
	lastMTLSRequiredLogNs atomic.Int64
	unnegotiatedLogged    [3]atomic.Bool
}

// TransportStatus describes the client's control stream for status output.
type TransportStatus struct {
	Connected bool   `json:"connected"`
	SessionID string `json:"session_id,omitempty"`
	// Authentication is how the current or last session authenticated:
	// "api-key", or "certificate" for an enrolled Agent.
	Authentication string `json:"authentication,omitempty"`
	// ServerCapabilities is HelloAck.server_capabilities of the current
	// session, as name.version.
	ServerCapabilities []string `json:"server_capabilities,omitempty"`
	// Negotiated lists the data-plane capabilities in use on the current
	// session; empty while disconnected, when the legacy transports carry
	// everything.
	Negotiated []string `json:"negotiated,omitempty"`
	// Deprecation is Control's last deprecation signal for the node API key.
	Deprecation          *AuthDeprecation `json:"deprecation,omitempty"`
	MTLSRequiredRefusals uint64           `json:"mtls_required_refusals"`
	UnnegotiatedPayloads uint64           `json:"unnegotiated_payloads"`
	// LastError is the last session error, if any.
	LastError string `json:"last_error,omitempty"`
	// Identity is the Agent's mTLS identity, nil when it is off.
	Identity *IdentityStatus `json:"identity,omitempty"`
	// DataPlane is the stream's data plane, nil when it is off.
	DataPlane *DataPlaneStatus `json:"data_plane,omitempty"`
}

// logDeprecation logs Control's deprecation signal once per client.
func (c *Client) logDeprecation(deprecation *AuthDeprecation) {
	if deprecation == nil || c.counters.deprecationLogged.Swap(true) {
		return
	}
	fields := log.Fields{
		"component": "agent-control",
		"node_id":   c.config.NodeID,
		"notice":    deprecation.Message,
	}
	if deprecation.Link != "" {
		fields["link"] = deprecation.Link
	}
	if deprecation.Sunset != "" {
		fields["sunset"] = deprecation.Sunset
	}
	log.WithFields(fields).Warn("Control deprecates node API key authentication on the Agent control stream; Control 4.2 requires an enrolled Agent that presents its client certificate")
}

// logMTLSRequired logs a refusal with agent_mtls_required at most once per
// mtlsRequiredLogInterval.
func (c *Client) logMTLSRequired(err error) {
	now := time.Now().UnixNano()
	last := c.counters.lastMTLSRequiredLogNs.Load()
	if last != 0 && time.Duration(now-last) < mtlsRequiredLogInterval {
		return
	}
	if !c.counters.lastMTLSRequiredLogNs.CompareAndSwap(last, now) {
		return
	}
	log.WithFields(log.Fields{
		"component": "agent-control",
		"node_id":   c.config.NodeID,
		"error":     err,
	}).Error("Control requires mTLS (agent_control.mtls: required) and refused the node API key; the Agent control stream stays down until this node is enrolled. The legacy transports remain active where Control still serves them")
}

// dropUnnegotiatedPayload counts and drops a data-plane payload Control sent
// without the capability negotiated on the session. Ending the stream would
// only reconnect into the same message.
func (c *Client) dropUnnegotiatedPayload(kind, capability string) {
	c.counters.unnegotiatedPayloads.Add(1)
	index := 0
	switch capability {
	case agentcontrol.CapabilityUsers:
		index = 1
	case agentcontrol.CapabilityReports:
		index = 2
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
