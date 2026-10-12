package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/AnixOps/anix-agent/v4/api/agent/pki"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

// Joining is the one-shot bootstrap of a machine that is not a node yet
// (`anix-agent join`, run by Control's installer before the Agent's service
// starts; anix-control docs/design/node-onboarding, "Join Protocol"). A
// node group's anixjoin_ join token goes to AgentEnrollment.Join, which
// creates a node of the group (or gives the machine its earlier node back);
// an anixagt_ enrollment credential goes to AgentEnrollment.Enroll, which
// issues the identity of the node the credential names. Either way the
// identity is stored where `anix-agent server` looks for it
// (AgentIdentity.CertDir/<node>), so the Agent starts enrolled.

// JoinErrorCodeRejected is Control's answer to an unusable join token
// (unknown, reset, expired, or a group at its node cap): one code without
// detail, so tokens cannot be probed.
const JoinErrorCodeRejected = "join_rejected"

// Approval states of a joined node (JoinResult.Approval).
const (
	JoinApprovalApproved = "approved"
	// JoinApprovalPending: the group requires approval; the node connects,
	// but Control withholds its configuration and users until an
	// administrator approves it.
	JoinApprovalPending = "pending"
	// JoinApprovalUnknown: Control did not say. Enroll does not answer it,
	// and a machine that keeps its identity does not ask.
	JoinApprovalUnknown = "unknown"
)

// Default timeouts of a join.
const (
	defaultJoinCallTimeout = 30 * time.Second
)

var (
	// ErrJoinRejected classifies a JoinError: Control refused the join
	// token or the enrollment credential.
	ErrJoinRejected = errors.New("Control rejected the credential")
	// ErrJoinUnreachable classifies a JoinError: Control's agent listener
	// could not be reached over TLS, or did not answer in time.
	ErrJoinUnreachable = errors.New("Control is unreachable")
)

// JoinError is a failed join. Class is ErrJoinRejected, ErrJoinUnreachable
// or nil for any other failure; errors.Is matches it.
type JoinError struct {
	Class error
	// Code is Control's error code (join_rejected, ...), "" without one.
	Code string
	// Message says what failed, for the operator.
	Message string
	// Err is the failure: the gRPC status or the dial error.
	Err error
}

func (e *JoinError) Error() string {
	if e.Message == "" {
		return e.Err.Error()
	}
	return e.Message
}

func (e *JoinError) Unwrap() []error {
	if e.Class == nil {
		return []error{e.Err}
	}
	return []error{e.Err, e.Class}
}

// JoinConfig is one join.
type JoinConfig struct {
	// Target is Control's agent listener, host:port.
	Target string
	// ServerName verifies Control's certificate; the target's host when
	// empty.
	ServerName string
	// RootCAs verifies Control's certificate; nil uses the system roots.
	RootCAs *x509.CertPool
	// Credential is a node group's anixjoin_ join token (Join) or a
	// one-time anixagt_ enrollment credential (Enroll).
	Credential string

	// The JoinRequest fields (Enroll sends AgentVersion and InstanceID
	// only).
	MachineFingerprint string
	Hostname           string
	RequestedName      string
	ConnectHost        string
	PublicAddresses    []string
	Arch               string
	OS                 string
	AgentVersion       string
	InstanceID         string
	Reset              bool

	// Cluster pins the SPIFFE cluster of the certificate; empty accepts
	// Control's (AgentIdentity.Cluster).
	Cluster string
	// Dir is the identity root (AgentIdentity.CertDir); pki.DefaultRoot when
	// empty.
	Dir string

	DialContext DialContextFunc
	DialTimeout time.Duration
	CallTimeout time.Duration
	Now         func() time.Time
}

// JoinResult is the stored identity and what Control said about its node.
type JoinResult struct {
	Identity *pki.Identity
	// Dir is the node's identity directory.
	Dir string
	// NodeName and Group are the node's display name and group; empty
	// when Control did not say (Enroll).
	NodeName string
	Group    string
	// Created is true when Control created the node; false for a rejoin
	// and for Enroll, whose node existed.
	Created bool
	// Approval is JoinApprovalApproved, JoinApprovalPending or
	// JoinApprovalUnknown.
	Approval string
}

// Join exchanges config.Credential and a new key's CSR for the
// certificate of a node, checks it against the node Control named, and
// stores it under config.Dir.
func Join(ctx context.Context, config JoinConfig) (*JoinResult, error) {
	joining := strings.HasPrefix(config.Credential, agentcontrol.JoinTokenPrefix)
	if !joining && !strings.HasPrefix(config.Credential, agentcontrol.EnrollmentCredentialPrefix) {
		return nil, fmt.Errorf("the credential is neither an %s join token nor an %s enrollment credential", agentcontrol.JoinTokenPrefix, agentcontrol.EnrollmentCredentialPrefix)
	}
	if strings.TrimSpace(config.Target) == "" {
		return nil, errors.New("Control's agent target (host:port) is required")
	}
	root := config.Dir
	if root == "" {
		root = pki.DefaultRoot
	}
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("agent identity directory %q must be an absolute path", root)
	}
	if config.ServerName == "" {
		host, _, err := net.SplitHostPort(config.Target)
		if err != nil {
			return nil, fmt.Errorf("Control's agent target %q is not host:port: %w", config.Target, err)
		}
		config.ServerName = host
	}
	if config.DialTimeout <= 0 {
		config.DialTimeout = defaultDialTimeout
	}
	if config.CallTimeout <= 0 {
		config.CallTimeout = defaultJoinCallTimeout
	}
	now := time.Now
	if config.Now != nil {
		now = config.Now
	}

	key, err := pki.GenerateKey()
	if err != nil {
		return nil, err
	}
	csr, err := pki.NewJoinCSR(key)
	if err != nil {
		return nil, err
	}
	conn, err := dialEnrollment(ctx, enrollmentTarget{
		Target: config.Target, ServerName: config.ServerName, RootCAs: config.RootCAs,
		DialContext: config.DialContext, DialTimeout: config.DialTimeout,
	}, nil)
	if err != nil {
		return nil, &JoinError{
			Class: ErrJoinUnreachable, Err: err,
			Message: fmt.Sprintf("cannot reach Control's agent listener %s over TLS (server name %s): %v", config.Target, config.ServerName, err),
		}
	}
	defer conn.Close()
	callCtx, cancel := context.WithTimeout(ctx, config.CallTimeout)
	defer cancel()
	enrollment := agentv1pb.NewAgentEnrollmentClient(conn)

	result := &JoinResult{Approval: JoinApprovalUnknown}
	var (
		issued    *agentv1pb.AgentCertificate
		node      agentcontrol.AgentNode
		bootstrap string
		trailer   metadata.MD
	)
	if joining {
		response, err := enrollment.Join(callCtx, &agentv1pb.JoinRequest{
			CsrDer: csr, JoinToken: config.Credential, MachineFingerprint: config.MachineFingerprint,
			Hostname: config.Hostname, RequestedName: config.RequestedName, ConnectHost: config.ConnectHost,
			PublicAddresses: config.PublicAddresses, Arch: config.Arch, Os: config.OS,
			AgentVersion: config.AgentVersion, InstanceId: config.InstanceID, Reset_: config.Reset,
		}, grpc.Trailer(&trailer))
		if err != nil {
			return nil, joinCallError("Join", "join token", config.Target, err, trailer)
		}
		node, err = agentcontrol.ParseAgentNode(response.GetNode())
		if err != nil {
			return nil, fmt.Errorf("Control's Join answer names no node: %w", err)
		}
		if named := response.GetCertificate().GetNode(); named != "" && named != node.String() {
			return nil, fmt.Errorf("%w: Control joined %s but issued the certificate of %s", pki.ErrInvalidIssuance, node, named)
		}
		issued, bootstrap = response.GetCertificate(), pki.BootstrapJoinToken
		result.NodeName, result.Group, result.Created = response.GetNodeName(), response.GetGroup(), response.GetCreated()
		if approval := response.GetApproval(); approval != "" {
			result.Approval = approval
		}
	} else {
		// The credential names its node: no x-node-id or x-node-kind.
		response, err := enrollment.Enroll(callCtx, &agentv1pb.EnrollAgentRequest{
			CsrDer: csr, EnrollmentCredential: config.Credential,
			AgentVersion: config.AgentVersion, InstanceId: config.InstanceID,
		}, grpc.Trailer(&trailer))
		if err != nil {
			return nil, joinCallError("Enroll", "enrollment credential", config.Target, err, trailer)
		}
		node, err = agentcontrol.ParseAgentNode(response.GetCertificate().GetNode())
		if err != nil {
			return nil, fmt.Errorf("Control's Enroll answer names no node: %w", err)
		}
		issued, bootstrap = response.GetCertificate(), pki.BootstrapEnrollmentCredential
	}

	identity, err := pki.FromIssued(key, issued, pki.Expectation{Node: node, Cluster: config.Cluster, Now: now()})
	if err != nil {
		return nil, fmt.Errorf("refusing the certificate Control issued for %s: %w", node, err)
	}
	identity.EnrolledAt, identity.Bootstrap = now().UTC(), bootstrap
	store, err := pki.NewStore(root, node)
	if err != nil {
		return nil, err
	}
	if err := store.Save(identity); err != nil {
		return nil, fmt.Errorf("store the identity of %s in %s: %w", node, store.Dir(), err)
	}
	// What `anix-agent server` will read: the files must load as the
	// Agent's user.
	stored, err := store.Load(pki.Expectation{Node: node, Cluster: config.Cluster, Now: now()})
	if err != nil {
		return nil, fmt.Errorf("the stored identity of %s does not load: %w", node, err)
	}
	result.Identity, result.Dir = stored, store.Dir()
	return result, nil
}

// joinCallError classifies a refused or failed Join or Enroll call. Its
// message carries Control's error code and status, without the gRPC
// framing.
func joinCallError(method, credential, target string, err error, trailer metadata.MD) error {
	coded := withControlCode(err, trailer)
	code := errorCodeOf(coded)
	st, _ := grpcStatus(err)
	if st == nil {
		return &JoinError{Code: code, Err: coded, Message: fmt.Sprintf("AgentEnrollment.%s failed: %v", method, err)}
	}
	detail := strings.TrimPrefix(st.Message(), code+": ")
	if code != "" {
		detail = code + ": " + detail
	}
	detail += " (" + st.Code().String() + ")"
	switch {
	case code == JoinErrorCodeRejected || code == agentcontrol.ErrorCodeEnrollmentRejected ||
		(code == "" && (st.Code() == codes.Unauthenticated || st.Code() == codes.PermissionDenied)):
		return &JoinError{Class: ErrJoinRejected, Code: code, Err: coded, Message: fmt.Sprintf("Control rejected the %s: %s", credential, detail)}
	case st.Code() == codes.Unavailable || st.Code() == codes.DeadlineExceeded:
		return &JoinError{Class: ErrJoinUnreachable, Code: code, Err: coded, Message: fmt.Sprintf("Control's agent listener %s did not answer AgentEnrollment.%s: %s", target, method, detail)}
	case st.Code() == codes.Unimplemented:
		return &JoinError{Code: code, Err: coded, Message: fmt.Sprintf("Control at %s does not serve AgentEnrollment.%s, so it predates node group join tokens; install with an %s enrollment credential instead: %s", target, method, agentcontrol.EnrollmentCredentialPrefix, detail)}
	default:
		return &JoinError{Code: code, Err: coded, Message: fmt.Sprintf("AgentEnrollment.%s failed: %s", method, detail)}
	}
}
