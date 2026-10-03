package agent

import (
	"errors"
	"fmt"
	"strings"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

// Control names the reason of every refusal in the x-anix-error-code
// trailer, and its status message starts with the same code (PROTOCOL.md,
// "Error codes"). Proxies can lose trailers, so the message prefix is read
// first and the trailer second. Controls before the codes sent neither; the
// certificate refusals then fall back to the messages they sent.

// maxErrorCodeLength bounds a code: lowercase words joined by "_".
const maxErrorCodeLength = 64

// ControlError is a call Control refused, with its error code.
type ControlError struct {
	// Code is Control's x-anix-error-code, "" without one.
	Code string
	Err  error
}

func (e *ControlError) Error() string { return e.Err.Error() }
func (e *ControlError) Unwrap() error { return e.Err }

// withControlCode wraps err with the error code Control named for it, if
// any. A nil err stays nil.
func withControlCode(err error, trailer metadata.MD) error {
	if err == nil {
		return nil
	}
	var coded *ControlError
	if errors.As(err, &coded) {
		return err
	}
	if code := controlErrorCode(err, trailer); code != "" {
		return &ControlError{Code: code, Err: err}
	}
	return err
}

// errorCodeOf returns the error code err carries, "" without one.
func errorCodeOf(err error) string {
	var coded *ControlError
	if errors.As(err, &coded) {
		return coded.Code
	}
	return controlErrorCode(err, nil)
}

// controlErrorCode reads Control's error code of a gRPC error: the code
// its status message starts with, else the trailer's.
func controlErrorCode(err error, trailer metadata.MD) string {
	if err == nil {
		return ""
	}
	if st, ok := grpcStatus(err); ok {
		message := st.Message()
		end := strings.IndexByte(message, ':')
		if end < 0 {
			end = len(message)
		}
		if candidate := message[:end]; validErrorCode(candidate) {
			return candidate
		}
	}
	for _, value := range trailer.Get(agentcontrol.MetadataErrorCode) {
		if value = strings.TrimSpace(value); validErrorCode(value) {
			return value
		}
	}
	return ""
}

// validErrorCode tells whether code has the shape of an error code:
// lowercase letters and digits in words joined by "_", with at least one
// "_" (so a message's first word is not taken for one).
func validErrorCode(code string) bool {
	if len(code) == 0 || len(code) > maxErrorCodeLength || !strings.Contains(code, "_") ||
		code[0] == '_' || code[len(code)-1] == '_' || strings.Contains(code, "__") {
		return false
	}
	for _, r := range code {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

// certificateAction is what the Agent does about a refusal of the client
// certificate it presented.
type certificateAction int

const (
	// certificateKept: not a refusal of the certificate.
	certificateKept certificateAction = iota
	// certificateReenroll: revoked, expired, invalid or of another
	// cluster: discard it and enroll again.
	certificateReenroll
	// certificateWrongNode: it names another node than the Agent's
	// configuration: a local configuration error; the certificate is kept.
	certificateWrongNode
)

// ErrCertificateWrongNode reports agent_cert_wrong_node: the Agent's
// certificate names another node than its configuration (x-node-id, the
// envelopes' node_id). Enrolling again would not help; the configuration
// must be fixed.
var ErrCertificateWrongNode = errors.New(agentcontrol.ErrorCodeCertWrongNode)

// CertificateWrongNodeError is Control's agent_cert_wrong_node refusal.
type CertificateWrongNodeError struct{ Err error }

func (e *CertificateWrongNodeError) Error() string {
	return fmt.Sprintf("%s: the agent certificate names another node than this Agent's configuration (NodeID); fix the configuration or remove the identity directory and enroll again: %v",
		agentcontrol.ErrorCodeCertWrongNode, e.Err)
}

func (e *CertificateWrongNodeError) Unwrap() []error { return []error{e.Err, ErrCertificateWrongNode} }

// certificateRefusal classifies a refusal of a presented client
// certificate, with Control's reason.
func certificateRefusal(err error) (string, certificateAction) {
	st, ok := grpcStatus(err)
	if !ok {
		return "", certificateKept
	}
	switch errorCodeOf(err) {
	case agentcontrol.ErrorCodeCertRevoked, agentcontrol.ErrorCodeCertExpired, agentcontrol.ErrorCodeCertInvalid, agentcontrol.ErrorCodeCertWrongCluster:
		// agent_cert_revoked comes as PermissionDenied too, for a node
		// found disabled or deleted after the certificate check.
		return st.Message(), certificateReenroll
	case agentcontrol.ErrorCodeCertWrongNode:
		return st.Message(), certificateWrongNode
	case "":
	default:
		return "", certificateKept
	}
	// A Control before the codes: its messages.
	if st.Code() != codes.Unauthenticated {
		return "", certificateKept
	}
	message := strings.ToLower(st.Message())
	if strings.Contains(message, "does not match the client certificate") {
		return st.Message(), certificateWrongNode
	}
	for _, marker := range []string{"revoked", "expired", "not a valid agent certificate", "renewal requires the current agent client certificate"} {
		if strings.Contains(message, marker) {
			return st.Message(), certificateReenroll
		}
	}
	return "", certificateKept
}
