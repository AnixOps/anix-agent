package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/AnixOps/anix-agent/v4/api/agent/pki"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestJoinCallErrorClassification(t *testing.T) {
	trailer := func(code string) metadata.MD { return metadata.Pairs(agentcontrol.MetadataErrorCode, code) }
	for name, test := range map[string]struct {
		err     error
		trailer metadata.MD
		class   error
		code    string
		message string
	}{
		"join rejected": {
			err: status.Error(codes.Unauthenticated, "join_rejected: join rejected"), trailer: trailer(JoinErrorCodeRejected),
			class: ErrJoinRejected, code: JoinErrorCodeRejected, message: "Control rejected the join token: join_rejected: join rejected (Unauthenticated)",
		},
		"code in the trailer only": {
			err: status.Error(codes.PermissionDenied, "refused"), trailer: trailer(JoinErrorCodeRejected),
			class: ErrJoinRejected, code: JoinErrorCodeRejected, message: "join_rejected: refused (PermissionDenied)",
		},
		"enrollment rejected": {
			err:   status.Error(codes.Unauthenticated, "agent_enrollment_rejected: agent enrollment rejected"),
			class: ErrJoinRejected, code: agentcontrol.ErrorCodeEnrollmentRejected,
		},
		"refused without a code": {
			err:   status.Error(codes.Unauthenticated, "bad token"),
			class: ErrJoinRejected, message: "Control rejected the join token: bad token (Unauthenticated)",
		},
		"unavailable": {
			err:   status.Error(codes.Unavailable, "connection reset"),
			class: ErrJoinUnreachable, message: "did not answer AgentEnrollment.Join: connection reset (Unavailable)",
		},
		"deadline": {
			err:   status.Error(codes.DeadlineExceeded, "context deadline exceeded"),
			class: ErrJoinUnreachable,
		},
		"Control before Join": {
			err:     status.Error(codes.Unimplemented, "unknown method Join for service anix.agent.v1.AgentEnrollment"),
			message: "does not serve AgentEnrollment.Join",
		},
		"another code": {
			err: status.Error(codes.ResourceExhausted, "join_rate_limited: slow down"), code: "join_rate_limited",
			message: "AgentEnrollment.Join failed: join_rate_limited: slow down (ResourceExhausted)",
		},
		"not a status": {
			err:     errors.New("boom"),
			message: "AgentEnrollment.Join failed: boom",
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := joinCallError("Join", "join token", "control.example.com:50051", test.err, test.trailer)
			var joinErr *JoinError
			require.ErrorAs(t, err, &joinErr)
			assert.Equal(t, test.code, joinErr.Code)
			for _, class := range []error{ErrJoinRejected, ErrJoinUnreachable} {
				assert.Equal(t, class == test.class, errors.Is(err, class), "class %v", class)
			}
			assert.Contains(t, err.Error(), test.message)
			assert.False(t, strings.Contains(err.Error(), "rpc error"), "no gRPC framing: %s", err)
			if _, ok := status.FromError(test.err); ok {
				assert.Equal(t, status.Code(test.err), status.Code(err), "the status stays reachable")
			}
		})
	}
}

func TestJoinRefusesBadConfigurationsBeforeDialling(t *testing.T) {
	dialled := false
	dial := func(context.Context, string, ...grpc.DialOption) (*grpc.ClientConn, error) {
		dialled = true
		return nil, errors.New("dialled")
	}
	for name, config := range map[string]JoinConfig{
		"credential":   {Target: "127.0.0.1:1", Credential: "anixops_key", Dir: t.TempDir()},
		"no target":    {Credential: "anixjoin_x", Dir: t.TempDir()},
		"relative dir": {Target: "127.0.0.1:1", Credential: "anixjoin_x", Dir: "pki"},
		"target":       {Target: "control.example.com", Credential: "anixjoin_x", Dir: t.TempDir()},
	} {
		t.Run(name, func(t *testing.T) {
			config.DialContext = dial
			_, err := Join(context.Background(), config)
			require.Error(t, err)
			assert.False(t, errors.Is(err, ErrJoinRejected) || errors.Is(err, ErrJoinUnreachable), err.Error())
		})
	}
	assert.False(t, dialled)
}

func TestIdentityCheckClassification(t *testing.T) {
	identity := &pki.Identity{
		Node: agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: 12}, SPIFFEID: "spiffe://anixops/prod/agent/proxy-12",
	}
	refusal := func(st codes.Code, code string) error { return status.Error(st, code+": refused") }
	trailer := func(code string) metadata.MD { return metadata.Pairs(agentcontrol.MetadataErrorCode, code) }
	for name, test := range map[string]struct {
		err     error
		trailer metadata.MD
		class   error
	}{
		"revoked":                    {err: refusal(codes.Unauthenticated, agentcontrol.ErrorCodeCertRevoked), class: ErrIdentityRefused},
		"revoked, node disabled":     {err: refusal(codes.PermissionDenied, agentcontrol.ErrorCodeCertRevoked), class: ErrIdentityRefused},
		"expired":                    {err: refusal(codes.Unauthenticated, agentcontrol.ErrorCodeCertExpired), class: ErrIdentityRefused},
		"invalid":                    {err: refusal(codes.Unauthenticated, agentcontrol.ErrorCodeCertInvalid), class: ErrIdentityRefused},
		"wrong cluster":              {err: refusal(codes.Unauthenticated, agentcontrol.ErrorCodeCertWrongCluster), class: ErrIdentityRefused},
		"wrong node":                 {err: refusal(codes.Unauthenticated, agentcontrol.ErrorCodeCertWrongNode), class: ErrIdentityRefused},
		"code in the trailer":        {err: status.Error(codes.Unauthenticated, "refused"), trailer: trailer(agentcontrol.ErrorCodeCertRevoked), class: ErrIdentityRefused},
		"unauthenticated, uncoded":   {err: status.Error(codes.Unauthenticated, "no"), class: ErrIdentityRefused},
		"permission denied, uncoded": {err: status.Error(codes.PermissionDenied, "no"), class: ErrIdentityRefused},
		"unavailable":                {err: status.Error(codes.Unavailable, "connection reset"), class: ErrJoinUnreachable},
		"deadline":                   {err: status.Error(codes.DeadlineExceeded, "slow"), class: ErrJoinUnreachable},
		"another refusal":            {err: refusal(codes.FailedPrecondition, "agent_pki_unavailable")},
		"internal":                   {err: status.Error(codes.Internal, "boom")},
	} {
		t.Run(name, func(t *testing.T) {
			err := identityCheckError(identity, "control.example.com:50051", test.err, test.trailer)
			require.Error(t, err)
			for _, class := range []error{ErrIdentityRefused, ErrJoinUnreachable, ErrJoinRejected} {
				assert.Equal(t, class == test.class, errors.Is(err, class), "class %v: %v", class, err)
			}
			if test.class == ErrIdentityRefused {
				assert.Contains(t, err.Error(), "proxy-12")
			}
		})
	}
	assert.NoError(t, identityCheckError(identity, "control.example.com:50051", nil, nil))
}
