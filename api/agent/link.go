package agent

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"strings"
	"time"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// Forward link certificates (owner decision H28; PROTOCOL.md "Forward link
// certificates"): AgentEnrollment.IssueLinkCertificate and
// GetLinkTrustBundle, called with the agent client certificate. The forward
// component keeps the link key, certificate and trust bundle in gost's
// directory; the client only makes the calls and handles the agent
// certificate codes they answer.

// ErrNoIdentity: the Agent has no agent client certificate to call with.
var ErrNoIdentity = errors.New("the agent has no client certificate")

// linkRPCTimeout bounds one link certificate call.
const linkRPCTimeout = 30 * time.Second

// IssueLinkCertificate asks Control for a link certificate for the link key
// of csrDER. Control's refusal codes come as *ControlError
// (link_cert_not_negotiated, link_cert_request_invalid,
// link_cert_unavailable, agent_cert_*); an agent certificate refusal is
// also handled as on the stream (discarded and enrolled again, or kept for
// agent_cert_wrong_node).
func (c *Client) IssueLinkCertificate(ctx context.Context, csrDER []byte) (*agentv1pb.LinkCertificate, error) {
	var certificate *agentv1pb.LinkCertificate
	err := c.linkCall(ctx, func(callCtx context.Context, service agentv1pb.AgentEnrollmentClient, trailer *metadata.MD) error {
		response, err := service.IssueLinkCertificate(callCtx, &agentv1pb.IssueLinkCertificateRequest{CsrDer: csrDER}, grpc.Trailer(trailer))
		if err != nil {
			return err
		}
		if response.GetCertificate() == nil || len(response.GetCertificate().GetCertificateDer()) == 0 {
			return errors.New("Control answered without a link certificate")
		}
		certificate = response.GetCertificate()
		return nil
	})
	return certificate, err
}

// LinkTrustBundle answers the forward link CAs (DER) the node trusts to
// verify its peers.
func (c *Client) LinkTrustBundle(ctx context.Context) ([][]byte, error) {
	var bundle [][]byte
	err := c.linkCall(ctx, func(callCtx context.Context, service agentv1pb.AgentEnrollmentClient, trailer *metadata.MD) error {
		response, err := service.GetLinkTrustBundle(callCtx, &agentv1pb.GetLinkTrustBundleRequest{}, grpc.Trailer(trailer))
		if err != nil {
			return err
		}
		bundle = response.GetTrustBundleDer()
		return nil
	})
	return bundle, err
}

func (c *Client) linkCall(ctx context.Context, do func(context.Context, agentv1pb.AgentEnrollmentClient, *metadata.MD) error) error {
	if c.identity == nil {
		return ErrNoIdentity
	}
	identity := c.identity.certificate()
	if identity == nil {
		return ErrNoIdentity
	}
	ctx, cancel := context.WithTimeout(ctx, linkRPCTimeout)
	defer cancel()
	conn, err := c.dialIdentity(ctx, identity.TLSCertificate())
	if err != nil {
		return fmt.Errorf("dial agent enrollment: %w", err)
	}
	defer conn.Close()
	var trailer metadata.MD
	err = withControlCode(do(ctx, agentv1pb.NewAgentEnrollmentClient(conn), &trailer), trailer)
	if err == nil {
		return nil
	}
	switch reason, action := certificateRefusal(err); action {
	case certificateReenroll:
		c.identity.rejected(identity, reason, refusalCode(err))
	case certificateWrongNode:
		c.identity.wrongNode(err)
	}
	return err
}

// AgentPublicKey answers the agent certificate's public key, nil without
// one: a link key must never be it.
func (c *Client) AgentPublicKey() crypto.PublicKey {
	if c.identity == nil {
		return nil
	}
	identity := c.identity.certificate()
	if identity == nil || identity.Leaf == nil {
		return nil
	}
	return identity.Leaf.PublicKey
}

// OnIdentityRejected sets a function run after Control refused the agent
// certificate and the Agent discarded it, with Control's code
// (agentcontrol.ErrorCodeCertRevoked, ...). The forward component deletes
// the link key and certificate on revocation. Set it before Start.
func (c *Client) OnIdentityRejected(f func(code string)) {
	if c.identity != nil {
		c.identity.onRejected = f
	}
}

// RestartSession ends the current session; the client reconnects and its
// next Hello lists the capabilities as they are then (the forward
// component's, after a link certificate arrived).
func (c *Client) RestartSession() {
	c.recycleSession()
}

// refusalCode answers Control's code of a certificate refusal; a Control
// before the codes says "revoked" in its message.
func refusalCode(err error) string {
	if code := errorCodeOf(err); code != "" {
		return code
	}
	if st, ok := grpcStatus(err); ok && strings.Contains(strings.ToLower(st.Message()), "revoked") {
		return agentcontrol.ErrorCodeCertRevoked
	}
	return ""
}
