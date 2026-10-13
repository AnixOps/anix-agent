package agenttest

import (
	"context"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Join (AgentEnrollment.Join), modelled on anix-control's
// docs/design/node-onboarding ("Join Protocol"):
//
//   - a join token names a node group (AddJoinToken); an unknown token is
//     refused with join_rejected and no detail;
//   - a join creates a node of the group's kind: the first one is the
//     fake's node (NodeID), later ones count up from it;
//   - a machine fingerprint that joined before gets its earlier node back
//     (created false) unless the request asks for reset; the fake does not
//     model the address and stream conditions of the rejoin rule;
//   - the node's name is requested_name, else hostname; approval is
//     "pending" in a group that requires approval.

// JoinErrorCodeRejected is Control's code for an unusable join token.
const JoinErrorCodeRejected = "join_rejected"

// JoinGroup is a node group of the fake.
type JoinGroup struct {
	Name string
	// Kind is agentcontrol.NodeKindProxy (when empty) or NodeKindForward.
	Kind string
	// RequireApproval answers approval "pending".
	RequireApproval bool
}

// EnrollCall records the node metadata of an Enroll call.
type EnrollCall struct {
	NodeID     string
	NodeKind   string
	Credential bool
}

type joinState struct {
	tokens   map[string]JoinGroup
	requests []*agentv1pb.JoinRequest
	enrolls  []EnrollCall
	// machines maps a fingerprint to the node it joined as.
	machines map[string]agentcontrol.AgentNode
	nextID   uint32
	// edit changes each answer before it is sent.
	edit func(*agentv1pb.JoinResponse)
	// bundleCalls counts GetTrustBundle calls.
	bundleCalls int
}

// AddJoinToken registers a node group's join token.
func (c *Control) AddJoinToken(token string, group JoinGroup) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.join.tokens == nil {
		c.join.tokens = map[string]JoinGroup{}
	}
	c.join.tokens[token] = group
}

// EditJoinAnswers lets edit change every later Join answer (tests of what
// the Agent refuses); nil sends them as they are.
func (c *Control) EditJoinAnswers(edit func(*agentv1pb.JoinResponse)) {
	c.mu.Lock()
	c.join.edit = edit
	c.mu.Unlock()
}

// JoinRequests returns every Join request received.
func (c *Control) JoinRequests() []*agentv1pb.JoinRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	requests := make([]*agentv1pb.JoinRequest, 0, len(c.join.requests))
	for _, request := range c.join.requests {
		requests = append(requests, proto.Clone(request).(*agentv1pb.JoinRequest))
	}
	return requests
}

// EnrollCalls returns the node metadata of every Enroll call that got past
// the mode check.
func (c *Control) EnrollCalls() []EnrollCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]EnrollCall(nil), c.join.enrolls...)
}

// DeleteNode models deleting a node in Control: its certificates are
// refused as revoked (agent_cert_revoked) from now on, and a machine that
// joined as it joins as a new node next time.
func (c *Control) DeleteNode(node agentcontrol.AgentNode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refusedSerials == nil {
		c.refusedSerials = map[string]bool{}
	}
	c.refuseCertificate = agentcontrol.ErrorCodeCertRevoked
	for serial, issued := range c.issuedTo {
		if issued == node {
			c.refusedSerials[serial] = true
		}
	}
	for fingerprint, joined := range c.join.machines {
		if joined == node {
			delete(c.join.machines, fingerprint)
		}
	}
}

// GetTrustBundle implements AgentEnrollment.GetTrustBundle: it needs a
// valid agent client certificate of any node, as Control's certificate
// principal checks it.
func (c *Control) GetTrustBundle(ctx context.Context, _ *agentv1pb.GetAgentTrustBundleRequest) (*agentv1pb.GetAgentTrustBundleResponse, error) {
	c.mu.Lock()
	c.join.bundleCalls++
	c.mu.Unlock()
	chain := peerChain(ctx)
	if len(chain) == 0 {
		return nil, refuse(ctx, codes.Unauthenticated, agentcontrol.ErrorCodeCertInvalid, "an agent client certificate is required")
	}
	if _, _, err := c.verifyCertificate(ctx, chain); err != nil {
		return nil, err
	}
	return &agentv1pb.GetAgentTrustBundleResponse{TrustBundleDer: [][]byte{c.agentCACert.Raw}}, nil
}

// TrustBundleCalls counts the GetTrustBundle calls.
func (c *Control) TrustBundleCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.join.bundleCalls
}

// Join implements AgentEnrollment.Join.
func (c *Control) Join(ctx context.Context, request *agentv1pb.JoinRequest) (*agentv1pb.JoinResponse, error) {
	if c.Mode() == ModeOff {
		return nil, status.Error(codes.FailedPrecondition, "agent enrollment needs the built-in CA")
	}
	c.mu.Lock()
	c.join.requests = append(c.join.requests, proto.Clone(request).(*agentv1pb.JoinRequest))
	group, known := c.join.tokens[request.GetJoinToken()]
	c.mu.Unlock()
	if !known {
		return nil, refuse(ctx, codes.Unauthenticated, JoinErrorCodeRejected, "join rejected")
	}
	kind := group.Kind
	if kind == "" {
		kind = agentcontrol.NodeKindProxy
	}

	c.mu.Lock()
	node, rejoin := c.join.machines[request.GetMachineFingerprint()]
	rejoin = rejoin && request.GetMachineFingerprint() != "" && !request.GetReset_() && node.Kind == kind
	if !rejoin {
		if c.join.nextID == 0 {
			c.join.nextID = c.NodeID
		}
		node = agentcontrol.AgentNode{Kind: kind, ID: c.join.nextID}
		c.join.nextID++
		if fingerprint := request.GetMachineFingerprint(); fingerprint != "" {
			if c.join.machines == nil {
				c.join.machines = map[string]agentcontrol.AgentNode{}
			}
			c.join.machines[fingerprint] = node
		}
	}
	edit := c.join.edit
	c.mu.Unlock()

	certificate, err := c.issueFor(request.GetCsrDer(), node)
	if err != nil {
		return nil, err
	}
	name := request.GetRequestedName()
	if name == "" {
		name = request.GetHostname()
	}
	approval := "approved"
	if group.RequireApproval {
		approval = "pending"
	}
	response := &agentv1pb.JoinResponse{
		Certificate: certificate, Node: node.String(), NodeName: name, Group: group.Name,
		Created: !rejoin, Approval: approval,
	}
	if edit != nil {
		edit(response)
	}
	return response, nil
}
