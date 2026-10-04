package agenttest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// maintenanceState is the maintenance outbox side (maintenance.v1),
// modelled on anix-control's agent_control_maintenance.go: each event
// stored once per event id, answered per event in the batch's order.
type maintenanceState struct {
	stored  map[string]agentcontrol.MaintenanceEvent
	order   []string
	batches []*agentv1pb.MaintenanceEvents
	acks    []*agentv1pb.MaintenanceAck
	// unavailable answers the next deliveries of events maintenance_unavailable.
	unavailable int
	// refuse returns an error code to refuse an event for good, "" to store it.
	refuse func(eventID string) string
	// hold answers nothing (a lost acknowledgement).
	hold bool
}

// aliveState is the alive list (alive.v1): every user's online device count.
type aliveState struct {
	counts   map[uint64]uint32
	pageSize int
	lists    []*agentv1pb.AliveList
	// dropAfter ends the session after that many pages of the next list.
	dropAfter int
}

// Release is a signed plugin release Control serves on AgentArtifacts.
type Release struct {
	PluginID, Version           string
	Manifest, Artifact          []byte
	Signature, Publisher, KeyID string
	APIVersion                  string
}

// artifactsState is the AgentArtifacts side (artifacts.v1).
type artifactsState struct {
	releases  map[string]Release
	chunkSize int
	// busy answers the next downloads plugin_release_download_busy.
	busy int
	// mutate changes the bytes or chunks sent (integrity tests).
	mutateArtifact func([]byte) []byte
	reorder        bool
	mutateRelease  func(*agentv1pb.PluginRelease)
	calls          []string
}

// operationsState records the operations sent and the Agent's answers.
type operationsState struct {
	acks     []*agentv1pb.OperationAck
	observed []*agentv1pb.ObservedState
	revision uint64
}

func (c *Control) initStreams() {
	c.maintenance.stored = map[string]agentcontrol.MaintenanceEvent{}
	c.alive.pageSize = 10000
	c.artifacts.releases = map[string]Release{}
	c.artifacts.chunkSize = 1 << 20
}

// --- Maintenance (maintenance.v1) ---

// UnavailableMaintenance makes Control unable to store the events of the
// next count batches: each is answered maintenance_unavailable with
// retry_after_ms 200.
func (c *Control) UnavailableMaintenance(count int) {
	c.mu.Lock()
	c.maintenance.unavailable = count
	c.mu.Unlock()
}

// RefuseMaintenance makes Control refuse events for good: refuse returns
// the error code for an event id, "" to store it.
func (c *Control) RefuseMaintenance(refuse func(eventID string) string) {
	c.mu.Lock()
	c.maintenance.refuse = refuse
	c.mu.Unlock()
}

// HoldMaintenanceAcks makes Control answer no MaintenanceAck.
func (c *Control) HoldMaintenanceAcks(hold bool) {
	c.mu.Lock()
	c.maintenance.hold = hold
	c.mu.Unlock()
}

// MaintenanceEvents returns the events stored, in the order stored.
func (c *Control) MaintenanceEvents() []agentcontrol.MaintenanceEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	events := make([]agentcontrol.MaintenanceEvent, 0, len(c.maintenance.order))
	for _, id := range c.maintenance.order {
		events = append(events, c.maintenance.stored[id])
	}
	return events
}

// MaintenanceBatches returns every MaintenanceEvents received.
func (c *Control) MaintenanceBatches() []*agentv1pb.MaintenanceEvents {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*agentv1pb.MaintenanceEvents(nil), c.maintenance.batches...)
}

// MaintenanceAcks returns every MaintenanceAck sent.
func (c *Control) MaintenanceAcks() []*agentv1pb.MaintenanceAck {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*agentv1pb.MaintenanceAck(nil), c.maintenance.acks...)
}

// handleMaintenance answers a batch, as Control's handleMaintenanceEvents.
func (c *Control) handleMaintenance(current *session, requestID string, batch *agentv1pb.MaintenanceEvents) error {
	node := agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: c.NodeID}
	c.mu.Lock()
	c.maintenance.batches = append(c.maintenance.batches, proto.Clone(batch).(*agentv1pb.MaintenanceEvents))
	if c.maintenance.hold {
		c.mu.Unlock()
		return nil
	}
	unavailable := c.maintenance.unavailable > 0
	if unavailable {
		c.maintenance.unavailable--
	}
	size := 0
	for _, raw := range batch.GetEventsJson() {
		size += len(raw)
	}
	batchRefusal := ""
	switch {
	case batch.GetVersion() != agentcontrol.MaintenanceSchemaV1:
		batchRefusal = agentcontrol.MaintenanceErrorCodeSchemaUnsupported
	case len(batch.GetEventsJson()) > agentcontrol.MaxMaintenanceBatchEvents || size > agentcontrol.MaxMaintenanceBatchBytes:
		batchRefusal = agentcontrol.MaintenanceErrorCodeBatchTooLarge
	}
	ack := &agentv1pb.MaintenanceAck{Version: batch.GetVersion()}
	for _, raw := range batch.GetEventsJson() {
		result := &agentv1pb.MaintenanceEventResult{EventId: agentcontrol.MaintenanceEventID(raw)}
		event, err := agentcontrol.ParseMaintenanceEvent(raw, node, time.Now())
		switch {
		case batchRefusal != "":
			result.Error, result.ErrorCode = "the batch is refused", batchRefusal
		case err != nil && strings.Contains(err.Error(), agentcontrol.ErrMaintenanceEventWrongNode.Error()):
			result.Error, result.ErrorCode = err.Error(), agentcontrol.MaintenanceErrorCodeWrongNode
		case err != nil:
			result.Error, result.ErrorCode = err.Error(), agentcontrol.MaintenanceErrorCodeEventInvalid
		case c.maintenance.refuse != nil && c.maintenance.refuse(event.EventID) != "":
			result.Error, result.ErrorCode = "refused", c.maintenance.refuse(event.EventID)
		case unavailable:
			result.ErrorCode, result.RetryAfterMs = agentcontrol.MaintenanceErrorCodeUnavailable, 200
		default:
			if _, ok := c.maintenance.stored[event.EventID]; !ok {
				c.maintenance.stored[event.EventID] = event
				c.maintenance.order = append(c.maintenance.order, event.EventID)
			}
			result.Persisted = true
		}
		ack.Events = append(ack.Events, result)
	}
	c.maintenance.acks = append(c.maintenance.acks, proto.Clone(ack).(*agentv1pb.MaintenanceAck))
	c.mu.Unlock()
	return current.send(&agentv1pb.ControlToAgent{
		RequestId: requestID, NodeId: c.NodeID, SentAtUnixMs: time.Now().UnixMilli(),
		Payload: &agentv1pb.ControlToAgent_MaintenanceAck{MaintenanceAck: ack},
	})
}

// --- Alive list (alive.v1) ---

// SetAlivePageSize sets the entries per AliveList page.
func (c *Control) SetAlivePageSize(size int) {
	c.mu.Lock()
	c.alive.pageSize = size
	c.mu.Unlock()
}

// DropNextAliveAfter makes the next alive list end its session after
// pages pages, before its last page.
func (c *Control) DropNextAliveAfter(pages int) {
	c.mu.Lock()
	c.alive.dropAfter = pages
	c.mu.Unlock()
}

// SetAlive sets every user's online device count and sends the list to the
// sessions that negotiated alive.v1.
func (c *Control) SetAlive(counts map[uint64]uint32) {
	c.mu.Lock()
	c.alive.counts = map[uint64]uint32{}
	for id, count := range counts {
		if count > 0 {
			c.alive.counts[id] = count
		}
	}
	sessions := c.openSessions()
	c.mu.Unlock()
	for _, session := range sessions {
		if session.negotiated[agentcontrol.CapabilityAlive] {
			_ = c.sendAlive(session)
		}
	}
}

// AliveLists returns every AliveList page sent.
func (c *Control) AliveLists() []*agentv1pb.AliveList {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*agentv1pb.AliveList(nil), c.alive.lists...)
}

// sendAlive sends the alive list in pages of the session's next revision.
func (c *Control) sendAlive(current *session) error {
	current.aliveMu.Lock()
	defer current.aliveMu.Unlock()
	c.mu.Lock()
	ids := make([]uint64, 0, len(c.alive.counts))
	for id := range c.alive.counts {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	entries := make([]*agentv1pb.UserAlive, 0, len(ids))
	for _, id := range ids {
		entries = append(entries, &agentv1pb.UserAlive{UserId: id, AliveCount: c.alive.counts[id]})
	}
	pageSize, dropAfter := max(c.alive.pageSize, 1), c.alive.dropAfter
	c.alive.dropAfter = 0
	c.mu.Unlock()
	current.aliveRevision++
	computed := time.Now().UnixMilli()
	for start, pages := 0, 0; ; start += pageSize {
		if dropAfter > 0 && pages == dropAfter {
			current.cancel()
			return status.Error(codes.Unavailable, "session dropped during an alive list")
		}
		end := min(start+pageSize, len(entries))
		page := &agentv1pb.AliveList{Revision: current.aliveRevision, LastPage: end >= len(entries), Entries: entries[start:end], ComputedAtUnixMs: computed}
		c.mu.Lock()
		c.alive.lists = append(c.alive.lists, proto.Clone(page).(*agentv1pb.AliveList))
		c.mu.Unlock()
		if err := current.send(&agentv1pb.ControlToAgent{
			RequestId: "alive-" + strconv.FormatUint(current.aliveRevision, 10), NodeId: c.NodeID, SentAtUnixMs: computed,
			Payload: &agentv1pb.ControlToAgent_AliveList{AliveList: page},
		}); err != nil {
			return err
		}
		pages++
		if page.LastPage {
			return nil
		}
	}
}

// --- Plugin artifacts (artifacts.v1) ---

// AddRelease makes Control serve release to the node.
func (c *Control) AddRelease(release Release) {
	c.mu.Lock()
	c.artifacts.releases[release.PluginID+"\x00"+release.Version] = release
	c.mu.Unlock()
}

// SetArtifactChunkSize sets the bytes per PluginArtifactChunk.
func (c *Control) SetArtifactChunkSize(size int) {
	c.mu.Lock()
	c.artifacts.chunkSize = size
	c.mu.Unlock()
}

// BusyDownloads answers the next count downloads plugin_release_download_busy.
func (c *Control) BusyDownloads(count int) {
	c.mu.Lock()
	c.artifacts.busy = count
	c.mu.Unlock()
}

// TamperArtifacts changes what DownloadPluginArtifact sends: mutate the
// bytes, reorder the chunks, or change the release; nil and false restore.
func (c *Control) TamperArtifacts(mutate func([]byte) []byte, reorder bool, release func(*agentv1pb.PluginRelease)) {
	c.mu.Lock()
	c.artifacts.mutateArtifact, c.artifacts.reorder, c.artifacts.mutateRelease = mutate, reorder, release
	c.mu.Unlock()
}

// ArtifactCalls lists the AgentArtifacts calls received: "manifest" or
// "artifact", with the plugin id.
func (c *Control) ArtifactCalls() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.artifacts.calls...)
}

// artifactRelease authenticates an AgentArtifacts call by its certificate
// and finds the release of address, as Control's agentArtifactsServer.
func (c *Control) artifactRelease(ctx context.Context, kind string, address *agentv1pb.PluginReleaseAddress) (Release, *agentv1pb.PluginRelease, error) {
	chain := peerChain(ctx)
	if len(chain) == 0 {
		return Release{}, nil, refuse(ctx, codes.Unauthenticated, agentcontrol.ErrorCodeCertInvalid, "AgentArtifacts requires an agent client certificate")
	}
	if _, err := c.verifyPeer(ctx, chain); err != nil {
		return Release{}, nil, err
	}
	c.mu.Lock()
	c.artifacts.calls = append(c.artifacts.calls, kind+":"+address.GetPluginId())
	release, ok := c.artifacts.releases[address.GetPluginId()+"\x00"+address.GetVersion()]
	mutateRelease := c.artifacts.mutateRelease
	c.mu.Unlock()
	if address.GetPluginId() == "" || address.GetVersion() == "" || len(address.GetSha256()) != 64 || address.GetSize() <= 0 {
		return Release{}, nil, refuse(ctx, codes.InvalidArgument, agentcontrol.ErrorCodePluginReleaseAddressInvalid, "invalid address")
	}
	if !ok {
		return Release{}, nil, refuse(ctx, codes.PermissionDenied, agentcontrol.ErrorCodePluginReleaseNotAssigned, "the release is not assigned to the node")
	}
	document := release.Manifest
	if kind == "artifact" {
		document = release.Artifact
	}
	if digest(document) != address.GetSha256() || int64(len(document)) != address.GetSize() {
		return Release{}, nil, refuse(ctx, codes.InvalidArgument, agentcontrol.ErrorCodePluginReleaseAddressMismatch, "the address is not the release's content")
	}
	described := &agentv1pb.PluginRelease{
		PluginId: release.PluginID, Version: release.Version,
		ArtifactSha256: digest(release.Artifact), ArtifactSize: int64(len(release.Artifact)),
		ManifestSha256: digest(release.Manifest), ManifestSize: int64(len(release.Manifest)),
		Signature: release.Signature, SignatureAlgorithm: "ed25519", Publisher: release.Publisher,
		KeyId: release.KeyID, PluginApiVersion: release.APIVersion,
	}
	if mutateRelease != nil {
		mutateRelease(described)
	}
	return release, described, nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// GetPluginManifest implements AgentArtifacts.GetPluginManifest.
func (c *Control) GetPluginManifest(ctx context.Context, request *agentv1pb.GetPluginManifestRequest) (*agentv1pb.GetPluginManifestResponse, error) {
	release, described, err := c.artifactRelease(ctx, "manifest", request.GetManifest())
	if err != nil {
		return nil, err
	}
	return &agentv1pb.GetPluginManifestResponse{Release: described, ManifestJson: release.Manifest}, nil
}

// DownloadPluginArtifact implements AgentArtifacts.DownloadPluginArtifact.
func (c *Control) DownloadPluginArtifact(request *agentv1pb.DownloadPluginArtifactRequest, stream agentv1pb.AgentArtifacts_DownloadPluginArtifactServer) error {
	ctx := stream.Context()
	release, described, err := c.artifactRelease(ctx, "artifact", request.GetArtifact())
	if err != nil {
		return err
	}
	c.mu.Lock()
	busy := c.artifacts.busy > 0
	if busy {
		c.artifacts.busy--
	}
	chunkSize, mutate, reorder := max(c.artifacts.chunkSize, 1), c.artifacts.mutateArtifact, c.artifacts.reorder
	c.mu.Unlock()
	if busy {
		return refuse(ctx, codes.ResourceExhausted, agentcontrol.ErrorCodePluginReleaseBusy, "the node runs as many downloads as allowed")
	}
	data := append([]byte(nil), release.Artifact...)
	if mutate != nil {
		data = mutate(data)
	}
	var chunks []*agentv1pb.PluginArtifactChunk
	for offset := 0; offset < len(data); offset += chunkSize {
		end := min(offset+chunkSize, len(data))
		chunks = append(chunks, &agentv1pb.PluginArtifactChunk{Offset: int64(offset), Data: data[offset:end]})
	}
	if len(chunks) == 0 {
		chunks = append(chunks, &agentv1pb.PluginArtifactChunk{})
	}
	if reorder && len(chunks) > 1 {
		chunks[0], chunks[1] = chunks[1], chunks[0]
	}
	chunks[0].Release = described
	for _, chunk := range chunks {
		if err := stream.Send(chunk); err != nil {
			return err
		}
	}
	return nil
}

// --- Operations ---

// SendOperation sends a DesiredOperation at the next revision to every
// open session, with the payload payload builds for the session, and
// returns the operation id.
func (c *Control) SendOperation(kind string, payload func(sessionID, operationID string, revision uint64) []byte) string {
	c.mu.Lock()
	c.operations.revision++
	revision := c.operations.revision
	operationID := "operation-" + strconv.FormatUint(revision, 10)
	sessions := c.openSessions()
	c.mu.Unlock()
	for _, session := range sessions {
		operation := &agentv1pb.DesiredOperation{
			OperationId: operationID, Kind: kind, Revision: revision,
			PayloadJson: payload(session.id, operationID, revision), DeadlineUnixMs: time.Now().Add(time.Minute).UnixMilli(),
		}
		_ = session.send(&agentv1pb.ControlToAgent{
			RequestId: operationID, NodeId: c.NodeID, Revision: revision, SentAtUnixMs: time.Now().UnixMilli(),
			Payload: &agentv1pb.ControlToAgent_DesiredOperation{DesiredOperation: operation},
		})
	}
	return operationID
}

// SessionIDs lists the open sessions.
func (c *Control) SessionIDs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	ids := make([]string, 0, len(c.sessions))
	for id := range c.sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// ObservedStates returns every ObservedState received.
func (c *Control) ObservedStates() []*agentv1pb.ObservedState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*agentv1pb.ObservedState(nil), c.operations.observed...)
}

func (c *Control) recordOperationAck(ack *agentv1pb.OperationAck) {
	c.mu.Lock()
	c.operations.acks = append(c.operations.acks, proto.Clone(ack).(*agentv1pb.OperationAck))
	c.mu.Unlock()
}

func (c *Control) recordObserved(observed *agentv1pb.ObservedState) {
	c.mu.Lock()
	c.operations.observed = append(c.operations.observed, proto.Clone(observed).(*agentv1pb.ObservedState))
	c.mu.Unlock()
}
