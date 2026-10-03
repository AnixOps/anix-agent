package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v4/api/agent/agenttest"
	"github.com/AnixOps/anix-agent/v4/api/agent/state"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memoryOutbox is a maintenance outbox in memory.
type memoryOutbox struct {
	mu      sync.Mutex
	events  []MaintenanceEvent
	removed []string
}

func (o *memoryOutbox) add(events ...MaintenanceEvent) {
	o.mu.Lock()
	o.events = append(o.events, events...)
	o.mu.Unlock()
}

func (o *memoryOutbox) PendingMaintenance(limit int) ([]MaintenanceEvent, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]MaintenanceEvent(nil), o.events[:min(limit, len(o.events))]...), nil
}

func (o *memoryOutbox) RemoveMaintenance(ids []string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	kept := o.events[:0]
	for _, event := range o.events {
		if !drop[event.ID] {
			kept = append(kept, event)
		}
	}
	o.events = kept
	o.removed = append(o.removed, ids...)
	return nil
}

func (o *memoryOutbox) pending() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	ids := make([]string, 0, len(o.events))
	for _, event := range o.events {
		ids = append(ids, event.ID)
	}
	return ids
}

// maintenanceEvent is a valid anixops.maintenance/v1 incident of node.
func maintenanceEvent(t *testing.T, id string, node uint32) MaintenanceEvent {
	t.Helper()
	failed := time.Now().Add(-3 * time.Minute).UTC()
	event := agentcontrol.MaintenanceEvent{
		SchemaVersion: 1, EventID: id, OccurredAt: time.Now().Add(-time.Minute).UTC(), Environment: "development", Source: "agent",
		NodeID: fmt.Sprint(node), PluginID: "machine-telemetry", PluginVersion: "1.0.0", InstanceID: "machine-telemetry",
		ErrorCode: "PLUGIN_HEALTH_FAILED", Severity: "P2", Status: "open", FirstFailedAt: &failed, ConsecutiveFailures: 3,
	}
	require.NoError(t, event.Validate(time.Now()))
	encoded, err := json.Marshal(event)
	require.NoError(t, err)
	return MaintenanceEvent{ID: id, JSON: encoded}
}

// recordingAlive records the alive lists applied.
type recordingAlive struct {
	mu    sync.Mutex
	lists []map[uint64]uint32
}

func (r *recordingAlive) ApplyAlive(_ context.Context, alive map[uint64]uint32) {
	r.mu.Lock()
	r.lists = append(r.lists, maps.Clone(alive))
	r.mu.Unlock()
}

func (r *recordingAlive) applied() []map[uint64]uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]map[uint64]uint32(nil), r.lists...)
}

func (r *recordingAlive) last() map[uint64]uint32 {
	lists := r.applied()
	if len(lists) == 0 {
		return nil
	}
	return lists[len(lists)-1]
}

type streamOptions struct {
	outbox    MaintenanceOutbox
	alive     AliveApplier
	artifacts bool
	reports   bool
	identity  bool
}

// newStreamClient is a client with the AG-5b capabilities; with identity
// it enrolls with a one-time credential (agent_control.mtls: required).
func newStreamClient(t *testing.T, control *agenttest.Control, options streamOptions) (*Client, string) {
	t.Helper()
	root := t.TempDir()
	store, err := state.Open(filepath.Join(root, "state"), agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: control.NodeID})
	require.NoError(t, err)
	plane := &DataPlaneConfig{State: store, Config: nopConfig{}, Users: &recordingUsers{}, Alive: options.alive, Artifacts: options.artifacts}
	if options.outbox != nil {
		plane.Maintenance = &MaintenanceConfig{Outbox: options.outbox, Interval: 100 * time.Millisecond}
	}
	if options.reports {
		plane.Reports = &ReportsConfig{}
	}
	config := Config{
		Target: control.Address, NodeID: int(control.NodeID), APIKey: control.APIKey, UseTLS: true, ServerName: control.ServerName,
		RootCAs: control.ServerCAs, AgentVersion: "test-agent", InstanceID: "instance-1",
		Capabilities: []*agentv1pb.Capability{{Name: "agent.control", Version: "v1"}},
		Heartbeat:    200 * time.Millisecond, ReconnectMin: 10 * time.Millisecond, ReconnectMax: 50 * time.Millisecond,
		DialTimeout: 2 * time.Second, DataPlane: plane,
	}
	credentialFile := filepath.Join(root, "enroll.token")
	if options.identity {
		writeCredential(t, control, credentialFile, "anixagt_first")
		config.Identity = &IdentityConfig{Dir: filepath.Join(root, "pki"), Enroll: true, EnrollCredentialFile: credentialFile, Cluster: control.Cluster}
	}
	client, err := NewClient(config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client, credentialFile
}

func writeCredential(t *testing.T, control *agenttest.Control, path, credential string) {
	t.Helper()
	control.AddCredential(credential)
	require.NoError(t, os.WriteFile(path, []byte(credential+"\n"), 0o600))
}

func storedIDs(control *agenttest.Control) []string {
	var ids []string
	for _, event := range control.MaintenanceEvents() {
		ids = append(ids, event.EventID)
	}
	sort.Strings(ids)
	return ids
}

func shortMaintenanceAckTimeout(t *testing.T) {
	previous := maintenanceAckTimeout
	maintenanceAckTimeout = 150 * time.Millisecond
	t.Cleanup(func() { maintenanceAckTimeout = previous })
}

func TestMaintenanceOutboxDrainsOnTheStreamPerEventResult(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers, agentcontrol.CapabilityMaintenance)
	outbox := &memoryOutbox{}
	outbox.add(
		maintenanceEvent(t, "event-stored", control.NodeID),
		maintenanceEvent(t, "event-refused", control.NodeID),
		maintenanceEvent(t, "event-other-node", control.NodeID+1),
	)
	broken := maintenanceEvent(t, "event-broken", control.NodeID)
	broken.JSON = []byte(strings.Replace(string(broken.JSON), `"severity":"P2"`, `"severity":"P9"`, 1))
	outbox.add(broken)
	control.RefuseMaintenance(func(id string) string {
		if id == "event-refused" {
			return "maintenance_some_future_refusal"
		}
		return ""
	})
	client, _ := newStreamClient(t, control, streamOptions{outbox: outbox, identity: true})
	startUsersClient(t, client)
	assert.True(t, client.Negotiated(agentcontrol.CapabilityMaintenance))

	// Persisted is removed; every refusal (another node's, an invalid
	// event, an unknown code) is dropped for good.
	require.Eventually(t, func() bool { return len(outbox.pending()) == 0 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, []string{"event-stored"}, storedIDs(control))
	batches := control.MaintenanceBatches()
	require.Len(t, batches, 1, "one batch, answered once")
	assert.Equal(t, agentcontrol.MaintenanceSchemaV1, batches[0].GetVersion())
	assert.Len(t, batches[0].GetEventsJson(), 4)
	codes := map[string]string{}
	for _, result := range control.MaintenanceAcks()[0].GetEvents() {
		codes[result.GetEventId()] = result.GetErrorCode()
	}
	assert.Equal(t, agentcontrol.MaintenanceErrorCodeWrongNode, codes["event-other-node"])
	assert.Equal(t, agentcontrol.MaintenanceErrorCodeEventInvalid, codes["event-broken"])
	assert.Equal(t, float64(1), heartbeatMetricOf(t, control, MetricMaintenancePersisted))
	assert.Equal(t, float64(3), heartbeatMetricOf(t, control, MetricMaintenanceRefused))
}

func TestMaintenanceUnavailableKeepsTheEventUntilRetryAfter(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers, agentcontrol.CapabilityMaintenance)
	control.UnavailableMaintenance(1)
	outbox := &memoryOutbox{}
	outbox.add(maintenanceEvent(t, "event-1", control.NodeID), maintenanceEvent(t, "event-2", control.NodeID))
	client, _ := newStreamClient(t, control, streamOptions{outbox: outbox, identity: true})
	startUsersClient(t, client)

	require.Eventually(t, func() bool { return len(outbox.pending()) == 0 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, []string{"event-1", "event-2"}, storedIDs(control))
	acks := control.MaintenanceAcks()
	require.GreaterOrEqual(t, len(acks), 2)
	for _, result := range acks[0].GetEvents() {
		assert.False(t, result.GetPersisted())
		assert.Equal(t, agentcontrol.MaintenanceErrorCodeUnavailable, result.GetErrorCode())
	}
	// Not before retry_after_ms (200 ms).
	first, second := batchTimes(control)
	assert.GreaterOrEqual(t, second.Sub(first), 150*time.Millisecond)
	assert.Equal(t, float64(2), heartbeatMetricOf(t, control, MetricMaintenanceDeferred))
}

// batchTimes returns when the first two maintenance batches were sent.
func batchTimes(control *agenttest.Control) (time.Time, time.Time) {
	var times []time.Time
	for _, message := range control.Received() {
		if message.GetMaintenanceEvents() != nil {
			times = append(times, time.UnixMilli(message.GetSentAtUnixMs()))
		}
	}
	if len(times) < 2 {
		return time.Time{}, time.Time{}
	}
	return times[0], times[1]
}

func TestMaintenanceBatchWithoutAnswerIsSentAgainAndStoredOnce(t *testing.T) {
	shortMaintenanceAckTimeout(t)
	control := agenttest.New(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers, agentcontrol.CapabilityMaintenance)
	control.HoldMaintenanceAcks(true)
	outbox := &memoryOutbox{}
	outbox.add(maintenanceEvent(t, "event-1", control.NodeID))
	client, _ := newStreamClient(t, control, streamOptions{outbox: outbox, identity: true})
	startUsersClient(t, client)
	require.Eventually(t, func() bool { return len(control.MaintenanceBatches()) >= 2 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, []string{"event-1"}, outbox.pending(), "kept without an answer")

	control.HoldMaintenanceAcks(false)
	require.Eventually(t, func() bool { return len(outbox.pending()) == 0 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, []string{"event-1"}, storedIDs(control))

	// A reconnect after a lost answer resends; Control stores it once.
	outbox.add(maintenanceEvent(t, "event-1", control.NodeID))
	require.Eventually(t, func() bool { return len(outbox.pending()) == 0 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, []string{"event-1"}, storedIDs(control))
}

func TestMaintenanceStaysInTheOutboxWhenControlDoesNotServeIt(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers)
	outbox := &memoryOutbox{}
	outbox.add(maintenanceEvent(t, "event-1", control.NodeID))
	client, _ := newStreamClient(t, control, streamOptions{outbox: outbox, identity: true})
	startUsersClient(t, client)
	assert.True(t, agentcontrol.HasCapabilityVersion(control.Hellos()[0].Capabilities, agentcontrol.CapabilityMaintenance, "v1"), "advertised")
	assert.False(t, client.Negotiated(agentcontrol.CapabilityMaintenance))
	assert.Equal(t, DataPlaneLegacy, client.DataPlane().Mode(agentcontrol.CapabilityMaintenance))
	time.Sleep(300 * time.Millisecond)
	assert.Empty(t, control.MaintenanceBatches(), "never sent unnegotiated")
	assert.Equal(t, []string{"event-1"}, outbox.pending())
}

func TestMaintenanceBatchTooLargeShrinksTheBatch(t *testing.T) {
	plane := &DataPlane{config: DataPlaneConfig{Maintenance: &MaintenanceConfig{Outbox: &memoryOutbox{}}}, now: time.Now}
	plane.client = &Client{}
	plane.maintenance.wake = make(chan struct{}, 1)
	plane.maintenance.notBefore = map[string]time.Time{}
	plane.maintenance.limit = agentcontrol.MaxMaintenanceBatchEvents
	outbox := plane.config.Maintenance.Outbox.(*memoryOutbox)
	outbox.add(MaintenanceEvent{ID: "a"}, MaintenanceEvent{ID: "b"}, MaintenanceEvent{ID: "c"}, MaintenanceEvent{ID: "d"})
	tooLarge := &agentv1pb.MaintenanceEventResult{Error: "too large", ErrorCode: agentcontrol.MaintenanceErrorCodeBatchTooLarge}
	plane.applyMaintenanceAck(&maintenanceBatch{events: []string{"a", "b", "c", "d"}}, &agentv1pb.MaintenanceAck{Events: []*agentv1pb.MaintenanceEventResult{tooLarge, tooLarge, tooLarge, tooLarge}})
	assert.Equal(t, 2, plane.maintenance.limit, "halved, nothing dropped")
	assert.Len(t, outbox.pending(), 4)
	plane.applyMaintenanceAck(&maintenanceBatch{events: []string{"a"}}, &agentv1pb.MaintenanceAck{Events: []*agentv1pb.MaintenanceEventResult{tooLarge}})
	assert.Equal(t, []string{"b", "c", "d"}, outbox.pending(), "a single event too large is refused for good")

	// An answer for another event at a position is not applied.
	plane.applyMaintenanceAck(&maintenanceBatch{events: []string{"b"}}, &agentv1pb.MaintenanceAck{Events: []*agentv1pb.MaintenanceEventResult{{EventId: "c", Persisted: true}}})
	assert.Equal(t, []string{"b", "c", "d"}, outbox.pending())
}

func TestAliveListReplacesTheListOnItsLastPageAndDropsAHalfReceivedOne(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers, agentcontrol.CapabilityAlive)
	control.SetAlivePageSize(2)
	control.SetAlive(map[uint64]uint32{1: 2, 2: 1, 3: 4})
	alive := &recordingAlive{}
	client, _ := newStreamClient(t, control, streamOptions{alive: alive, identity: true})
	startUsersClient(t, client)
	require.Eventually(t, func() bool { return len(alive.applied()) == 1 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, map[uint64]uint32{1: 2, 2: 1, 3: 4}, alive.last(), "two pages, applied once on the last")
	list, ok := client.DataPlane().AliveList()
	require.True(t, ok)
	assert.Equal(t, alive.last(), list)

	// A new list replaces it whole: users missing from it have no device.
	control.SetAlive(map[uint64]uint32{2: 3})
	require.Eventually(t, func() bool { return len(alive.applied()) == 2 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, map[uint64]uint32{2: 3}, alive.last())

	// A session that ends after the first page: the half list is dropped,
	// and the reconnect's list applies.
	control.DropNextAliveAfter(1)
	control.SetAlive(map[uint64]uint32{5: 1, 6: 1, 7: 1})
	require.Eventually(t, func() bool { return len(control.Hellos()) >= 2 }, 5*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return len(alive.last()) == 3 }, 5*time.Second, 10*time.Millisecond)
	for _, applied := range alive.applied() {
		assert.NotEqual(t, map[uint64]uint32{5: 1, 6: 1}, applied, "a half-received list is never applied")
	}
	assert.Equal(t, map[uint64]uint32{5: 1, 6: 1, 7: 1}, alive.last())
	assert.Equal(t, float64(3), heartbeatMetricOf(t, control, MetricAliveUsers))
}

func TestAliveListPagesOfAnotherRevisionStartANewList(t *testing.T) {
	alive := &recordingAlive{}
	plane := &DataPlane{config: DataPlaneConfig{Alive: alive}, now: time.Now, wake: make(chan struct{}, 1)}
	plane.client = &Client{}
	plane.alive.arrived = make(chan struct{})
	plane.ctx = context.Background()
	plane.receiveAlive("s1", &agentv1pb.AliveList{Revision: 1, Entries: []*agentv1pb.UserAlive{{UserId: 1, AliveCount: 1}}})
	plane.receiveAlive("s1", &agentv1pb.AliveList{Revision: 2, LastPage: true, Entries: []*agentv1pb.UserAlive{{UserId: 2, AliveCount: 2}}})
	plane.applyPendingAlive()
	assert.Equal(t, map[uint64]uint32{2: 2}, alive.last())
	// An empty list is one empty page: nobody online.
	plane.receiveAlive("s1", &agentv1pb.AliveList{Revision: 3, LastPage: true})
	plane.applyPendingAlive()
	assert.Equal(t, map[uint64]uint32{}, alive.last())
}

func TestTransientReportAckKeepsTheBatchAndResendsAfterRetry(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers, agentcontrol.CapabilityReports)
	control.UnavailableReports(1)
	client, _ := newStreamClient(t, control, streamOptions{reports: true, identity: true})
	startUsersClient(t, client)
	hello := control.Hellos()[0]
	assert.True(t, agentcontrol.TransientReportAcks(hello.Capabilities, client.ServerCapabilities()), "transient_ack listed and echoed")

	require.NoError(t, client.DataPlane().SubmitTraffic(trafficReport(4)))
	require.Eventually(t, func() bool { return len(control.Batches()) == 1 && spooled(client) == 0 }, 5*time.Second, 10*time.Millisecond)
	acks := control.ReportAcks()
	require.Len(t, acks, 2)
	assert.Equal(t, agentcontrol.ReportErrorCodeUnavailable, acks[0].GetErrorCode())
	assert.True(t, acks[1].GetApplied())
	assert.Equal(t, map[uint64][2]uint64{4: {400, 4000}}, control.Traffic())
	assert.Equal(t, float64(1), heartbeatMetricOf(t, control, MetricReportsDeferred))
}

func TestReportAckWithOnlyAnUnknownCodeIsARefusal(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeOptional)
	client, _ := newStreamClient(t, control, streamOptions{reports: true})
	plane := client.DataPlane()
	require.NoError(t, plane.SubmitTraffic(trafficReport(1)))
	require.NoError(t, plane.SubmitTraffic(trafficReport(2)))
	pending := plane.reports.traffic.Pending()
	require.Len(t, pending, 2)
	plane.receiveReportAck("s", &agentv1pb.ReportAck{BatchId: pending[0].BatchID, ErrorCode: agentcontrol.ReportErrorCodeUnavailable, RetryAfterMs: 1000})
	plane.receiveReportAck("s", &agentv1pb.ReportAck{BatchId: pending[1].BatchID, ErrorCode: "report_from_a_later_control"})
	assert.Equal(t, 1, spooled(client), "unavailable keeps, an unknown code drops")
	assert.Equal(t, uint64(1), plane.reports.refused.Load())
}

func TestHelloListsArtifactsOnlyWithTheClientCertificate(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeOptional, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers, agentcontrol.CapabilityArtifacts)
	client, _ := newStreamClient(t, control, streamOptions{artifacts: true})
	startUsersClient(t, client)
	assert.False(t, agentcontrol.HasCapability(control.Hellos()[0].Capabilities, agentcontrol.CapabilityArtifacts), "not on an API key session")
	assert.Equal(t, PluginDownloadHTTP, client.PluginDownload(), "not enrolled: the HTTP download")
	_, err := client.PluginArtifacts()
	require.ErrorIs(t, err, ErrSessionGone)
}

// releaseFixture is a release AgentArtifacts serves.
func releaseFixture(control *agenttest.Control) agenttest.Release {
	release := agenttest.Release{
		PluginID: "wireguard", Version: "4.0.0", Manifest: []byte(`{"id":"wireguard"}`), Artifact: []byte("0123456789abcdefghijklmnopqrstuvwxyz"),
		Signature: "c2lnbmF0dXJl", Publisher: "AnixOps", KeyID: "0123456789abcdef", APIVersion: "v1",
	}
	control.AddRelease(release)
	return release
}

func addressOf(release agenttest.Release, document []byte) *agentv1pb.PluginReleaseAddress {
	return &agentv1pb.PluginReleaseAddress{PluginId: release.PluginID, Version: release.Version, Sha256: sha256Hex(document), Size: int64(len(document))}
}

func shortArtifactRetry(t *testing.T) {
	previous := artifactRetry
	artifactRetry = 20 * time.Millisecond
	t.Cleanup(func() { artifactRetry = previous })
}

func enrolledArtifactsClient(t *testing.T) (*agenttest.Control, *Client, string) {
	t.Helper()
	control := agenttest.New(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers, agentcontrol.CapabilityArtifacts)
	client, credential := newStreamClient(t, control, streamOptions{artifacts: true, identity: true})
	startUsersClient(t, client)
	require.True(t, client.Negotiated(agentcontrol.CapabilityArtifacts))
	require.Equal(t, PluginDownloadArtifacts, client.PluginDownload())
	return control, client, credential
}

func TestArtifactsDownloadByCertificateInOffsetOrder(t *testing.T) {
	shortArtifactRetry(t)
	control, client, _ := enrolledArtifactsClient(t)
	release := releaseFixture(control)
	control.SetArtifactChunkSize(7)
	control.BusyDownloads(2)
	artifacts, err := client.PluginArtifacts()
	require.NoError(t, err)

	described, manifest, err := artifacts.GetPluginManifest(context.Background(), addressOf(release, release.Manifest))
	require.NoError(t, err)
	assert.Equal(t, release.Manifest, manifest)
	assert.Equal(t, "ed25519", described.GetSignatureAlgorithm())

	described, artifact, err := artifacts.DownloadPluginArtifact(context.Background(), addressOf(release, release.Artifact), 1<<20)
	require.NoError(t, err, "plugin_release_download_busy is retried")
	assert.Equal(t, release.Artifact, artifact)
	assert.Equal(t, int64(len(release.Artifact)), described.GetArtifactSize())
	assert.Equal(t, []string{"manifest:wireguard", "artifact:wireguard", "artifact:wireguard", "artifact:wireguard"}, control.ArtifactCalls())
	assert.Equal(t, float64(2), heartbeatMetricOf(t, control, MetricArtifactDownloads))
}

func TestArtifactsDownloadRefusesChunksOutOfOrderOrBeyondTheSize(t *testing.T) {
	control, client, _ := enrolledArtifactsClient(t)
	release := releaseFixture(control)
	control.SetArtifactChunkSize(7)
	artifacts, err := client.PluginArtifacts()
	require.NoError(t, err)

	control.TamperArtifacts(nil, true, nil)
	_, _, err = artifacts.DownloadPluginArtifact(context.Background(), addressOf(release, release.Artifact), 1<<20)
	require.ErrorContains(t, err, "offset")

	control.TamperArtifacts(func(data []byte) []byte { return append(data, 'x') }, false, nil)
	_, _, err = artifacts.DownloadPluginArtifact(context.Background(), addressOf(release, release.Artifact), 1<<20)
	require.ErrorContains(t, err, "exceeds")

	control.TamperArtifacts(func(data []byte) []byte { return data[:len(data)-1] }, false, nil)
	_, _, err = artifacts.DownloadPluginArtifact(context.Background(), addressOf(release, release.Artifact), 1<<20)
	require.ErrorContains(t, err, "names")

	// Another address is refused with its code.
	control.TamperArtifacts(nil, false, nil)
	wrong := addressOf(release, release.Artifact)
	wrong.Sha256 = strings.Repeat("0", 64)
	_, _, err = artifacts.DownloadPluginArtifact(context.Background(), wrong, 1<<20)
	require.Error(t, err)
	assert.Equal(t, agentcontrol.ErrorCodePluginReleaseAddressMismatch, errorCodeOf(err))
}

func TestArtifactsCertificateRefusalDiscardsTheCertificateAndEnrollsAgain(t *testing.T) {
	control, client, credential := enrolledArtifactsClient(t)
	release := releaseFixture(control)
	first := client.TransportStatus().Identity.Serial
	artifacts, err := client.PluginArtifacts()
	require.NoError(t, err)

	// The operator already issued a new one-time credential.
	writeCredential(t, control, credential, "anixagt_second")
	control.RefuseCertificates(agentcontrol.ErrorCodeCertRevoked)
	_, _, err = artifacts.GetPluginManifest(context.Background(), addressOf(release, release.Manifest))
	require.Error(t, err)
	assert.Equal(t, agentcontrol.ErrorCodeCertRevoked, errorCodeOf(err))
	control.RefuseCertificates("")
	require.Eventually(t, func() bool {
		status := client.TransportStatus()
		return status.Identity.Enrolled && status.Identity.Serial != first && client.PluginDownload() == PluginDownloadArtifacts
	}, 10*time.Second, 20*time.Millisecond)
}

func TestStreamCertificateCodes(t *testing.T) {
	t.Run("revoked: enroll again", func(t *testing.T) {
		control := agenttest.New(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers)
		client, credential := newStreamClient(t, control, streamOptions{identity: true})
		startUsersClient(t, client)
		first := client.TransportStatus().Identity.Serial
		writeCredential(t, control, credential, "anixagt_second")
		control.RefuseCertificates(agentcontrol.ErrorCodeCertExpired)
		control.DropSessions()
		require.Eventually(t, func() bool { return client.TransportStatus().Identity.Serial != first }, 5*time.Second, 10*time.Millisecond)
		control.RefuseCertificates("")
		require.Eventually(t, func() bool {
			status := client.TransportStatus()
			return status.Connected && status.Identity.Enrolled && status.Identity.Serial != first
		}, 10*time.Second, 20*time.Millisecond)
	})
	t.Run("wrong node: keep the certificate and retry slowly", func(t *testing.T) {
		previous := wrongNodeReconnect
		wrongNodeReconnect = time.Hour
		t.Cleanup(func() { wrongNodeReconnect = previous })
		control := agenttest.New(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers)
		client, _ := newStreamClient(t, control, streamOptions{identity: true})
		startUsersClient(t, client)
		serial := client.TransportStatus().Identity.Serial
		control.RefuseCertificates(agentcontrol.ErrorCodeCertWrongNode)
		control.DropSessions()
		require.Eventually(t, func() bool {
			return strings.Contains(client.TransportStatus().LastError, agentcontrol.ErrorCodeCertWrongNode)
		}, 5*time.Second, 10*time.Millisecond)
		streams := len(control.Streams())
		time.Sleep(300 * time.Millisecond)
		assert.Equal(t, streams, len(control.Streams()), "no reconnect loop")
		status := client.TransportStatus()
		assert.True(t, status.Identity.Enrolled)
		assert.Equal(t, serial, status.Identity.Serial, "kept")
		assert.Equal(t, float64(1), client.identity.metrics()[MetricIdentityWrongNode])
	})
}

var healthMetricName = regexp.MustCompile(`^agent_(control|identity|dataplane)_[a-z0-9_]+$`)

func TestHeartbeatHealthMetricsAreWithinControlsBounds(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeRequired, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers,
		agentcontrol.CapabilityReports, agentcontrol.CapabilityMaintenance, agentcontrol.CapabilityAlive, agentcontrol.CapabilityArtifacts)
	client, _ := newStreamClient(t, control, streamOptions{outbox: &memoryOutbox{}, alive: &recordingAlive{}, artifacts: true, reports: true, identity: true})
	startUsersClient(t, client)
	var metrics map[string]float64
	require.Eventually(t, func() bool {
		for _, message := range control.Received() {
			if heartbeat := message.GetHeartbeat(); heartbeat != nil {
				metrics = heartbeat.GetMetrics()
				return true
			}
		}
		return false
	}, 5*time.Second, 20*time.Millisecond)
	health := 0
	for name := range metrics {
		if strings.HasPrefix(name, "agent_") {
			health++
			assert.Regexp(t, healthMetricName, name)
			assert.LessOrEqual(t, len(name), 108)
		}
	}
	assert.LessOrEqual(t, health, 64)
	for _, name := range []string{MetricMaintenancePending, MetricAliveRevision, MetricArtifactDownloads, MetricIdentityEnrolled, MetricReportsDeferred} {
		assert.Contains(t, metrics, name)
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
