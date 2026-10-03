package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v4/api/agent/agenttest"
	"github.com/AnixOps/anix-agent/v4/api/agent/state"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type reportsOptions struct {
	trafficBytes int64
	status       func(context.Context) (*agentv1pb.NodeStatus, error)
	packages     func(context.Context) ([]*agentv1pb.PackageReport, error)
}

func newReportsClient(t *testing.T, control *agenttest.Control, root string, options reportsOptions) *Client {
	t.Helper()
	store, err := state.Open(root, agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: control.NodeID})
	require.NoError(t, err)
	plane := &DataPlaneConfig{State: store, Config: nopConfig{}, Users: &recordingUsers{},
		Reports: &ReportsConfig{TrafficMaxBytes: options.trafficBytes, Status: options.status, StatusInterval: 200 * time.Millisecond}}
	if options.packages != nil {
		plane.PackageReports = &PackageReportsConfig{Collect: options.packages, Interval: 200 * time.Millisecond}
	}
	client, err := NewClient(Config{
		Target: control.Address, NodeID: int(control.NodeID), APIKey: control.APIKey, UseTLS: true, ServerName: control.ServerName,
		RootCAs: control.ServerCAs, AgentVersion: "test-agent", InstanceID: "instance-1",
		Capabilities: []*agentv1pb.Capability{{Name: "agent.control", Version: "v1"}},
		Heartbeat:    time.Second, ReconnectMin: 10 * time.Millisecond, ReconnectMax: 50 * time.Millisecond,
		DialTimeout: 2 * time.Second, DataPlane: plane,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func shortAckTimeout(t *testing.T) {
	previous := reportAckTimeout
	reportAckTimeout = 150 * time.Millisecond
	t.Cleanup(func() { reportAckTimeout = previous })
}

func trafficReport(users ...uint64) *agentv1pb.TrafficReport {
	report := &agentv1pb.TrafficReport{WindowEndUnixMs: time.Now().UnixMilli()}
	for _, id := range users {
		report.Users = append(report.Users, &agentv1pb.UserTraffic{UserId: id, UploadBytes: 100 * id, DownloadBytes: 1000 * id})
	}
	return report
}

func spooled(client *Client) int {
	count, _, _ := client.dataPlane.spoolStats()
	return count
}

func TestReportsAreSpooledSentAndDroppedOnTheirAck(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeOptional, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers, agentcontrol.CapabilityReports)
	client := newReportsClient(t, control, t.TempDir(), reportsOptions{})
	startUsersClient(t, client)
	plane := client.DataPlane()
	assert.Equal(t, DataPlaneStream, plane.Mode(agentcontrol.CapabilityReports))
	assert.True(t, agentcontrol.HasCapabilityVersion(control.Hellos()[0].Capabilities, agentcontrol.CapabilityReports, "v1"))

	report := trafficReport(1, 2)
	report.Online = []*agentv1pb.OnlineUser{{UserId: 1, Ips: []string{"203.0.113.7"}}}
	require.NoError(t, plane.SubmitTraffic(report))
	require.NoError(t, plane.SubmitLogs(&agentv1pb.LogBatch{Entries: []*agentv1pb.LogEntry{{Level: "info", Message: "started", LoggedAtUnixMs: 1}}}))
	require.Eventually(t, func() bool { return len(control.Batches()) == 2 && spooled(client) == 0 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, map[uint64][2]uint64{1: {100, 1000}, 2: {200, 2000}}, control.Traffic())
	require.Len(t, control.Online(), 1)
	assert.Equal(t, "started", control.LogEntries()[0].Message)
	for _, id := range control.Batches() {
		assert.Regexp(t, `^node:proxy-12:[0-9a-f]{32}:[0-9]+$`, id)
		assert.LessOrEqual(t, len(id), 128)
	}
	assert.Equal(t, float64(2), heartbeatMetricOf(t, control, MetricReportsAcked))
}

func TestReportsWaitInTheSpoolWhileTheStreamIsDownAndReplayInOrder(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeOptional, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers, agentcontrol.CapabilityReports)
	root := t.TempDir()
	client := newReportsClient(t, control, root, reportsOptions{})
	startUsersClient(t, client)
	plane := client.DataPlane()

	// The stream goes down: reports stay pending and go to the spool.
	control.SetMode(agenttest.ModeRequired)
	control.DropSessions()
	require.Eventually(t, func() bool { return !client.IsConnected() }, 5*time.Second, 5*time.Millisecond)
	assert.Equal(t, DataPlanePending, plane.Mode(agentcontrol.CapabilityReports))
	for id := uint64(1); id <= 3; id++ {
		require.NoError(t, plane.SubmitTraffic(trafficReport(id)))
	}
	assert.Equal(t, 3, spooled(client))
	files, err := os.ReadDir(filepath.Join(root, "proxy-12", "spool", "traffic"))
	require.NoError(t, err)
	assert.Len(t, files, 3)

	// A restart while the stream is down keeps them, with their batch ids.
	require.NoError(t, client.Close())
	restarted := newReportsClient(t, control, root, reportsOptions{})
	assert.Equal(t, 3, spooled(restarted))
	control.SetMode(agenttest.ModeOptional)
	startUsersClient(t, restarted)
	require.Eventually(t, func() bool { return len(control.Batches()) == 3 && spooled(restarted) == 0 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, map[uint64][2]uint64{1: {100, 1000}, 2: {200, 2000}, 3: {300, 3000}}, control.Traffic())

	// In order: the sequence of the batch ids that reached Control.
	var sequence []string
	for _, message := range control.Received() {
		if traffic := message.GetTraffic(); traffic != nil {
			parts := strings.Split(traffic.BatchId, ":")
			sequence = append(sequence, parts[len(parts)-1])
		}
	}
	assert.Equal(t, []string{"1", "2", "3"}, sequence)
}

func TestReportsAreResentUntilAckedAndCountOnce(t *testing.T) {
	shortAckTimeout(t)
	control := agenttest.New(t, agenttest.ModeOptional, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers, agentcontrol.CapabilityReports)
	client := newReportsClient(t, control, t.TempDir(), reportsOptions{})
	startUsersClient(t, client)
	plane := client.DataPlane()

	// Control cannot record now: no ReportAck, the batch is resent.
	control.HoldReportAcks(true)
	require.NoError(t, plane.SubmitTraffic(trafficReport(1)))
	require.Eventually(t, func() bool { return control.Deliveries() >= 3 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, 1, spooled(client))
	control.HoldReportAcks(false)
	require.Eventually(t, func() bool { return spooled(client) == 0 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, map[uint64][2]uint64{1: {100, 1000}}, control.Traffic())

	// A recorded batch whose ReportAck was lost is answered as recorded
	// before when resent, and still counts once.
	control.LoseNextAcks(1)
	require.NoError(t, plane.SubmitTraffic(trafficReport(2)))
	require.Eventually(t, func() bool { return spooled(client) == 0 }, 5*time.Second, 10*time.Millisecond)
	acks := control.ReportAcks()
	last := acks[len(acks)-1]
	assert.False(t, last.Applied)
	assert.Empty(t, last.Error)
	assert.Equal(t, map[uint64][2]uint64{1: {100, 1000}, 2: {200, 2000}}, control.Traffic())

	// A batch Control refuses for good is dropped too.
	control.RefuseBatches(func(string) string { return "traffic entry 0: user_id is required" })
	require.NoError(t, plane.SubmitTraffic(trafficReport(3)))
	require.Eventually(t, func() bool { return spooled(client) == 0 && client.dataPlane.reports.refused.Load() == 1 }, 5*time.Second, 10*time.Millisecond)
	_, present := control.Traffic()[3]
	assert.False(t, present)
}

func TestReportSpoolDropsTheOldestBatchesAtItsBound(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeOptional)
	client := newReportsClient(t, control, t.TempDir(), reportsOptions{trafficBytes: 600})
	plane := client.DataPlane()
	for id := uint64(1); id <= 20; id++ {
		require.NoError(t, plane.SubmitTraffic(trafficReport(id, id+100, id+200)))
	}
	count, bytes, drops := client.dataPlane.spoolStats()
	assert.LessOrEqual(t, bytes, int64(600))
	assert.Positive(t, drops.Size)
	assert.Equal(t, 20, count+int(drops.Size))
	metrics := client.dataPlane.metrics()
	assert.Equal(t, float64(drops.Size), metrics[MetricReportSpoolDropped])
}

func TestStatusAndPackageReportsAreLatestOnlyAndNeedTheirCapabilities(t *testing.T) {
	control := agenttest.New(t, agenttest.ModeOptional, agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers, agentcontrol.CapabilityReports)
	var observed atomic.Int64
	observed.Store(1000)
	packages := func(context.Context) ([]*agentv1pb.PackageReport, error) {
		return []*agentv1pb.PackageReport{{PluginId: "machine-telemetry", Kind: "systemd.services", Version: "4.1.0", PayloadJson: []byte(`{"supported":true,"window_seconds":600,"units":[]}`), ObservedAtUnixMs: observed.Load()}}, nil
	}
	status := func(context.Context) (*agentv1pb.NodeStatus, error) {
		return &agentv1pb.NodeStatus{CpuUsagePercent: 12.5, RuntimeHealthy: true, ObservedAtUnixMs: time.Now().UnixMilli()}, nil
	}
	client := newReportsClient(t, control, t.TempDir(), reportsOptions{status: status, packages: packages})
	startUsersClient(t, client)

	// reports.v1 is served, package-reports.v1 is not: status only.
	require.Eventually(t, func() bool { return len(control.NodeStatuses()) >= 2 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, 12.5, control.NodeStatuses()[0].CpuUsagePercent)
	assert.Empty(t, control.PackageReports())
	assert.True(t, agentcontrol.HasCapabilityVersion(control.Hellos()[0].Capabilities, agentcontrol.CapabilityPackageReports, "v1"))

	control.Serve(agentcontrol.CapabilityPackageReports, true)
	control.DropSessions()
	require.Eventually(t, func() bool { return len(control.PackageReports()) == 1 }, 5*time.Second, 10*time.Millisecond)
	time.Sleep(500 * time.Millisecond)
	assert.Len(t, control.PackageReports(), 1, "the same observation is sent once per session")
	observed.Store(2000)
	require.Eventually(t, func() bool { return len(control.PackageReports()) == 2 }, 5*time.Second, 10*time.Millisecond)
	report := control.PackageReports()[1]
	assert.Equal(t, "machine-telemetry", report.PluginId)
	assert.Equal(t, "4.1.0", report.Version)
	assert.Equal(t, int64(2000), report.ObservedAtUnixMs)
	// Package reports and status are never spooled.
	assert.Zero(t, spooled(client))
}

// heartbeatMetricOf waits for a heartbeat carrying metric and returns it.
func heartbeatMetricOf(t *testing.T, control *agenttest.Control, metric string) float64 {
	t.Helper()
	var value float64
	require.Eventually(t, func() bool {
		messages := control.Received()
		for index := len(messages) - 1; index >= 0; index-- {
			if heartbeat := messages[index].GetHeartbeat(); heartbeat != nil {
				if got, ok := heartbeat.Metrics[metric]; ok && got > 0 {
					value = got
					return true
				}
			}
		}
		return false
	}, 5*time.Second, 20*time.Millisecond)
	return value
}
