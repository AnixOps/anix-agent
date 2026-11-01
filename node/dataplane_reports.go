package node

import (
	"context"
	"math"
	"sort"
	"strings"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v5/api/agent"
	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/common/destinations"
	"github.com/AnixOps/anix-agent/v5/common/monitor"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	log "github.com/sirupsen/logrus"
)

// Reports on the stream (AG-5): traffic with online IPs, logs and status.
// Traffic and logs go through the data plane's spool, which keeps them
// while the stream is down.

const (
	// trafficUsersPerBatch bounds the users of one TrafficReport, so a
	// batch stays far below Control's 4 MiB message limit.
	trafficUsersPerBatch = 5000
	// logBatchEntries batches the node's log entries.
	logBatchEntries = 200
	// destinationEntriesPerBatch bounds the entries of one
	// DestinationReport, far below Control's 50000 and 4 MiB.
	destinationEntriesPerBatch = 10000
)

// logBatchInterval spools the buffered log entries as one LogBatch per node
// at most this often (each batch is a row Control remembers for 7 days); a
// variable for tests.
var logBatchInterval = 30 * time.Second

// submitTraffic hands a controller's traffic window to the spool as a
// TrafficReport (in batches of trafficUsersPerBatch users). online is the
// controller's online IPs; the report carries the union of every
// controller of the node, since Control replaces the node's whole alive set
// with each report. A window with no traffic and no online IPs is not
// reported, unless the last report had online IPs (to clear them).
func (n *nodeDataPlane) submitTraffic(controller *Controller, traffic []panel.UserTraffic, online map[int][]string) error {
	plane := n.client.DataPlane()
	n.reportMu.Lock()
	if n.online == nil {
		n.online = map[*Controller]map[int][]string{}
	}
	n.online[controller] = online
	merged := mergeOnline(n.online)
	clear := len(merged) == 0 && n.onlineSent
	n.reportMu.Unlock()

	users := make([]*agentv1pb.UserTraffic, 0, len(traffic))
	for _, entry := range traffic {
		if entry.UID <= 0 || (entry.Upload <= 0 && entry.Download <= 0) {
			continue
		}
		users = append(users, &agentv1pb.UserTraffic{UserId: uint64(entry.UID), UploadBytes: uint64(max(entry.Upload, 0)), DownloadBytes: uint64(max(entry.Download, 0))}) // #nosec G115 -- checked positive.
	}
	if len(users) == 0 && len(merged) == 0 && !clear {
		return nil
	}
	windowEnd := time.Now().UnixMilli()
	for start := 0; start == 0 || start < len(users); start += trafficUsersPerBatch {
		end := min(start+trafficUsersPerBatch, len(users))
		report := &agentv1pb.TrafficReport{Users: users[start:end], Online: merged, WindowEndUnixMs: windowEnd}
		if err := plane.SubmitTraffic(report); err != nil {
			if start == 0 {
				return err
			}
			// The earlier batches are spooled and count; the rest of
			// this window is lost rather than counted twice.
			n.logger().WithError(err).Error("Could not spool part of a traffic window")
			break
		}
	}
	n.reportMu.Lock()
	n.onlineSent = len(merged) > 0
	n.reportMu.Unlock()
	return nil
}

// reportDestinations reads the controller's destination statistics of the
// window (destinations.v1) and spools them while the stream carries
// destinations.v1 or is briefly down. Otherwise the window is dropped. The
// core's counters are read either way, so they never pile up.
func (c *Controller) reportDestinations() {
	provider, ok := c.server.(vCore.DestinationProvider)
	if !ok {
		return
	}
	traffic, err := provider.GetDestinationTraffic(c.tag)
	if err != nil {
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).Warn("Could not read the destination statistics")
		return
	}
	if len(traffic) == 0 || c.stream.mode(agentcontrol.CapabilityDestinations) == agentapi.DataPlaneOff {
		return
	}
	c.stream.submitDestinations(c.tag, traffic)
}

// submitDestinations spools a window of destination statistics, in
// batches of destinationEntriesPerBatch entries.
func (n *nodeDataPlane) submitDestinations(tag string, traffic []destinations.Traffic) {
	entries := make([]*agentv1pb.DestinationTraffic, 0, len(traffic))
	for _, entry := range traffic {
		if entry.UID <= 0 || (entry.Upload <= 0 && entry.Download <= 0 && entry.Connections <= 0) {
			continue
		}
		entries = append(entries, &agentv1pb.DestinationTraffic{
			UserId: uint64(entry.UID), Domain: entry.Domain, Protocol: entry.Protocol, // #nosec G115 -- checked positive.
			UploadBytes: uint64(max(entry.Upload, 0)), DownloadBytes: uint64(max(entry.Download, 0)), // #nosec G115 -- checked positive.
			Connections: uint32(min(max(entry.Connections, 0), math.MaxUint32)), // #nosec G115 -- clamped.
		})
	}
	windowEnd := time.Now().UnixMilli()
	plane := n.client.DataPlane()
	for start := 0; start < len(entries); start += destinationEntriesPerBatch {
		end := min(start+destinationEntriesPerBatch, len(entries))
		if err := plane.SubmitDestinations(&agentv1pb.DestinationReport{Entries: entries[start:end], WindowEndUnixMs: windowEnd}); err != nil {
			n.logger().WithError(err).WithField("tag", tag).Warn("Could not spool the destination statistics; this window's are dropped")
			return
		}
	}
}

// mergeOnline is the union of the controllers' online IPs, by user id.
func mergeOnline(online map[*Controller]map[int][]string) []*agentv1pb.OnlineUser {
	ips := map[int]map[string]struct{}{}
	for _, users := range online {
		for uid, addresses := range users {
			if uid <= 0 {
				continue
			}
			if ips[uid] == nil {
				ips[uid] = map[string]struct{}{}
			}
			for _, address := range addresses {
				if address = strings.TrimSpace(address); address != "" {
					ips[uid][address] = struct{}{}
				}
			}
		}
	}
	merged := make([]*agentv1pb.OnlineUser, 0, len(ips))
	for uid, set := range ips {
		if len(set) == 0 {
			continue
		}
		user := &agentv1pb.OnlineUser{UserId: uint64(uid)} // #nosec G115 -- checked positive.
		for address := range set {
			user.Ips = append(user.Ips, address)
		}
		sort.Strings(user.Ips)
		merged = append(merged, user)
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].UserId < merged[j].UserId })
	return merged
}

// submitLogs buffers log entries for the node's next LogBatch.
func (n *nodeDataPlane) submitLogs(entries []panel.NodeLogEntry) error {
	n.reportMu.Lock()
	for _, entry := range entries {
		n.logBuffer = append(n.logBuffer, logEntry(entry))
	}
	full := len(n.logBuffer) >= logBatchEntries
	n.reportMu.Unlock()
	stopped := false
	if n.stop != nil {
		select {
		case <-n.stop:
			// After close (a controller's last entries at shutdown): no
			// flusher runs any more.
			stopped = true
		default:
		}
	}
	if full || stopped {
		return n.flushLogs()
	}
	return nil
}

// flushLogs spools the buffered entries as one LogBatch.
func (n *nodeDataPlane) flushLogs() error {
	n.reportMu.Lock()
	entries := n.logBuffer
	n.logBuffer = nil
	n.reportMu.Unlock()
	if len(entries) == 0 || n.client == nil || n.client.DataPlane() == nil {
		return nil
	}
	return n.client.DataPlane().SubmitLogs(&agentv1pb.LogBatch{Entries: entries})
}

// runLogFlusher flushes the log buffer every logBatchInterval until stop.
func (n *nodeDataPlane) runLogFlusher() {
	ticker := time.NewTicker(logBatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-n.stop:
			_ = n.flushLogs()
			return
		case <-ticker.C:
			_ = n.flushLogs()
		}
	}
}

// close stops the node data plane's background work, flushing the logs.
func (n *nodeDataPlane) close() {
	n.stopOnce.Do(func() {
		if n.stop != nil {
			close(n.stop)
			<-n.stopped
		}
		n.background.Wait()
		if n.network != nil {
			n.network.close()
		}
	})
}

// logEntry converts a node log entry; levels are debug, info, warning or
// error.
func logEntry(entry panel.NodeLogEntry) *agentv1pb.LogEntry {
	level := strings.ToLower(entry.Level)
	switch level {
	case "trace":
		level = "debug"
	case "warn":
		level = "warning"
	case "fatal", "panic":
		level = "error"
	}
	converted := &agentv1pb.LogEntry{
		Level: level, Source: entry.Source, Message: entry.Message, TraceId: entry.TraceID,
		LoggedAtUnixMs: entry.Timestamp.UnixMilli(),
	}
	if entry.FieldsJSON != "" {
		converted.FieldsJson = []byte(entry.FieldsJSON)
	}
	return converted
}

// nodeStatus is the node's NodeStatus: the machine's usage, the Agent's
// uptime and the runtime health of every controller's core (healthy only
// when all are).
func (n *nodeDataPlane) nodeStatus(context.Context) (*agentv1pb.NodeStatus, error) {
	info, err := monitor.GetSystemInfo()
	n.reportMu.Lock()
	if err == nil {
		n.lastSystem = info
	} else if n.lastSystem != nil {
		// Control writes the usage and the runtime health from one
		// NodeStatus: the last sample rather than zeros.
		n.logger().WithError(err).Debug("Could not read the system usage; sending the last sample")
		info, err = n.lastSystem, nil
	}
	n.reportMu.Unlock()
	if err != nil {
		return nil, err
	}
	status := &agentv1pb.NodeStatus{
		CpuUsagePercent: info.CPUUsage, MemoryUsagePercent: info.MemoryUsage, DiskUsagePercent: info.DiskUsage,
		UptimeSeconds: info.Uptime, RuntimeHealthy: true, ObservedAtUnixMs: time.Now().UnixMilli(),
	}
	var problems []string
	for _, controller := range n.allControllers() {
		if !controller.isStarted() {
			continue
		}
		provider, ok := controller.server.(vCore.RuntimeHealthProvider)
		if !ok {
			continue
		}
		healthy, message := provider.RuntimeHealth(controller.tag)
		if !healthy {
			status.RuntimeHealthy = false
			if message == "" {
				message = "runtime unhealthy"
			}
			problems = append(problems, message)
		}
	}
	status.RuntimeError = strings.Join(problems, "; ")
	if len(status.RuntimeError) > 1024 {
		status.RuntimeError = status.RuntimeError[:1024]
	}
	n.reportMu.Lock()
	n.health = &runtimeHealth{healthy: status.RuntimeHealthy, message: status.RuntimeError}
	n.reportMu.Unlock()
	return status, nil
}

// runtimeHealth is the node's runtime health as a NodeStatus reports it.
type runtimeHealth struct {
	healthy bool
	message string
}

// runtimeHealthChanged asks for a NodeStatus at once when the runtime
// health of the node's controllers differs from the one last reported: a
// NodeStatus carries the health and the current system usage together
// (Control writes both from it), so a health change is never sent alone.
func (n *nodeDataPlane) runtimeHealthChanged() {
	if n == nil || n.client == nil || n.client.DataPlane() == nil {
		return
	}
	healthy, messages := true, []string(nil)
	for _, controller := range n.allControllers() {
		if !controller.isStarted() {
			continue
		}
		provider, ok := controller.server.(vCore.RuntimeHealthProvider)
		if !ok {
			continue
		}
		if ok, message := provider.RuntimeHealth(controller.tag); !ok {
			healthy = false
			if message == "" {
				message = "runtime unhealthy"
			}
			messages = append(messages, message)
		}
	}
	message := strings.Join(messages, "; ")
	if len(message) > 1024 {
		message = message[:1024]
	}
	n.reportMu.Lock()
	last := n.health
	n.reportMu.Unlock()
	if last == nil || (last.healthy == healthy && last.message == message) {
		// Nothing reported yet (the session's first status carries it),
		// or no change.
		return
	}
	n.client.DataPlane().StatusChanged()
}
