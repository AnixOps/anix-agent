package node

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	"github.com/AnixOps/anix-agent/v4/common/maintenance"
	"github.com/AnixOps/anix-agent/v4/plugin"
)

// streamMaintenanceInterval is how often the data plane reads the outbox
// (0: agentapi.DefaultMaintenanceInterval); tests lower it.
var streamMaintenanceInterval time.Duration

// maintenanceOutbox is the supervisor's durable outbox as the data plane
// drains it on the stream (maintenance.v1).
type maintenanceOutbox struct{ store *maintenance.Store }

func (o maintenanceOutbox) PendingMaintenance(limit int) ([]agentapi.MaintenanceEvent, error) {
	events, err := o.store.Pending(limit)
	if err != nil {
		return nil, err
	}
	pending := make([]agentapi.MaintenanceEvent, 0, len(events))
	for _, event := range events {
		encoded, err := json.Marshal(event)
		if err != nil {
			return nil, err
		}
		pending = append(pending, agentapi.MaintenanceEvent{ID: event.EventID, JSON: encoded})
	}
	return pending, nil
}

func (o maintenanceOutbox) RemoveMaintenance(ids []string) error { return o.store.Remove(ids) }

// Plugin commands may use the v3 gRPC stream. Maintenance still uses the same
// authenticated WebSocket protocol as HTTP nodes, with credentials from the
// final registered NodeAPI identity and a separate HTTP(S) ApiHost.
//
// While the control stream carries the outbox (maintenance.v1) no
// WebSocket is opened: the data plane drains it.
func (c *Controller) attachMaintenanceTransport(supervisor *plugin.Supervisor) error {
	if c.streamCarriesMaintenance() {
		return nil
	}
	c.syncMu.Lock()
	defer c.syncMu.Unlock()
	if c.closed {
		return nil
	}
	if c.syncManager != nil {
		if !c.syncManager.config.EnableWebSocket {
			return fmt.Errorf("plugin maintenance requires WebSocket enabled for node %d", c.apiClient.GetNodeID())
		}
		c.syncManager.SetMaintenanceStore(supervisor.MaintenanceStore())
		return nil
	}
	endpoint, err := url.Parse(c.apiClient.GetAPIHost())
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") {
		return fmt.Errorf("plugin maintenance requires an HTTP(S) ApiHost alongside GRPCHost for node %d", c.apiClient.GetNodeID())
	}
	config := c.buildSyncConfig()
	if !config.EnableWebSocket {
		return fmt.Errorf("plugin maintenance requires WebSocket enabled for node %d", c.apiClient.GetNodeID())
	}
	config.MaintenanceOnly = true
	sm := NewSyncManager(c.apiClient, c, config)
	sm.SetMaintenanceStore(supervisor.MaintenanceStore())
	if err := sm.Start(); err != nil {
		_ = sm.Close()
		return err
	}
	c.syncManager = sm
	return nil
}
