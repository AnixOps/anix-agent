package node

import (
	"fmt"
	"net/url"

	"github.com/AnixOps/anix-agent/v4/plugin"
)

// Plugin commands may use the v3 gRPC stream. Maintenance still uses the same
// authenticated WebSocket protocol as HTTP nodes, with credentials from the
// final registered NodeAPI identity and a separate HTTP(S) ApiHost.
func (c *Controller) attachMaintenanceTransport(supervisor *plugin.Supervisor) error {
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
