package panel

import "github.com/AnixOps/anix-agent/v4/common/monitor"

// Close implements api/client.NodeAPI.
// REST transport has no persistent connection to close.
func (c *Client) Close() error { return nil }

// GetNodeID implements api/client.NodeAPI.
func (c *Client) GetNodeID() int { return c.NodeId }

// GetAPIHost implements api/client.NodeAPI.
func (c *Client) GetAPIHost() string { return c.APIHost }

// GetAPIKey implements api/client.NodeAPI.
func (c *Client) GetAPIKey() string { return c.Token }

// GetSecret implements api/client.NodeAPI.
func (c *Client) GetSecret() string { return c.Secret }

// IsSignEnabled implements api/client.NodeAPI.
func (c *Client) IsSignEnabled() bool { return c.EnableSign }

// SetNodeType implements api/client.NodeAPI.
func (c *Client) SetNodeType(nodeType string) {
	c.NodeType = nodeType
	if c.client != nil && nodeType != "" {
		c.client.SetQueryParam("node_type", nodeType)
	}
}

// SupportsSync implements api/client.NodeAPI.
func (c *Client) SupportsSync() bool { return true }

// ReportNodeStatus implements api/client.NodeAPI.
// REST transport does not expose a dedicated node status RPC, so this is a no-op.
func (c *Client) ReportNodeStatus(_ *monitor.SystemInfo, _ int, _ int64, _ int64) error { return nil }

// ReportNodeLogs implements api/client.NodeAPI.
// REST transport does not expose a dedicated node log ingestion endpoint, so this is a no-op.
func (c *Client) ReportNodeLogs(_ []NodeLogEntry) error { return nil }

// ReportNodeRuntimeHealth sends the supervised runtime state through the
// node-scoped REST channel.
func (c *Client) ReportNodeRuntimeHealth(healthy bool, message string) error {
	return c.reportRuntimeHealth(&RuntimeHealthRequest{Healthy: healthy, Error: message})
}

// ResetPullCache forgets the last configuration and user answers (ETag,
// body hash), so the next pulls are taken in full. The node calls it when
// the legacy pull takes over again after the Agent control stream carried
// the data.
func (c *Client) ResetPullCache() {
	c.nodeEtag = ""
	c.userEtag = ""
	c.responseBodyHash = ""
}
