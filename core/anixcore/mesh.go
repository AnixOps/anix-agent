package anixcore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	vCore "github.com/AnixOps/anix-agent/v5/core"
)

// The intranet mesh (anix-agent docs/mesh.md "Kernel interface"): anixcore
// with the feature meshFeature runs the networks of PUT /v1/mesh, each a
// "type": "mesh" configuration (config_version 1) tagged meshTagPrefix +
// id, and answers their state on GET /v1/mesh. {"networks": []} stops
// them.

// meshFeature is the anixcore feature of /v1/mesh.
const meshFeature = "mesh"

// meshTagPrefix starts the kernel tag of a mesh network.
const meshTagPrefix = "mesh-"

var _ vCore.MeshApplier = (*Core)(nil)

// MeshSupported implements vCore.MeshApplier.
func (c *Core) MeshSupported() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.client != nil && c.client.mesh.Load()
}

// ApplyMesh implements vCore.MeshApplier. The networks are kept, so a
// restarted anixcore gets them again.
func (c *Core) ApplyMesh(networks []panel.MeshNetwork) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client == nil {
		return errors.New("anixcore: the core is not started")
	}
	if !c.client.mesh.Load() {
		c.mesh = nil
		if len(networks) == 0 {
			return nil
		}
		return vCore.ErrMeshUnsupported
	}
	c.mesh = meshBody(networks)
	return c.putMesh()
}

// putMesh sends c.mesh; c.mu is held.
func (c *Core) putMesh() error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	if err := c.client.do(ctx, http.MethodPut, "/v1/mesh", c.mesh, nil); err != nil {
		return fmt.Errorf("anixcore mesh: %w", err)
	}
	return nil
}

// replayMesh gives a fresh anixcore the networks; c.mu is held.
func (c *Core) replayMesh() error {
	if c.mesh == nil || !c.client.mesh.Load() {
		return nil
	}
	return c.putMesh()
}

// MeshStatus implements vCore.MeshApplier.
func (c *Core) MeshStatus(ctx context.Context) ([]panel.MeshNetworkStatus, error) {
	c.mu.Lock()
	client := c.client
	c.mu.Unlock()
	if client == nil || !client.mesh.Load() {
		return nil, vCore.ErrMeshUnsupported
	}
	var answer struct {
		Networks []panel.MeshNetworkStatus `json:"networks"`
	}
	if err := client.do(ctx, http.MethodGet, "/v1/mesh", nil, &answer); err != nil {
		return nil, fmt.Errorf("anixcore mesh status: %w", err)
	}
	for i := range answer.Networks {
		answer.Networks[i].ID = strings.TrimPrefix(answer.Networks[i].Tag, meshTagPrefix)
		answer.Networks[i].Tag = ""
	}
	return answer.Networks, nil
}

// meshBody is the PUT /v1/mesh body of networks: each flat network of the
// panel in the kernel's layered configuration.
func meshBody(networks []panel.MeshNetwork) map[string]any {
	out := make([]map[string]any, 0, len(networks))
	for _, n := range networks {
		network := map[string]any{"name": n.Name, "secret": n.Secret, "secure_mode": n.SecureMode}
		if n.Cipher != "" {
			network["cipher"] = n.Cipher
		}
		node := map[string]any{"address": n.Address}
		if n.AddressV6 != "" {
			node["address_v6"] = n.AddressV6
		}
		if n.Role != "" {
			node["role"] = n.Role
		}
		if len(n.Listen) > 0 {
			node["listen"] = n.Listen
		}
		config := map[string]any{
			"tag": meshTagPrefix + n.ID, "type": "mesh", "config_version": 1,
			"network": network, "node": node, "peers": n.Peers,
		}
		if len(n.Peers) == 0 {
			config["peers"] = []any{}
		}
		if len(n.Subnets) > 0 {
			config["subnets"] = n.Subnets
		}
		if len(n.Routing) > 0 {
			config["routing"] = n.Routing
		}
		out = append(out, config)
	}
	return map[string]any{"networks": out}
}
