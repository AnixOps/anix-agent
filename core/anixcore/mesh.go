package anixcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	vCore "github.com/AnixOps/anix-agent/v5/core"
)

// The intranet mesh (anix-agent docs/mesh.md "Kernel interface"): anixcore
// with the feature meshFeature runs the networks of PUT /v1/mesh, each a
// "type": "mesh" configuration (config_version 1) tagged meshTagPrefix +
// id, and answers their state on GET /v1/mesh. {"networks": []} stops
// them. The sections dns and host_groups go only to a kernel that lists
// meshDNSFeature and meshHostGroupsFeature, and the network fields kind
// and native_keys only to one that lists meshNativeKeysFeature: the kernel
// rejects unknown fields. A kernel that lists meshRegionRequestsFeature holds the node
// owner's region requests in the GET answer until
// DELETE /v1/mesh/region_requests/{id}.

// The anixcore features of the mesh.
const (
	meshFeature               = "mesh"
	meshDNSFeature            = "mesh_dns"
	meshHostGroupsFeature     = "mesh_host_groups"
	meshRegionRequestsFeature = "mesh_region_requests"
	meshNativeKeysFeature     = "mesh_native_keys"
)

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
	c.mesh = append([]panel.MeshNetwork{}, networks...)
	return c.putMesh()
}

// putMesh sends c.mesh; c.mu is held.
func (c *Core) putMesh() error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	body := meshBody(c.mesh, meshSections{
		dns: c.client.meshDNS.Load(), hostGroups: c.client.meshHostGroups.Load(), nativeKeys: c.client.meshNativeKeys.Load(),
	})
	if err := c.client.do(ctx, http.MethodPut, "/v1/mesh", body, nil); err != nil {
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

// MeshStatus implements vCore.MeshApplier. An instance id that is not
// 1-64 letters, digits or dashes is left out, as are region requests
// without an id that fits a path segment the same way, and every region
// request of a kernel without meshRegionRequestsFeature.
func (c *Core) MeshStatus(ctx context.Context) (panel.MeshState, error) {
	c.mu.Lock()
	client := c.client
	c.mu.Unlock()
	if client == nil || !client.mesh.Load() {
		return panel.MeshState{}, vCore.ErrMeshUnsupported
	}
	var answer panel.MeshState
	if err := client.do(ctx, http.MethodGet, "/v1/mesh", nil, &answer); err != nil {
		return panel.MeshState{}, fmt.Errorf("anixcore mesh status: %w", err)
	}
	if !panel.MeshInstanceID(answer.InstanceID) {
		answer.InstanceID = ""
	}
	for i := range answer.Networks {
		network := &answer.Networks[i]
		network.ID = strings.TrimPrefix(network.Tag, meshTagPrefix)
		network.Tag = ""
		if !panel.MeshStaticKeyValid(network.StaticKey) {
			network.StaticKey = ""
		}
		// A refused peer goes to the alerts, once, as Control shows it.
		if f := network.Failure; f != nil && f.Code == panel.MeshAlertPeerNotNative && f.Detail != "" {
			alert := panel.MeshAlert{Code: panel.MeshAlertPeerNotNative, Peer: f.Detail}
			if !slices.ContainsFunc(network.Alerts, func(a panel.MeshAlert) bool {
				return a.Code == alert.Code && a.Peer == alert.Peer
			}) {
				network.Alerts = append(network.Alerts, alert)
			}
		}
	}
	keys := answer.StaticKeys[:0]
	for _, key := range answer.StaticKeys {
		if key.Network != "" && panel.MeshStaticKeyValid(key.StaticKey) {
			keys = append(keys, key)
		}
	}
	answer.StaticKeys = keys
	if len(answer.StaticKeys) == 0 {
		answer.StaticKeys = nil
	}
	requests := answer.RegionRequests[:0]
	if client.meshRegionRequests.Load() {
		for _, request := range answer.RegionRequests {
			if panel.MeshInstanceID(request.ID) {
				request.Network = strings.TrimPrefix(request.Network, meshTagPrefix)
				requests = append(requests, request)
			}
		}
	}
	answer.RegionRequests = requests
	if len(answer.RegionRequests) == 0 {
		answer.RegionRequests = nil
	}
	return answer, nil
}

// DoneMeshRegionRequest implements vCore.MeshApplier.
func (c *Core) DoneMeshRegionRequest(ctx context.Context, id string) error {
	c.mu.Lock()
	client := c.client
	c.mu.Unlock()
	if client == nil || !client.meshRegionRequests.Load() {
		return vCore.ErrMeshUnsupported
	}
	if !panel.MeshInstanceID(id) {
		return fmt.Errorf("anixcore mesh: region request id %q is invalid", id)
	}
	err := client.do(ctx, http.MethodDelete, "/v1/mesh/region_requests/"+id, nil, nil)
	if err != nil && !isStatus(err, http.StatusNotFound) {
		return fmt.Errorf("anixcore mesh region request: %w", err)
	}
	return nil
}

// meshSections are the optional parts of a network the kernel takes.
type meshSections struct{ dns, hostGroups, nativeKeys bool }

// meshBody is the PUT /v1/mesh body of networks: each flat network of the
// panel in the kernel's layered configuration, with dns, host_groups, kind
// and native_keys only when the kernel takes them.
func meshBody(networks []panel.MeshNetwork, sections meshSections) map[string]any {
	out := make([]map[string]any, 0, len(networks))
	for _, n := range networks {
		network := map[string]any{"name": n.Name, "secret": n.Secret, "secure_mode": n.SecureMode}
		if n.Cipher != "" {
			network["cipher"] = n.Cipher
		}
		if sections.nativeKeys && n.Kind != "" {
			network["kind"] = n.Kind
		}
		if sections.nativeKeys && present(n.NativeKeys) {
			network["native_keys"] = n.NativeKeys
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
		if sections.dns && present(n.DNS) {
			config["dns"] = n.DNS
		}
		if sections.hostGroups && present(n.HostGroups) {
			config["host_groups"] = n.HostGroups
		}
		out = append(out, config)
	}
	return map[string]any{"networks": out}
}

// present tells whether a section was sent, not empty nor null.
func present(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != "null"
}
