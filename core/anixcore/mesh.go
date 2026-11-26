package anixcore

import (
	"context"
	"encoding/json"
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
// them. The sections dns and host_groups go only to a kernel that lists
// meshDNSFeature and meshHostGroupsFeature: the kernel rejects unknown
// fields, and dns.resolver_address goes only to one that also lists
// meshResolverAddressFeature; external_bridge only to one that lists
// meshExternalBridgeFeature. A kernel that lists meshRegionRequestsFeature holds the node
// owner's region requests in the GET answer until
// DELETE /v1/mesh/region_requests/{id}.

// The anixcore features of the mesh.
const (
	meshFeature                = "mesh"
	meshDNSFeature             = "mesh_dns"
	meshResolverAddressFeature = "mesh_resolver_address"
	meshHostGroupsFeature      = "mesh_host_groups"
	meshExternalBridgeFeature  = "mesh_external_bridge"
	meshPathsFeature           = "mesh_paths"
	meshRegionRequestsFeature  = "mesh_region_requests"
	meshNativeKeysFeature      = "mesh_native_keys"
)

// meshTagPrefix starts the kernel tag of a mesh network.
const meshTagPrefix = "mesh-"

var _ vCore.MeshApplier = (*Core)(nil)

// MeshNativeKeysSupported implements vCore.MeshApplier.
func (c *Core) MeshNativeKeysSupported() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.client != nil && c.client.meshNativeKeys.Load()
}

// MeshExternalBridgeSupported implements vCore.MeshApplier.
func (c *Core) MeshExternalBridgeSupported() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.client != nil && c.client.meshExternalBridge.Load()
}

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
		dns: c.client.meshDNS.Load(), dnsResolver: c.client.meshResolverAddress.Load(),
		hostGroups: c.client.meshHostGroups.Load(), externalBridge: c.client.meshExternalBridge.Load(),
		nativeKeys: c.client.meshNativeKeys.Load(), paths: c.client.meshPaths.Load(),
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
// 1-64 letters, digits or dashes is left out, as is a static key that is
// not 32 bytes in standard base64, as are region requests
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
	keys := answer.StaticKeys[:0]
	for _, key := range answer.StaticKeys {
		if key.Network != "" && panel.MeshStaticKeyValid(key.StaticKey) {
			keys = append(keys, key)
		}
	}
	answer.StaticKeys = keys
	if len(keys) == 0 {
		answer.StaticKeys = nil
	}
	for i := range answer.Networks {
		answer.Networks[i].ID = strings.TrimPrefix(answer.Networks[i].Tag, meshTagPrefix)
		answer.Networks[i].Tag = ""
		if len(answer.Networks[i].Paths) == 0 {
			answer.Networks[i].Paths = nil
		}
		// externalBridge has three states, all passed on: a digest, an
		// explicit null (the kernel runs no bridge on this network, so
		// Control may release its addresses), or no key (unknown: never
		// read as no bridge).
		if len(answer.Networks[i].ExternalBridge) == 0 {
			answer.Networks[i].ExternalBridge = nil
		}
	}
	requests := answer.RegionRequests[:0]
	if client.meshRegionRequests.Load() {
		for _, request := range answer.RegionRequests {
			if panel.MeshInstanceID(request.ID) {
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
type meshSections struct {
	dns, dnsResolver, hostGroups, externalBridge, nativeKeys, paths bool
}

// meshBody is the PUT /v1/mesh body of networks: each flat network of the
// panel in the kernel's layered configuration, with dns, host_groups and
// native_keys only when the kernel takes them (dns.resolver_address only
// with mesh_resolver_address). A network the kernel must
// not run (MeshHold: a managed one on a kernel without native_keys, which
// would run it open to any node, or one of an unknown kind) is left out
// here too, so a restarted, older kernel never gets it on replay; the
// key list is dropped only from legacy networks, where it only names the
// members' implementation.
func meshBody(networks []panel.MeshNetwork, take meshSections) map[string]any {
	out := make([]map[string]any, 0, len(networks))
	for _, n := range networks {
		if code, _ := n.MeshHold(take.nativeKeys); code != "" {
			continue
		}
		network := map[string]any{"name": n.Name, "secret": n.Secret, "secure_mode": n.SecureMode}
		if n.Cipher != "" {
			network["cipher"] = n.Cipher
		}
		if n.Kind != "" {
			network["kind"] = n.Kind
		}
		if take.nativeKeys && present(n.NativeKeys) {
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
			config["routing"] = meshRouting(n.Routing, take.paths)
		}
		if take.dns && present(n.DNS) {
			config["dns"] = meshDNS(n.DNS, take.dnsResolver)
		}
		if take.hostGroups && present(n.HostGroups) {
			config["host_groups"] = n.HostGroups
		}
		if take.externalBridge && present(n.ExternalBridge) {
			config["external_bridge"] = n.ExternalBridge
		}
		out = append(out, config)
	}
	return map[string]any{"networks": out}
}

// meshRouting is the routing section for the kernel: without paths (the
// kernel does not list mesh_paths: it takes routing.paths but does not
// apply them) routing.paths is emptied, so no path is taken for applied.
// A section that is not an object, or has no paths, goes as it is.
func meshRouting(routing json.RawMessage, paths bool) json.RawMessage {
	if paths {
		return routing
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(routing, &fields) != nil || fields == nil {
		return routing
	}
	if _, ok := fields["paths"]; !ok {
		return routing
	}
	fields["paths"] = json.RawMessage(`[]`)
	out, err := json.Marshal(fields)
	if err != nil {
		return routing
	}
	return out
}

// meshDNS is the dns section for the kernel: without resolver it drops
// resolver_address, which an older kernel rejects as an unknown field
// (and with it the whole configuration). A section that is not an object
// goes as it is, for the kernel to refuse.
func meshDNS(dns json.RawMessage, resolver bool) json.RawMessage {
	if resolver {
		return dns
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(dns, &fields) != nil || fields == nil {
		return dns
	}
	if _, ok := fields["resolver_address"]; !ok {
		return dns
	}
	delete(fields, "resolver_address")
	out, err := json.Marshal(fields)
	if err != nil {
		return dns
	}
	return out
}

// present tells whether a section was sent, not empty nor null.
func present(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != "null"
}
