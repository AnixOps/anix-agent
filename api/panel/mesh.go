package panel

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// Mesh is the member "mesh" of a configuration document (anix-control
// docs/design/mesh-regions/agent-contract.md): the intranet mesh networks
// the node joins, one per region, and the existing mesh program the Agent
// takes over before joining (requirement R12). A document without the
// member runs no mesh.
type Mesh struct {
	Networks []MeshNetwork `json:"networks"`
	// Takeover is deployment data the panel keeps; nil for none.
	Takeover *MeshTakeover `json:"takeover,omitempty"`
}

// MeshNetwork is one network of the member, flat: without ID it is the
// core's mesh configuration (config_version 1) with the network and node
// layers inlined. The Agent passes the nested parts through; the core
// validates them.
type MeshNetwork struct {
	// ID is the region code (cn, apac, eu, na, ...).
	ID         string `json:"id"`
	Name       string `json:"name"`
	Secret     string `json:"secret"`
	SecureMode bool   `json:"secure_mode"`
	Cipher     string `json:"cipher,omitempty"`
	// Kind (managed or legacy) and NativeKeys, the static keys of the
	// operator's own nodes in this network, belong to the kernel's network
	// layer; a managed network needs NativeKeys.
	Kind       string          `json:"kind,omitempty"`
	NativeKeys json.RawMessage `json:"native_keys,omitempty"`
	Address    string          `json:"address"`
	AddressV6  string          `json:"address_v6,omitempty"`
	Role       string          `json:"role,omitempty"`
	Listen     json.RawMessage `json:"listen,omitempty"`
	Peers      json.RawMessage `json:"peers,omitempty"`
	Subnets    json.RawMessage `json:"subnets,omitempty"`
	Routing    json.RawMessage `json:"routing,omitempty"`
	// DNS is the network's intranet names (enabled, suffix, names) and
	// HostGroups its host groups (cidr, gateway, backup_gateway, the
	// gateways by instance id). Control always sends both; the Agent
	// passes each only to a kernel that takes it (its kernel rejects
	// unknown fields), so an older kernel runs the network without them.
	DNS        json.RawMessage `json:"dns,omitempty"`
	HostGroups json.RawMessage `json:"host_groups,omitempty"`
}

// MeshTakeover names the existing mesh program on the node: its system
// services, process names and configuration files. The names are data
// from the panel, never part of the Agent.
type MeshTakeover struct {
	ProcessNames []string `json:"process_names,omitempty"`
	ServiceNames []string `json:"service_names,omitempty"`
	ConfigPaths  []string `json:"config_paths,omitempty"`
}

// Empty tells whether the takeover names nothing.
func (t *MeshTakeover) Empty() bool {
	return t == nil || len(t.ProcessNames)+len(t.ServiceNames)+len(t.ConfigPaths) == 0
}

// ParseMesh reads the member "mesh" of a configuration document; nil when
// the document has none.
func ParseMesh(document []byte) (*Mesh, error) {
	var holder struct {
		Mesh *Mesh `json:"mesh"`
	}
	if err := json.Unmarshal(document, &holder); err != nil {
		return nil, fmt.Errorf("decode the mesh member: %w", err)
	}
	if holder.Mesh == nil {
		return nil, nil
	}
	if err := holder.Mesh.Validate(); err != nil {
		return nil, fmt.Errorf("mesh: %w", err)
	}
	return holder.Mesh, nil
}

// Validate checks what the Agent itself uses: the ids (they name the
// core's networks) and the takeover names (they reach systemctl and
// /proc). The core checks the rest.
func (m *Mesh) Validate() error {
	ids := map[string]bool{}
	for _, network := range m.Networks {
		if !meshID(network.ID) || ids[network.ID] {
			return fmt.Errorf("network id %q is invalid or repeated", network.ID)
		}
		ids[network.ID] = true
		if network.Name == "" || network.Secret == "" || network.Address == "" {
			return fmt.Errorf("network %s: name, secret and address are required", network.ID)
		}
	}
	if m.Takeover == nil {
		return nil
	}
	for _, name := range append(append([]string(nil), m.Takeover.ProcessNames...), m.Takeover.ServiceNames...) {
		if name == "" || strings.HasPrefix(name, "-") || strings.ContainsAny(name, "/\x00") || len(name) > 255 {
			return fmt.Errorf("takeover: invalid name %q", name)
		}
	}
	for _, path := range m.Takeover.ConfigPaths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("takeover: config path %q is not a clean absolute path", path)
		}
	}
	return nil
}

// meshID tells whether id is 1-32 lowercase letters, digits or dashes.
func meshID(id string) bool {
	if id == "" || len(id) > 32 {
		return false
	}
	for _, r := range id {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// MeshStatus is the payload of the PackageReport plugin_id "mesh", kind
// "mesh.status", version "v1".
type MeshStatus struct {
	// InstanceID is the kernel's mesh instance id (self.id of its mesh
	// status), empty until the kernel answers a valid one. Control names
	// host group gateways by it.
	InstanceID string              `json:"instance_id,omitempty"`
	Networks   []MeshNetworkStatus `json:"networks"`
	Takeover   *MeshTakeoverResult `json:"takeover,omitempty"`
}

// MeshNetworkStatus is one network as the core runs it. The core answers
// it with Tag; the report carries ID.
type MeshNetworkStatus struct {
	ID                     string           `json:"id,omitempty"`
	Tag                    string           `json:"tag,omitempty"`
	Running                bool             `json:"running"`
	Error                  string           `json:"error,omitempty"`
	Address                string           `json:"address,omitempty"`
	ForwardSecrecy         bool             `json:"forward_secrecy"`
	Peers                  []MeshPeerStatus `json:"peers"`
	RejectedAdvertisements int              `json:"rejected_advertisements"`
	// StaticKey is this node's static public key in the network (the
	// kernel's static_keys), from which Control builds native_keys;
	// empty for a network without one.
	StaticKey string      `json:"static_key,omitempty"`
	Overlaps  []string    `json:"overlaps,omitempty"`
	Alerts    []MeshAlert `json:"alerts,omitempty"`
}

// MeshPeerStatus is one peer of a network.
type MeshPeerStatus struct {
	Address        string   `json:"address"`
	Subnets        []string `json:"subnets,omitempty"`
	Via            []string `json:"via,omitempty"`
	Hops           int      `json:"hops"`
	LatencyMs      int      `json:"latency_ms"`
	ForwardSecrecy bool     `json:"forward_secrecy"`
}

// Mesh alert codes. The core raises the address ones (requirement R29)
// and start_refused (R12); the Agent raises unsupported and
// takeover_pending.
const (
	MeshAlertTakeoverPending  = "takeover_pending"
	MeshAlertAddressConflict  = "address_conflict"
	MeshAlertAddressUnmanaged = "address_unmanaged"
	MeshAlertUnsupported      = "unsupported"
	MeshAlertStartRefused     = "start_refused"
)

// MeshAlert is one alert of a network.
type MeshAlert struct {
	Code    string `json:"code"`
	Address string `json:"address,omitempty"`
	Peer    string `json:"peer,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// MeshTakeoverResult says what the takeover found and stopped.
type MeshTakeoverResult struct {
	Found   bool     `json:"found"`
	Stopped []string `json:"stopped,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// MeshState is what the kernel answers on GET /v1/mesh: its instance id,
// the networks it runs, and the region requests the node owner made on the
// node (the kernel command mesh_request_region) that wait to go to
// Control.
type MeshState struct {
	InstanceID string `json:"instance_id,omitempty"`
	// StaticKeys are the node's static public keys, one per secure-mode
	// network, by the network's name.
	StaticKeys     []MeshStaticKey     `json:"static_keys,omitempty"`
	Networks       []MeshNetworkStatus `json:"networks"`
	RegionRequests []MeshRegionRequest `json:"region_requests,omitempty"`
}

// MeshInstanceID tells whether id is a valid instance id: 1-64 letters,
// digits or dashes, starting with a letter or digit (so it never reads as
// a command-line option).
func MeshInstanceID(id string) bool {
	if id == "" || len(id) > 64 || id[0] == '-' {
		return false
	}
	for _, r := range id {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// MeshRegionRequest is one region request the kernel holds: ID names it to
// the kernel, Network is the kernel tag of the network it was made on.
type MeshRegionRequest struct {
	ID      string `json:"id"`
	Network string `json:"network,omitempty"`
	Region  string `json:"region"`
	Reason  string `json:"reason,omitempty"`
}

// MeshRegionRequestReasonMax bounds the reason, in characters.
const MeshRegionRequestReasonMax = 500

// MeshRegionRequestReport is the payload of the PackageReport plugin_id
// "mesh", kind "mesh.region_request", version "v1".
type MeshRegionRequestReport struct {
	Region string `json:"region"`
	Reason string `json:"reason,omitempty"`
}

// Report is the request as Control takes it: the region must be a region
// code; a longer reason is cut to MeshRegionRequestReasonMax characters.
func (r MeshRegionRequest) Report() (MeshRegionRequestReport, error) {
	if !meshID(r.Region) {
		return MeshRegionRequestReport{}, fmt.Errorf("region %q is not a region code", r.Region)
	}
	reason := strings.TrimSpace(strings.ToValidUTF8(r.Reason, ""))
	if runes := []rune(reason); len(runes) > MeshRegionRequestReasonMax {
		reason = string(runes[:MeshRegionRequestReasonMax])
	}
	return MeshRegionRequestReport{Region: r.Region, Reason: reason}, nil
}

// MeshStaticKey is the node's static public key in one network: Network
// is the network's name (network.name), StaticKey the 32-byte X25519 key
// in standard base64 with padding.
type MeshStaticKey struct {
	Network   string `json:"network"`
	StaticKey string `json:"static_key"`
}

// MeshStaticKeyValid tells whether key is a 32-byte key in standard base64
// with padding (44 characters).
func MeshStaticKeyValid(key string) bool {
	if len(key) != 44 {
		return false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(key)
	return err == nil && len(raw) == 32
}
