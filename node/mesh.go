package node

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v5/api/agent"
	"github.com/AnixOps/anix-agent/v5/api/panel"
	vCore "github.com/AnixOps/anix-agent/v5/core"
	"github.com/AnixOps/anix-agent/v5/mesh"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	log "github.com/sirupsen/logrus"
)

// The intranet mesh (docs/mesh.md): the member "mesh" of the configuration
// lists the networks the kernel joins. While the node's existing mesh
// program the member names still runs, the networks wait for it to be
// taken over (as root, `anix-agent mesh takeover`); the
// kernel's state goes to Control as the PackageReport "mesh.status" after
// each change and every meshStatusInterval, followed by the node owner's
// region requests the kernel holds ("mesh.region_request"). A node in no
// region reports nothing. One node of an Agent drives it: the kernel runs
// one set of networks.

// meshStatusInterval spaces out the status reports.
var meshStatusInterval = time.Minute

// meshComponent runs the mesh member on the kernel.
type meshComponent struct {
	core     vCore.MeshApplier
	takeover *mesh.Takeover

	// runMu serializes run: a snapshot and the retry loop may race.
	runMu      sync.Mutex
	mu         sync.Mutex
	client     *agentapi.Client
	negotiated bool
	// member is the member applied last, nil for none; err why the kernel
	// does not run it.
	member *panel.Mesh
	err    error
	// took is what the takeover found, nil for nothing.
	took *panel.MeshTakeoverResult
	// held are the networks held back from the kernel (MeshHold), by id.
	held map[string]bool
	// bridgedPath records the networks that ran an external bridge on a
	// kernel that takes external_bridge; empty is defaultBridgedPath.
	bridgedPath string
	bridgedMu   sync.Mutex
	// sendReport sends a mesh PackageReport; nil sends it on client's
	// data plane (tests set it).
	sendReport func(*agentv1pb.PackageReport) error

	wake    chan struct{}
	stop    chan struct{}
	stopped chan struct{}
	once    sync.Once
}

// newMeshComponent answers the mesh component of core, nil when no kernel
// of it can run the mesh.
func newMeshComponent(core vCore.Core) *meshComponent {
	applier, ok := core.(vCore.MeshApplier)
	if !ok {
		return nil
	}
	return &meshComponent{
		core: applier, takeover: &mesh.Takeover{},
		wake: make(chan struct{}, 1), stop: make(chan struct{}), stopped: make(chan struct{}),
	}
}

func (c *meshComponent) logger() *log.Entry {
	return log.WithField("component", "agent-mesh")
}

// MeshSession implements agentapi.MeshHandler.
func (c *meshComponent) MeshSession(negotiated bool) {
	c.mu.Lock()
	c.negotiated = negotiated
	c.mu.Unlock()
	if negotiated {
		c.signal()
	}
}

func (c *meshComponent) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *meshComponent) attach(client *agentapi.Client) {
	c.mu.Lock()
	c.client = client
	c.mu.Unlock()
	go c.loop()
}

func (c *meshComponent) close() {
	c.once.Do(func() {
		close(c.stop)
		c.mu.Lock()
		started := c.client != nil
		c.mu.Unlock()
		if started {
			<-c.stopped
		}
	})
}

func (c *meshComponent) loop() {
	defer close(c.stopped)
	ticker := time.NewTicker(meshStatusInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-c.wake:
		case <-ticker.C:
			c.retry()
		}
		c.report()
	}
}

// retry applies the member again once what held it back is gone: an
// updated kernel has the mesh or takes native_keys, or the existing
// program was taken over.
func (c *meshComponent) retry() {
	c.mu.Lock()
	member, err, held := c.member, c.err, c.held
	c.mu.Unlock()
	// A held network waits for an updated kernel: no reapplying the others
	// every minute until one of them may go.
	freed := false
	if member != nil && len(held) > 0 {
		nativeKeys := c.core.MeshNativeKeysSupported()
		for _, network := range member.Networks {
			freed = freed || (held[network.ID] && !holdNow(network, nativeKeys))
		}
	}
	if member != nil && (freed || errors.Is(err, vCore.ErrMeshUnsupported) || errors.Is(err, errTakeoverPending)) {
		_ = c.run(member)
	}
}

// apply runs the snapshot's member "mesh"; a snapshot without it stops the
// networks. A kernel without the mesh fails nothing: the report says so.
func (c *meshComponent) apply(snapshot *agentv1pb.ConfigSnapshot) error {
	if snapshot == nil {
		return nil
	}
	member, err := panel.ParseMesh(snapshot.GetConfigJson())
	if err != nil {
		return agentapi.InvalidConfig(err)
	}
	c.mu.Lock()
	same := reflect.DeepEqual(member, c.member)
	c.mu.Unlock()
	if same {
		return nil
	}
	err = c.run(member)
	c.signal()
	if errors.Is(err, vCore.ErrMeshUnsupported) || errors.Is(err, errTakeoverPending) {
		return nil
	}
	return err
}

// errTakeoverPending holds the networks back while the existing program
// runs: joining its network next to it would put two nodes on one address.
var errTakeoverPending = errors.New("the existing mesh program still runs; take it over with `anix-agent mesh takeover` (as root)")

// run gives the kernel the networks, unless the kernel has no mesh or the
// existing program the member names still runs. A kernel that does not
// take native_keys gets no managed network: it would admit any node.
func (c *meshComponent) run(member *panel.Mesh) error {
	c.runMu.Lock()
	defer c.runMu.Unlock()
	var networks []panel.MeshNetwork
	took := &panel.MeshTakeoverResult{}
	if member != nil {
		networks = member.Networks
		if running := c.takeover.Detect(member.Takeover); len(running) > 0 {
			took = &panel.MeshTakeoverResult{Found: true, Error: errTakeoverPending.Error()}
		}
	}
	took.Stopped = c.takeover.Stopped()
	if !took.Found && len(took.Stopped) > 0 {
		took.Found = true
	}
	var err error
	var held map[string]bool
	switch {
	case len(networks) > 0 && !c.core.MeshSupported():
		err = vCore.ErrMeshUnsupported
	case len(networks) > 0 && took.Error != "":
		err = errTakeoverPending
	default:
		networks, held = c.admissible(networks)
		err = c.core.ApplyMesh(networks)
	}
	if !took.Found {
		took = nil
	}
	c.mu.Lock()
	c.member, c.err, c.took, c.held = member, err, took, held
	c.mu.Unlock()
	if err == nil && len(networks) > 0 {
		c.logger().WithField("networks", len(networks)).Info("Applied the mesh networks")
	}
	return err
}

// admissible splits networks into those the kernel may run and those
// it may not (MeshHold), by id.
func (c *meshComponent) admissible(networks []panel.MeshNetwork) ([]panel.MeshNetwork, map[string]bool) {
	nativeKeys := c.core.MeshNativeKeysSupported()
	var run []panel.MeshNetwork
	held := map[string]bool{}
	for _, network := range networks {
		if code, detail := network.MeshHold(nativeKeys); code != "" {
			held[network.ID] = true
			c.logger().WithField("network", network.ID).WithField("reason", code).Warn("Held back a mesh network: " + detail)
			continue
		}
		run = append(run, network)
	}
	if len(held) == 0 {
		return networks, nil
	}
	return run, held
}

// status is the report payload now and the region requests the kernel
// holds. ok is false while the node is in no region (no member, or one
// without networks): Control refuses that node's reports (not_assigned),
// so none go, and the kernel keeps its region requests.
func (c *meshComponent) status(ctx context.Context) (status panel.MeshStatus, requests []panel.MeshRegionRequest, ok bool) {
	c.mu.Lock()
	member, applyErr, took, held := c.member, c.err, c.took, c.held
	c.mu.Unlock()
	status = panel.MeshStatus{Networks: []panel.MeshNetworkStatus{}, Takeover: took}
	if member == nil || len(member.Networks) == 0 {
		return status, nil, false
	}
	// A kernel with the mesh answers its instance id and region requests
	// even while the networks wait for the takeover.
	var state panel.MeshState
	var readErr error
	if c.core.MeshSupported() {
		state, readErr = c.core.MeshStatus(ctx)
	} else if applyErr == nil {
		readErr = vCore.ErrMeshUnsupported
	}
	status.InstanceID = state.InstanceID
	nativeKeys := c.core.MeshNativeKeysSupported()
	// residue: networks that ran a bridge on a kernel that took
	// external_bridge, now read on one that does not (a downgrade). The
	// newer kernel clears its rules when it exits; the older one does not
	// know them (docs/protocols/intranet-mesh.md §15.12 item 9).
	var residue map[string]bool
	if readErr == nil && c.core.MeshSupported() {
		residue = c.trackBridges(member.Networks, state.Networks, c.core.MeshExternalBridgeSupported())
	}
	// bridge: the kernel was given the networks and does not take
	// external_bridge.
	bridge := applyErr == nil && c.core.MeshSupported() && !c.core.MeshExternalBridgeSupported()
	// noBridge: the kernel, read just now, does not take external_bridge,
	// so no bridge runs in any of its networks. Each network then reports
	// an explicit null, whether or not Control sent a bridge: Control
	// releases what it held for a bridge deleted since, which the alert
	// alone (sent only while a bridge is configured) never lets it do.
	noBridge := readErr == nil && c.core.MeshSupported() && !c.core.MeshExternalBridgeSupported()
	var running map[string]panel.MeshNetworkStatus
	if applyErr == nil {
		applyErr = readErr
		running = make(map[string]panel.MeshNetworkStatus, len(state.Networks))
		for _, network := range state.Networks {
			running[network.ID] = network
		}
	}
	// The static keys come by network name: the node's key in each
	// network, read even while the networks wait, for Control's
	// native_keys.
	keys := make(map[string]string, len(state.StaticKeys))
	for _, key := range state.StaticKeys {
		keys[key.Network] = key.StaticKey
	}
	for _, network := range member.Networks {
		entry, found := running[network.ID]
		if !found {
			entry = panel.MeshNetworkStatus{ID: network.ID, Peers: []panel.MeshPeerStatus{}}
			switch {
			case applyErr == nil && held[network.ID]:
				code, detail := network.MeshHold(false)
				entry.Alerts = []panel.MeshAlert{{Code: code, Detail: detail}}
			case applyErr == nil && holdNow(network, nativeKeys):
				// Given while the kernel took native_keys; a restarted,
				// older kernel does not get it again (meshBody).
				code, detail := network.MeshHold(nativeKeys)
				entry.Alerts = []panel.MeshAlert{{Code: code, Detail: detail}}
			case errors.Is(applyErr, vCore.ErrMeshUnsupported):
				entry.Alerts = []panel.MeshAlert{{Code: panel.MeshAlertUnsupported, Detail: applyErr.Error()}}
			case errors.Is(applyErr, errTakeoverPending):
				entry.Alerts = []panel.MeshAlert{{Code: panel.MeshAlertTakeoverPending, Detail: applyErr.Error()}}
			case applyErr != nil:
				entry.Error = applyErr.Error()
			default:
				entry.Error = "the kernel does not run this network"
			}
		}
		if entry.Peers == nil {
			entry.Peers = []panel.MeshPeerStatus{}
		}
		// Why the kernel holds the network (native_keys_pending, ...)
		// goes as an alert.
		if failure := entry.Failure; failure != nil {
			entry.Failure = nil
			if failure.Code != "" && !hasAlert(entry.Alerts, failure.Code) {
				entry.Alerts = append(entry.Alerts, panel.MeshAlert{Code: failure.Code, Detail: failure.Detail})
			}
		}
		// The kernel runs the network without the bridge it does not take.
		if bridge && meshSent(network.ExternalBridge) && !held[network.ID] && !holdNow(network, nativeKeys) && !hasAlert(entry.Alerts, panel.MeshAlertExternalBridgeUnsupported) {
			entry.Alerts = append(entry.Alerts, panel.MeshAlert{
				Code:   panel.MeshAlertExternalBridgeUnsupported,
				Detail: "the kernel does not take external_bridge, so it runs this network without the bridge; update it",
			})
		}
		if residue[network.ID] && !hasAlert(entry.Alerts, panel.MeshAlertExternalBridgeDowngradeResidue) {
			entry.Alerts = append(entry.Alerts, panel.MeshAlert{
				Code: panel.MeshAlertExternalBridgeDowngradeResidue,
				Detail: "this node bridged the network on a kernel that takes external_bridge; the kernel now running does not, " +
					"so bridge rules left by the newer kernel stay in place: clear them, or let the newer kernel exit cleanly before downgrading, " +
					"then remove " + c.bridgedFile(),
			})
		}
		if noBridge && entry.ExternalBridge == nil {
			entry.ExternalBridge = json.RawMessage("null")
		}
		entry.StaticKey = keys[network.Name]
		status.Networks = append(status.Networks, entry)
	}
	return status, state.RegionRequests, true
}

// report sends the status, then the kernel's region requests, on a
// session that negotiated the mesh.
func (c *meshComponent) report() {
	c.mu.Lock()
	send, negotiated := c.sendReport, c.negotiated
	if client := c.client; send == nil && client != nil {
		send = client.DataPlane().SendMeshReport
	}
	c.mu.Unlock()
	if send == nil || !negotiated {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	status, requests, ok := c.status(ctx)
	cancel()
	if !ok {
		return
	}
	payload, err := json.Marshal(status)
	if err != nil {
		c.logger().WithError(err).Warn("Could not build the mesh status")
		return
	}
	if err := c.send(send, agentapi.MeshStatusKind, agentapi.MeshStatusVersion, payload); err != nil {
		if !errors.Is(err, agentapi.ErrSessionGone) {
			c.logger().WithError(err).Warn("Could not send the mesh status")
		}
		return
	}
	for _, request := range requests {
		if !c.sendRegionRequest(send, request) {
			return
		}
	}
}

// sendRegionRequest sends one region request the kernel holds and then
// drops it from the kernel; it answers false when the session is gone.
// Control never acknowledges it: it records the request for the network
// manager, and the decision comes back as the configuration. A request
// Control can never take (no region code) is dropped unsent; one that
// could not be sent stays in the kernel for the next report.
func (c *meshComponent) sendRegionRequest(send func(*agentv1pb.PackageReport) error, request panel.MeshRegionRequest) bool {
	logger := c.logger().WithField("region_request", request.ID)
	report, err := request.Report()
	if err == nil {
		var payload []byte
		if payload, err = json.Marshal(report); err == nil {
			err = c.send(send, agentapi.MeshRegionRequestKind, agentapi.MeshRegionRequestVersion, payload)
			if errors.Is(err, agentapi.ErrSessionGone) {
				return false
			}
			if err != nil {
				logger.WithError(err).Warn("Could not send the mesh region request")
				return true
			}
			logger.WithField("region", report.Region).Info("Sent the mesh region request to Control")
		}
	}
	if err != nil {
		logger.WithError(err).Warn("Dropped a mesh region request Control cannot take")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := c.core.DoneMeshRegionRequest(ctx, request.ID); err != nil {
		logger.WithError(err).Warn("Could not drop the sent mesh region request from the kernel")
	}
	return true
}

// send sends one mesh PackageReport.
func (c *meshComponent) send(send func(*agentv1pb.PackageReport) error, kind, version string, payload []byte) error {
	return send(&agentv1pb.PackageReport{
		PluginId: agentapi.MeshPluginID, Kind: kind, Version: version,
		PayloadJson: payload, ObservedAtUnixMs: time.Now().UnixMilli(),
	})
}

// hasAlert tells whether alerts has one of code.
func hasAlert(alerts []panel.MeshAlert, code string) bool {
	for _, alert := range alerts {
		if alert.Code == code {
			return true
		}
	}
	return false
}

// holdNow tells whether the kernel as it runs now may not run network.
func holdNow(network panel.MeshNetwork, nativeKeys bool) bool {
	code, _ := network.MeshHold(nativeKeys)
	return code != ""
}

// defaultBridgedPath records the bridged networks, next to the takeover's
// record.
func defaultBridgedPath() string {
	return filepath.Join(filepath.Dir(mesh.DefaultStatePath), "bridged.json")
}

func (c *meshComponent) bridgedFile() string {
	if c.bridgedPath != "" {
		return c.bridgedPath
	}
	return defaultBridgedPath()
}

// bridgedRecord is the file bridgedFile holds.
type bridgedRecord struct {
	Networks []string `json:"networks"`
}

// trackBridges keeps the record of the networks that run an external
// bridge on a kernel that takes external_bridge, read just now: capable
// tells whether it does. On such a kernel the record becomes the networks
// configured or reported with a bridge (the kernel removes the rules of a
// bridge deleted since) and nothing is answered. On a kernel without it
// the record stays as it was, so it outlives an Agent restarted with the
// older kernel, and is answered: those networks may keep the newer
// kernel's rules. The record is cleared once a capable kernel runs again,
// or when the operator removes the file.
func (c *meshComponent) trackBridges(networks []panel.MeshNetwork, running []panel.MeshNetworkStatus, capable bool) map[string]bool {
	path := c.bridgedFile()
	// The file is read each time, so removing it takes effect at once.
	c.bridgedMu.Lock()
	defer c.bridgedMu.Unlock()
	recorded := readBridged(path)
	if !capable {
		return recorded
	}
	now := map[string]bool{}
	for _, network := range networks {
		if meshSent(network.ExternalBridge) {
			now[network.ID] = true
		}
	}
	for _, network := range running {
		if meshSent(network.ExternalBridge) {
			now[network.ID] = true
		}
	}
	if !reflect.DeepEqual(now, recorded) {
		if err := writeBridged(path, now); err != nil {
			log.WithField("component", "agent-mesh").WithError(err).Warn("cannot record the bridged networks")
		}
	}
	return nil
}

// readBridged reads the record at path; missing or unreadable is empty.
func readBridged(path string) map[string]bool {
	out := map[string]bool{}
	data, err := os.ReadFile(path) // #nosec G304 -- the Agent's own state file.
	if err != nil {
		return out
	}
	var record bridgedRecord
	if json.Unmarshal(data, &record) != nil {
		return out
	}
	for _, id := range record.Networks {
		out[id] = true
	}
	return out
}

// writeBridged writes the record, removing the file when it is empty.
func writeBridged(path string, bridged map[string]bool) error {
	if len(bridged) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	record := bridgedRecord{Networks: make([]string, 0, len(bridged))}
	for id := range bridged {
		record.Networks = append(record.Networks, id)
	}
	sort.Strings(record.Networks)
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301 -- the Agent reads it.
		return err
	}
	return os.WriteFile(path, data, 0o644) // #nosec G306 -- network ids only, no secret.
}

// meshSent tells whether the panel sent a section, not empty nor null.
func meshSent(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != "null"
}
