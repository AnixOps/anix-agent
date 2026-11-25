package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	agentapi "github.com/AnixOps/anix-agent/v5/api/agent"
	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	log "github.com/sirupsen/logrus"
)

// controlRoute is a node identity's live route to Control: the region
// relays its connections go through and the release caches its upgrades
// use (anix-control docs/design/region-relay). It starts from the route
// Control last pushed (stored next to the stream state, so a restart keeps
// it even when the configuration file has none) or else from the
// configuration (GRPCRelays, ReleaseCaches), and follows the member
// "control_route" of Control's snapshots:
//
//   - No member keeps the route.
//   - Relays move the node to them: the next connection goes through them,
//     and the current session is ended so that happens at once.
//   - Empty relays never mean "go direct" (the contract with Control): the
//     relays are kept, with a warning; the caches still follow.
//   - Only "direct": true drops the relays.
type controlRoute struct {
	owner      string
	apiConfig  conf.ApiConfig
	target     string
	serverName string
	file       string
	dial       *agentapi.RelaySwitch

	mu     sync.Mutex
	relays []string
	caches []string
	// reconnect ends the client's session (Client.Reconnect); nil before
	// the client exists.
	reconnect func()
}

// storedControlRoute is the file form of a route Control pushed.
type storedControlRoute struct {
	Relays        []string `json:"relays"`
	ReleaseCaches []string `json:"release_caches"`
}

// controlRouteFile is where the route of owner is kept: in the stream
// state directory, which the Agent owns and several node identities may
// share.
func controlRouteFile(apiConfig *conf.ApiConfig, owner string) string {
	return filepath.Join(apiConfig.AgentStream.Dir(), "control-route-"+owner+".json")
}

// newControlRoute answers owner's route, from the stored one or the
// configuration, with its relays registered and its upgrade route set.
func newControlRoute(owner string, apiConfig *conf.ApiConfig, target, serverName string) (*controlRoute, error) {
	route := &controlRoute{
		owner: owner, apiConfig: *apiConfig, target: target, serverName: serverName,
		file:   controlRouteFile(apiConfig, owner),
		relays: slices.Clone(apiConfig.GRPCRelays), caches: slices.Clone(apiConfig.ReleaseCaches),
	}
	if stored, err := loadControlRoute(route.file); err != nil {
		log.WithError(err).WithField("node", owner).Warn("Ignoring the stored region relay route; using the configuration's")
	} else if stored != nil {
		route.relays, route.caches = stored.Relays, stored.ReleaseCaches
		log.WithField("node", owner).WithField("relays", route.relays).Info("Reaching Control by the region relay route Control pushed")
	}
	relays, err := agentControlRelays(owner, route.relays)
	if err != nil && slices.Equal(route.relays, apiConfig.GRPCRelays) {
		return nil, err
	}
	if err != nil {
		// A stored route this Agent cannot use: the configuration's.
		log.WithError(err).WithField("node", owner).Warn("Ignoring the stored region relays; using the configuration's")
		route.relays, route.caches = slices.Clone(apiConfig.GRPCRelays), slices.Clone(apiConfig.ReleaseCaches)
		if relays, err = agentControlRelays(owner, route.relays); err != nil {
			return nil, err
		}
	}
	route.dial = agentapi.NewRelaySwitch(relays)
	route.setUpgradeRoute(relays)
	return route, nil
}

// attach lets the route end client's session when the relays change.
func (r *controlRoute) attach(client *agentapi.Client) {
	if r == nil || client == nil {
		return
	}
	r.mu.Lock()
	r.reconnect = client.Reconnect
	r.mu.Unlock()
}

// setUpgradeRoute hands the upgrader the route's caches and, with relays,
// Control's hosts.
func (r *controlRoute) setUpgradeRoute(relays *agentapi.Relays) {
	if upgrader := agentUpgrader(); upgrader != nil {
		upgrader.SetRoute(r.owner, relayRoute(&r.apiConfig, r.caches, relays, r.target, r.serverName))
	}
}

// apply follows the member "control_route" of snapshot.
func (r *controlRoute) apply(snapshot *agentv1pb.ConfigSnapshot) error {
	if r == nil || snapshot == nil {
		return nil
	}
	pushed, err := panel.ParseControlRoute(snapshot.GetConfigJson())
	if err != nil || pushed == nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	relays := r.relays
	switch {
	case pushed.Direct:
		relays = nil
	case len(nonBlank(pushed.Relays)) > 0:
		relays = nonBlank(pushed.Relays)
	case len(r.relays) > 0:
		log.WithField("node", r.owner).WithField("relays", r.relays).
			Warn("Control sent a region relay route without relays; keeping the current relays (only an explicit direct route reaches Control directly)")
	}
	caches := nonBlank(pushed.ReleaseCaches)
	if slices.Equal(relays, r.relays) && slices.Equal(caches, r.caches) {
		return nil
	}
	shared, err := agentControlRelays(r.owner, relays)
	if err != nil {
		// Keep the relays the node has; the list was registered for nobody.
		if _, restoreErr := agentControlRelays(r.owner, r.relays); restoreErr != nil {
			log.WithError(restoreErr).WithField("node", r.owner).Warn("Could not restore the region relays")
		}
		return fmt.Errorf("%s: %w", panel.ControlRouteMember, err)
	}
	if err := saveControlRoute(r.file, storedControlRoute{Relays: relays, ReleaseCaches: caches}); err != nil {
		// Without the file a restart would fall back to the configuration:
		// still switch now, and say so.
		log.WithError(err).WithField("node", r.owner).Warn("Could not store the region relay route; a restart uses the configuration's")
	}
	moved := !slices.Equal(relays, r.relays)
	r.relays, r.caches = slices.Clone(relays), slices.Clone(caches)
	r.dial.Set(shared)
	r.setUpgradeRoute(shared)
	log.WithField("node", r.owner).WithField("relays", r.relays).WithField("release_caches", r.caches).
		Info("Region relay route changed by Control")
	if moved && r.reconnect != nil {
		// Reconnect through the new route; the session ends after this
		// snapshot is applied.
		r.reconnect()
	}
	return nil
}

// nonBlank answers list without blank entries, trimmed: a list of blanks
// is an empty one, never "direct".
func nonBlank(list []string) []string {
	var kept []string
	for _, entry := range list {
		if entry = strings.TrimSpace(entry); entry != "" {
			kept = append(kept, entry)
		}
	}
	return kept
}

// loadControlRoute reads a stored route; nil without a file.
func loadControlRoute(path string) (*storedControlRoute, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the Agent's own state file.
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var stored storedControlRoute
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &stored, nil
}

// saveControlRoute writes a route atomically (temporary file, rename).
func saveControlRoute(path string, route storedControlRoute) error {
	data, err := json.Marshal(route)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".control-route-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
