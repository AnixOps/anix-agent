package node

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

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
//
// New relays are taken only once a TLS handshake with Control (its
// certificate verified for the server name) completes through one of
// them, so a list Control can parse but the relays cannot carry never cuts
// the node off; a list that fails is retried after routeRetry. A stored
// route is kept only while the configuration's own route is the one it
// was stored against: an edited configuration, or the installer run
// again, wins.
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
	// checking is the relay list being verified, "" when none; failed
	// holds when each list that failed its check may be tried again.
	checking string
	failed   map[string]time.Time
}

// storedControlRoute is the file form of a route Control pushed, with the
// configuration's route it replaced (ConfigRelays, ConfigCaches).
type storedControlRoute struct {
	Relays        []string `json:"relays"`
	ReleaseCaches []string `json:"release_caches"`
	ConfigRelays  []string `json:"config_relays"`
	ConfigCaches  []string `json:"config_release_caches"`
	// Direct records Control's explicit "direct": true; without it a
	// stored route with no relays is not valid (never read as direct).
	Direct bool `json:"direct,omitempty"`
}

// routeRetry is how long a relay list that failed its check is not
// checked again.
const routeRetry = 10 * time.Minute

// routeCheckTimeout bounds the check of one relay list.
const routeCheckTimeout = 30 * time.Second

// routeCheck verifies that a relay list carries Control: a TLS handshake
// with target, verified for serverName, through at least one relay (a
// variable for tests).
var routeCheck = checkRouteRelays

// routeAsync runs a route check off the snapshot's path (a variable for
// tests, which run it inline).
var routeAsync = func(check func()) { go check() }

// checkRouteRelays dials each relay in turn and completes a TLS handshake
// with Control through it; the first that succeeds is enough. A relay
// sends the node's bytes to Control only, so this is the handshake the
// stream would make, without a client certificate.
func checkRouteRelays(ctx context.Context, relays []string, serverName string) error {
	var errs []error
	for _, relay := range relays {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		conn, err := dialer.DialContext(ctx, "tcp", relay)
		if err != nil {
			errs = append(errs, fmt.Errorf("relay %s: %w", relay, err))
			continue
		}
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: serverName, RootCAs: agentControlRootCAs, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"},
		})
		handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = tlsConn.HandshakeContext(handshakeCtx)
		cancel()
		_ = tlsConn.Close()
		if err == nil {
			return nil
		}
		errs = append(errs, fmt.Errorf("relay %s: TLS with %s: %w", relay, serverName, err))
	}
	return errors.Join(errs...)
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
	stored, err := loadControlRoute(route.file)
	switch {
	case err != nil && len(nonBlank(apiConfig.GRPCRelays)) == 0:
		// The stored route may be all that keeps the node off a direct
		// path to Control (R34): stop rather than go direct.
		return nil, fmt.Errorf("the stored region relay route %s cannot be used (%w); the configuration has no GRPCRelays, so the node does not reach Control directly instead. Run the node group's install command again: it writes the group's relays and replaces the stored route", route.file, err)
	case err != nil:
		log.WithError(err).WithField("node", owner).Warn("Ignoring the stored region relay route; using the configuration's relays")
	case stored != nil && (!slices.Equal(stored.ConfigRelays, nonBlank(apiConfig.GRPCRelays)) || !slices.Equal(stored.ConfigCaches, nonBlank(apiConfig.ReleaseCaches))):
		// The configuration changed since Control's route was stored (an
		// edit, the installer run again): it wins.
		log.WithField("node", owner).WithField("relays", apiConfig.GRPCRelays).
			Info("The configuration's region relays changed since Control's route was stored; using the configuration's")
		if removeErr := os.Remove(route.file); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			log.WithError(removeErr).WithField("node", owner).Warn("Could not remove the stored region relay route")
		}
	case stored != nil:
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
	check, err := r.decide(pushed)
	if check != nil {
		// Outside mu: the check takes it to switch.
		routeAsync(check)
	}
	return err
}

// decide applies what of pushed needs no check and answers the check of
// new relays, nil when there is none to run.
func (r *controlRoute) decide(pushed *panel.ControlRoute) (func(), error) {
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
		return nil, nil
	}
	if slices.Equal(relays, r.relays) || relays == nil {
		// Only the caches change, or Control asks for direct: nothing to
		// verify through relays.
		return nil, r.switchLocked(relays, caches)
	}
	if _, err := agentapi.NewRelays(relays); err != nil {
		return nil, fmt.Errorf("%s: %w", panel.ControlRouteMember, err)
	}
	key := strings.Join(relays, ",")
	if r.checking == key {
		return nil, nil
	}
	if until, ok := r.failed[key]; ok && time.Now().Before(until) {
		return nil, nil
	}
	r.checking = key
	return func() { r.verify(relays, caches, key) }, nil
}

// verify checks relays and switches to them, or keeps the current route.
func (r *controlRoute) verify(relays, caches []string, key string) {
	ctx, cancel := context.WithTimeout(context.Background(), routeCheckTimeout)
	err := routeCheck(ctx, relays, r.serverName)
	cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.checking == key {
		r.checking = ""
	}
	if err != nil {
		if r.failed == nil {
			r.failed = map[string]time.Time{}
		}
		r.failed[key] = time.Now().Add(routeRetry)
		log.WithError(err).WithField("node", r.owner).WithField("relays", relays).
			Warn("Control's region relays do not carry Control from here; keeping the current route")
		return
	}
	delete(r.failed, key)
	if err := r.switchLocked(relays, caches); err != nil {
		log.WithError(err).WithField("node", r.owner).Warn("Could not switch the region relay route")
	}
}

// switchLocked moves the route to relays and caches; the caller holds mu.
func (r *controlRoute) switchLocked(relays, caches []string) error {
	shared, err := agentControlRelays(r.owner, relays)
	if err != nil {
		// Keep the relays the node has; the list was registered for nobody.
		if _, restoreErr := agentControlRelays(r.owner, r.relays); restoreErr != nil {
			log.WithError(restoreErr).WithField("node", r.owner).Warn("Could not restore the region relays")
		}
		return fmt.Errorf("%s: %w", panel.ControlRouteMember, err)
	}
	stored := storedControlRoute{
		Relays: relays, ReleaseCaches: caches, Direct: len(relays) == 0,
		ConfigRelays: nonBlank(r.apiConfig.GRPCRelays), ConfigCaches: nonBlank(r.apiConfig.ReleaseCaches),
	}
	if err := saveControlRoute(r.file, stored); err != nil {
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
		// Reconnect through the new route; the session ends once the
		// current snapshot is applied.
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
	// Only an explicit direct route may lack relays: an empty file body,
	// {} or null is damage, never "reach Control directly" (R34).
	if !stored.Direct {
		if len(nonBlank(stored.Relays)) == 0 {
			return nil, fmt.Errorf("%s holds no relays", path)
		}
		if _, err := agentapi.NewRelays(stored.Relays); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
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
