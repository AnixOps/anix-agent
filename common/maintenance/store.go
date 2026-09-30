package maintenance

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/gofrs/flock"
)

const FailureDuration = 2 * time.Minute
const RecoveryDuration = 5 * time.Minute
const RestartWindow = 30 * time.Minute
const RestartLimit = 2
const maxQueueEvents = 100000
const maxStateBytes = 256 << 20

type Store struct {
	mu           sync.Mutex
	path         string
	lock         *flock.Flock
	nodeID       string
	environment  string
	agentVersion string
	// write is injectable only within this package for disk-failure tests.
	write func([]byte) error
}
type diskState struct {
	NextSequence uint64                   `json:"next_sequence"`
	Order        map[string]uint64        `json:"order"`
	Version      string                   `json:"version"`
	NodeID       string                   `json:"node_id"`
	Environment  string                   `json:"environment"`
	Events       map[string]Event         `json:"events"`
	Instances    map[string]instanceState `json:"instances"`
}
type instanceState struct {
	FailureStreakAt     *time.Time  `json:"failure_streak_at,omitempty"`
	FirstFailedAt       *time.Time  `json:"first_failed_at,omitempty"`
	LastObservedAt      time.Time   `json:"last_observed_at"`
	ConsecutiveFailures int         `json:"consecutive_failures"`
	HealthySince        *time.Time  `json:"healthy_since,omitempty"`
	Open                bool        `json:"open"`
	ErrorCode           string      `json:"error_code"`
	RestartTimes        []time.Time `json:"restart_times,omitempty"`
}

type Observation struct {
	PluginID       string
	InstanceID     string
	PluginVersion  string
	ConfigVersion  string
	ErrorCode      string // Empty means a successful real health check.
	RestartAllowed bool
}
type Decision struct{ Restart bool }

// Open creates a node-scoped durable queue. Every transaction locks and reloads
// disk state, so independent readers/writers cannot reset the restart budget.
func Open(path, nodeID, environment, agentVersion string) (*Store, error) {
	at := time.Now()
	probe := Event{FirstFailedAt: &at, ConsecutiveFailures: 1, SchemaVersion: 1, PluginID: "validation", InstanceID: "validation", PluginVersion: "1", EventID: "validation", OccurredAt: at, Environment: environment, Source: "agent", NodeID: nodeID, AgentVersion: agentVersion, ErrorCode: "HEALTH_CHECK_FAILED", Severity: "P2", Status: "open"}
	if err := probe.Validate(); err != nil {
		return nil, err
	}
	if path == "" {
		return nil, errors.New("maintenance state path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	s := &Store{path: path, nodeID: nodeID, environment: environment, agentVersion: agentVersion, lock: flock.New(path + ".lock")}
	s.write = func(data []byte) error { return atomicWrite(path, data) }
	if err := s.transaction(func(state *diskState) error {
		for id, instance := range state.Instances {
			instance.HealthySince = nil
			state.Instances[id] = instance
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) transaction(change func(*diskState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.lock.Lock(); err != nil {
		return err
	}
	defer s.lock.Unlock()
	state := diskState{Version: Version, NodeID: s.nodeID, Environment: s.environment, Events: map[string]Event{}, Instances: map[string]instanceState{}}
	info, err := os.Lstat(s.path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Size() > maxStateBytes {
			return errors.New("maintenance state is not a bounded regular file")
		}
		file, err := os.Open(s.path)
		if err != nil {
			return err
		}
		decoder := json.NewDecoder(io.LimitReader(file, maxStateBytes))
		decoder.DisallowUnknownFields()
		var loaded diskState
		err = decoder.Decode(&loaded)
		state = loaded
		if err == nil && decoder.Decode(&struct{}{}) != io.EOF {
			err = errors.New("maintenance state contains trailing values")
		}
		file.Close()
		if err != nil {
			return fmt.Errorf("read maintenance state: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if state.Version != Version || state.NodeID != s.nodeID || state.Environment != s.environment || state.Events == nil || state.Instances == nil {
		return errors.New("maintenance state identity or version mismatch")
	}
	if state.Order == nil {
		state.Order = map[string]uint64{}
	}
	if err := change(&state); err != nil {
		return err
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(encoded) > maxStateBytes {
		return errors.New("maintenance state capacity exceeded")
	}
	return s.write(encoded)
}
func atomicWrite(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".maintenance-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(temporary, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func newEventID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}
func (s *Store) append(state *diskState, e Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if e.NodeID != s.nodeID {
		return errors.New("maintenance event node does not match store")
	}
	if existing, ok := state.Events[e.EventID]; ok {
		a, _ := json.Marshal(existing)
		b, _ := json.Marshal(e)
		if string(a) != string(b) {
			return errors.New("maintenance event ID collision")
		}
		return nil
	}
	if len(state.Events) >= maxQueueEvents {
		return errors.New("maintenance outbox is full; event not accepted")
	}
	state.NextSequence++
	state.Order[e.EventID] = state.NextSequence
	state.Events[e.EventID] = e
	return nil
}
func (s *Store) Queue(e Event) error {
	return s.transaction(func(state *diskState) error { return s.append(state, e) })
}
func (s *Store) Pending(limit int) ([]Event, error) {
	if limit <= 0 || limit > MaxBatchSize {
		limit = MaxBatchSize
	}
	var events []Event
	order := map[string]uint64{}
	err := s.transaction(func(state *diskState) error {
		for _, e := range state.Events {
			order[e.EventID] = state.Order[e.EventID]
			events = append(events, e)
		}
		return nil
	})
	sort.Slice(events, func(i, j int) bool {
		if events[i].OccurredAt.Equal(events[j].OccurredAt) {
			if order[events[i].EventID] != order[events[j].EventID] {
				return order[events[i].EventID] < order[events[j].EventID]
			}
			return events[i].EventID < events[j].EventID
		}
		return events[i].OccurredAt.Before(events[j].OccurredAt)
	})
	if len(events) > limit {
		events = events[:limit]
	}
	return events, err
}

// Acknowledge removes only explicitly durable acknowledgments. Message-level ACKs,
// rejects, absent results and a failed local commit leave the queue intact.
func (s *Store) Acknowledge(ack Acknowledgment) error {
	if ack.Version != Version || len(ack.Events) > MaxBatchSize {
		return errors.New("invalid maintenance acknowledgment")
	}
	for _, result := range ack.Events {
		if !identityPattern.MatchString(result.EventID) {
			return errors.New("invalid maintenance acknowledgment event_id")
		}
	}
	return s.transaction(func(state *diskState) error {
		for _, result := range ack.Events {
			if result.Persisted {
				delete(state.Events, result.EventID)
				delete(state.Order, result.EventID)
			}
		}
		return nil
	})
}
func (s *Store) Observe(observation Observation, now time.Time) (Decision, error) {
	decision := Decision{}
	if observation.InstanceID == "" {
		observation.InstanceID = observation.PluginID
	}
	if !identityPattern.MatchString(observation.PluginID) || !identityPattern.MatchString(observation.InstanceID) {
		return decision, errors.New("invalid plugin instance")
	}
	err := s.transaction(func(state *diskState) error {
		instance := state.Instances[observation.InstanceID]
		if now.Before(instance.LastObservedAt) {
			return errors.New("maintenance observation clock moved backwards")
		}
		// Multiple monitors or exit + probe at the same instant do not create failures.
		if now.Equal(instance.LastObservedAt) {
			return nil
		}
		if now.Sub(instance.LastObservedAt) > time.Minute {
			instance.HealthySince = nil
		}
		instance.LastObservedAt = now
		restartTimes := instance.RestartTimes[:0]
		for _, at := range instance.RestartTimes {
			if at.After(now.Add(-RestartWindow)) {
				restartTimes = append(restartTimes, at)
			}
		}
		instance.RestartTimes = restartTimes
		action, result, status := "none", "not_attempted", "open"
		emit := false
		if observation.ErrorCode == "" {
			instance.ConsecutiveFailures = 0
			instance.FailureStreakAt = nil
			if instance.HealthySince == nil {
				healthy := now
				instance.HealthySince = &healthy
			}
			if instance.Open && now.Sub(*instance.HealthySince) >= RecoveryDuration {
				emit = true
				status = "recovered"
			}
			if !instance.Open {
				instance.FirstFailedAt = nil
				instance.ConsecutiveFailures = 0
			}
		} else {
			if !errorPattern.MatchString(observation.ErrorCode) {
				return errors.New("invalid observation error code")
			}
			instance.HealthySince = nil
			if instance.FailureStreakAt == nil {
				first := now
				instance.FailureStreakAt = &first
			}
			if instance.FirstFailedAt == nil {
				first := now
				instance.FirstFailedAt = &first
				instance.ConsecutiveFailures = 0
			}
			if instance.ConsecutiveFailures < 1000000 {
				instance.ConsecutiveFailures++
			}
			instance.ErrorCode = observation.ErrorCode
			if (instance.ConsecutiveFailures >= 3 && now.Sub(*instance.FailureStreakAt) >= FailureDuration) || manualError(observation.ErrorCode) {
				instance.Open = true
				emit = true
				if observation.RestartAllowed && (observation.ErrorCode == "PLUGIN_HEALTH_FAILED" || observation.ErrorCode == "PLUGIN_PROCESS_EXITED") {
					if len(instance.RestartTimes) < RestartLimit {
						instance.RestartTimes = append(instance.RestartTimes, now)
						decision.Restart = true
						action, result = "restart", "not_attempted"
					} else {
						action, result = "circuit_break", "blocked"
					}
				} else {
					result = "blocked"
				}
			}
		}
		if emit {
			id, err := newEventID()
			if err != nil {
				return err
			}
			event := s.event(observation, instance, now, id, status, action, result)
			if err := s.append(state, event); err != nil {
				return err
			}
			if status == "recovered" {
				instance.Open = false
				instance.FirstFailedAt = nil
				instance.ConsecutiveFailures = 0
				instance.ErrorCode = ""
			}
		}
		state.Instances[observation.InstanceID] = instance
		return nil
	})
	if err != nil {
		decision.Restart = false
	}
	return decision, err
}
func (s *Store) event(observation Observation, instance instanceState, now time.Time, id, status, action, result string) Event {
	severity := "P2"
	if instance.ErrorCode == "PLUGIN_SIGNATURE_INVALID" {
		severity = "P0"
	}
	return Event{SchemaVersion: 1, EventID: id, OccurredAt: now, Environment: s.environment, Source: "agent", NodeID: s.nodeID, AgentVersion: s.agentVersion, ConfigVersion: observation.ConfigVersion, PluginID: observation.PluginID, PluginVersion: observation.PluginVersion, InstanceID: observation.InstanceID, ErrorCode: instance.ErrorCode, Severity: severity, Status: status, FirstFailedAt: instance.FirstFailedAt, ConsecutiveFailures: instance.ConsecutiveFailures, HealthySince: instance.HealthySince, SelfHealAction: action, SelfHealResult: result}
}
func (s *Store) CompleteRestart(observation Observation, now time.Time, restartErr error) error {
	if observation.InstanceID == "" {
		observation.InstanceID = observation.PluginID
	}
	return s.transaction(func(state *diskState) error {
		instance, ok := state.Instances[observation.InstanceID]
		if !ok || !instance.Open {
			return errors.New("restart has no persisted incident")
		}
		id, err := newEventID()
		if err != nil {
			return err
		}
		result := "succeeded"
		if restartErr != nil {
			result = "failed"
		}
		return s.append(state, s.event(observation, instance, now, id, "open", "restart", result))
	})
}

func manualError(code string) bool {
	return oneOf(code, "PLUGIN_CREDENTIAL_INVALID", "PLUGIN_PERMISSION_DENIED", "PLUGIN_SIGNATURE_INVALID", "PLUGIN_CONFIG_INVALID")
}

// HasFailure gates startup restoration as well as live restarts. Graceful
// shutdown changes a plugin's process state to stopped; the independent durable
// incident state must still prevent that transition from clearing its budget.
func (s *Store) HasFailure(instanceID string) (bool, error) {
	failed := false
	err := s.transaction(func(state *diskState) error {
		instance := state.Instances[instanceID]
		failed = instance.FirstFailedAt != nil
		return nil
	})
	return failed, err
}
