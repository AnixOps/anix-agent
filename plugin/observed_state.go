package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
)

const (
	// observedStateCapability is deliberately opt-in. A plugin cannot cause the
	// Agent to read arbitrary runtime data merely by writing beside its state.
	observedStateCapability = "kernel.observed-state"

	observedStateFileSuffix          = ".observed.json"
	observedStateSchemaVersion       = 1
	maxObservedManifestBytes   int64 = 1 << 20
	maxObservedSignatureBytes  int64 = 4 << 10
	maxObservedStateBytes      int64 = 256 << 10
	maxObservedRuleCounters          = 1024
	maxObservedRuleIDLength          = 96
	maxObservedStateAge              = 2 * time.Minute
	maxObservedStateFutureSkew       = 30 * time.Second
)

type observedStateTarget struct {
	state PluginState
}

// runtimeObservedState is a deliberately narrow on-disk contract between an
// official runtime plugin and the Agent Supervisor. It must never contain
// config, secret references, process output, or free-form diagnostics.
type runtimeObservedState struct {
	Version          int                      `json:"version"`
	PluginID         string                   `json:"plugin_id"`
	PluginVersion    string                   `json:"plugin_version"`
	Health           string                   `json:"health"`
	ObservedAtUnixMs int64                    `json:"observed_at_unix_ms"`
	RulesetSHA256    string                   `json:"ruleset_sha256,omitempty"`
	RuleCounters     []runtimeObservedCounter `json:"rule_counters,omitempty"`
}

type runtimeObservedCounter struct {
	RuleID  string `json:"rule_id"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// PluginObservations returns only signed, enabled plugin evidence suitable for
// the Agent Control heartbeat. Supervisor state supplies the version,
// revisions, config hash, and authoritative process health; plugins can only
// contribute the fixed ruleset fingerprint and counters from their private
// observation file.
func (s *Supervisor) PluginObservations(ctx context.Context) ([]*agentv1pb.PluginObservedState, error) {
	if s == nil {
		return nil, errors.New("plugin Supervisor is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.checkOpen(); err != nil {
		return nil, err
	}

	release, err := s.lifecycle.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	targets := make([]observedStateTarget, 0, len(s.state.Plugins))
	for id, state := range s.state.Plugins {
		if !state.Enabled || state.ID != id || s.processes[id] == nil {
			continue
		}
		targets = append(targets, observedStateTarget{state: state})
	}
	s.mu.Unlock()
	sort.Slice(targets, func(left, right int) bool {
		return targets[left].state.ID < targets[right].state.ID
	})

	now := s.now()
	observations := make([]*agentv1pb.PluginObservedState, 0, len(targets))
	var result error
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return observations, errors.Join(result, err)
		}
		state := target.state

		manifest, err := s.verifyObservedStateManifest(state.ID, state.ObservedVersion)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("verify observed-state plugin %s: %w", state.ID, err))
			continue
		}
		if !manifestSupportsCapability(manifest, observedStateCapability) {
			continue
		}
		// A private observation file alone is not enough evidence. The runtime
		// must still report serving on its Supervisor-owned socket for every
		// heartbeat. This fails closed if a runtime cannot replace a previous
		// healthy observation after kernel drift or a filesystem failure.
		state, active, healthErr := s.refreshObservedStateRuntimeHealth(ctx, state.ID)
		if !active || !safeObservationSupervisorState(state) {
			continue
		}
		if healthErr != nil {
			observations = append(observations, supervisorUnhealthyObservation(state, now))
			result = errors.Join(result, fmt.Errorf("observed-state plugin %s runtime health is unavailable", state.ID))
			continue
		}

		diskState, exists, err := readRuntimeObservedState(s.rootDir, s.runtimeObservedStatePath(state.ID), now)
		if err != nil {
			// The Agent owns identity, revisions, and config hash, so it can emit a
			// bounded unhealthy snapshot without trusting malformed plugin data.
			// This replaces any previously accepted healthy evidence immediately.
			observations = append(observations, supervisorUnhealthyObservation(state, now))
			result = errors.Join(result, fmt.Errorf("read observed state for plugin %s failed", state.ID))
			continue
		}
		if !exists {
			continue
		}
		if diskState.PluginID != state.ID || diskState.PluginVersion != state.ObservedVersion {
			observations = append(observations, supervisorUnhealthyObservation(state, now))
			result = errors.Join(result, fmt.Errorf("read observed state for plugin %s: identity does not match Supervisor state", state.ID))
			continue
		}

		observations = append(observations, observedStateToProto(state, diskState))
	}
	return observations, result
}

// refreshObservedStateRuntimeHealth verifies the live runtime independently of
// its on-disk observation. It only returns an active state; a concurrent
// disable or process replacement is intentionally treated as no evidence.
func (s *Supervisor) refreshObservedStateRuntimeHealth(ctx context.Context, id string) (PluginState, bool, error) {
	if s == nil {
		return PluginState{}, false, errors.New("plugin Supervisor is unavailable")
	}
	checkErr := errors.New("plugin runtime health checker is unavailable")
	if s.health != nil {
		checkErr = s.health.Check(ctx, s.socketPath(id))
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	state, active := s.state.Plugins[id]
	if !active || !state.Enabled || s.processes[id] == nil {
		return PluginState{}, false, nil
	}
	health, lastError := "healthy", ""
	if checkErr != nil {
		health, lastError = "unhealthy", "runtime health check failed"
	}
	if state.Health != health || state.LastError != lastError {
		state.Health, state.LastError, state.UpdatedAt = health, lastError, s.now()
		s.state.Plugins[id] = state
		if err := s.persistLocked(); err != nil {
			if checkErr == nil {
				checkErr = err
			}
		}
	}
	return state, true, checkErr
}

func supervisorUnhealthyObservation(state PluginState, at time.Time) *agentv1pb.PluginObservedState {
	return &agentv1pb.PluginObservedState{
		PluginId:         state.ID,
		Version:          state.ObservedVersion,
		DesiredRevision:  state.DesiredRevision,
		ObservedRevision: state.ObservedRevision,
		ConfigHash:       strings.ToLower(state.ConfigHash),
		Health:           "unhealthy",
		ObservedAtUnixMs: at.UTC().UnixMilli(),
	}
}

func safeObservationSupervisorState(state PluginState) bool {
	return safeSegment(state.ID) && safeSegment(state.DesiredVersion) &&
		safeSegment(state.ObservedVersion) && state.DesiredVersion == state.ObservedVersion &&
		state.DesiredRevision > 0 && state.ObservedRevision > 0 && validSHA256(state.ConfigHash)
}

func (s *Supervisor) runtimeObservedStatePath(id string) string {
	return s.runtimeStatePath(id) + observedStateFileSuffix
}

func (s *Supervisor) verifyObservedStateManifest(id, version string) (*Manifest, error) {
	if !safeSegment(id) || !safeSegment(version) {
		return nil, errors.New("plugin id and version must be safe path segments")
	}
	directory := s.versionDir(id, version)
	if err := privateRealDirectoryWithin(s.rootDir, directory); err != nil {
		return nil, fmt.Errorf("inspect installed plugin directory: %w", err)
	}
	manifestJSON, err := readPrivateRegularFile(filepath.Join(directory, manifestFileName), maxObservedManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("read installed plugin manifest: %w", err)
	}
	signature, err := readPrivateRegularFile(filepath.Join(directory, signatureFileName), maxObservedSignatureBytes)
	if err != nil {
		return nil, fmt.Errorf("read installed plugin signature: %w", err)
	}
	manifest, err := VerifyManifest(string(manifestJSON), strings.TrimSpace(string(signature)), s.publicKey)
	if err != nil {
		return nil, fmt.Errorf("verify installed plugin manifest: %w", err)
	}
	if manifest.ID != id || manifest.Version != version {
		return nil, errors.New("installed plugin manifest does not match its path")
	}
	return manifest, nil
}

func readRuntimeObservedState(rootDir, statePath string, now time.Time) (runtimeObservedState, bool, error) {
	contents, exists, err := readPrivateRuntimeFile(rootDir, statePath, maxObservedStateBytes)
	if err != nil || !exists {
		return runtimeObservedState{}, exists, err
	}

	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var observed runtimeObservedState
	if err := decoder.Decode(&observed); err != nil {
		return runtimeObservedState{}, false, fmt.Errorf("decode runtime observation: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return runtimeObservedState{}, false, errors.New("runtime observation must contain exactly one JSON object")
	}
	if err := validateRuntimeObservedState(observed, now); err != nil {
		return runtimeObservedState{}, false, err
	}
	return observed, true, nil
}

func validateRuntimeObservedState(observed runtimeObservedState, now time.Time) error {
	if observed.Version != observedStateSchemaVersion {
		return fmt.Errorf("unsupported runtime observation schema version %d", observed.Version)
	}
	if !safeSegment(observed.PluginID) || !safeSegment(observed.PluginVersion) {
		return errors.New("runtime observation plugin identity is invalid")
	}
	if observed.ObservedAtUnixMs <= 0 {
		return errors.New("runtime observation timestamp is invalid")
	}
	observedAt := time.UnixMilli(observed.ObservedAtUnixMs)
	if observedAt.After(now.Add(maxObservedStateFutureSkew)) {
		return errors.New("runtime observation timestamp is too far in the future")
	}
	if now.Sub(observedAt) > maxObservedStateAge {
		return fmt.Errorf("runtime observation is older than %s", maxObservedStateAge)
	}

	switch observed.Health {
	case "healthy":
		if !validSHA256(observed.RulesetSHA256) {
			return errors.New("healthy runtime observation requires a ruleset sha256")
		}
	case "unhealthy":
		if observed.RulesetSHA256 != "" && !validSHA256(observed.RulesetSHA256) {
			return errors.New("runtime observation ruleset sha256 is invalid")
		}
	default:
		return errors.New("runtime observation health is invalid")
	}
	if len(observed.RuleCounters) > maxObservedRuleCounters {
		return fmt.Errorf("runtime observation exceeds %d rule counters", maxObservedRuleCounters)
	}
	seen := make(map[string]struct{}, len(observed.RuleCounters))
	for _, counter := range observed.RuleCounters {
		if !safeSegment(counter.RuleID) || len(counter.RuleID) > maxObservedRuleIDLength {
			return errors.New("runtime observation rule counter id is invalid")
		}
		if _, duplicate := seen[counter.RuleID]; duplicate {
			return errors.New("runtime observation rule counter id is duplicated")
		}
		seen[counter.RuleID] = struct{}{}
	}
	return nil
}

func observedStateToProto(state PluginState, observed runtimeObservedState) *agentv1pb.PluginObservedState {
	health := "unhealthy"
	if state.Health == "healthy" && observed.Health == "healthy" {
		health = "healthy"
	}

	result := &agentv1pb.PluginObservedState{
		PluginId:         state.ID,
		Version:          state.ObservedVersion,
		DesiredRevision:  state.DesiredRevision,
		ObservedRevision: state.ObservedRevision,
		ConfigHash:       strings.ToLower(state.ConfigHash),
		Health:           health,
		ObservedAtUnixMs: observed.ObservedAtUnixMs,
	}
	if health != "healthy" {
		return result
	}
	result.RulesetSha256 = strings.ToLower(observed.RulesetSHA256)
	if len(observed.RuleCounters) == 0 {
		return result
	}
	counters := append([]runtimeObservedCounter(nil), observed.RuleCounters...)
	sort.Slice(counters, func(left, right int) bool { return counters[left].RuleID < counters[right].RuleID })
	result.RuleCounters = make([]*agentv1pb.PluginRuleCounter, 0, len(counters))
	for _, counter := range counters {
		result.RuleCounters = append(result.RuleCounters, &agentv1pb.PluginRuleCounter{
			RuleId: counter.RuleID, Packets: counter.Packets, Bytes: counter.Bytes,
		})
	}
	return result
}

// readPrivateRuntimeFile avoids following a plugin-supplied symlink and checks
// every parent between the Supervisor root and the file. The runtime writes
// atomically, while this reader binds its read to the inode it inspected.
func readPrivateRuntimeFile(rootDir, filePath string, maximum int64) ([]byte, bool, error) {
	if err := privateRealDirectoryWithin(rootDir, filepath.Dir(filePath)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	info, err := os.Lstat(filePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("inspect runtime observation: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, false, errors.New("runtime observation must be a regular file, not a symlink")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, false, errors.New("runtime observation must be private")
	}
	if info.Size() > maximum {
		return nil, false, fmt.Errorf("runtime observation exceeds %d bytes", maximum)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, false, fmt.Errorf("open runtime observation: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, false, fmt.Errorf("stat runtime observation: %w", err)
	}
	if !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 {
		return nil, false, errors.New("runtime observation changed while it was being opened")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, false, fmt.Errorf("read runtime observation: %w", err)
	}
	if int64(len(contents)) > maximum {
		return nil, false, fmt.Errorf("runtime observation exceeds %d bytes", maximum)
	}
	return contents, true, nil
}

func readPrivateRegularFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("path must be a regular file, not a symlink")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("path must be private")
	}
	if info.Size() > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("file changed while it was being opened")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	return contents, nil
}

func privateRealDirectoryWithin(rootDir, directory string) error {
	rootDir = filepath.Clean(rootDir)
	directory = filepath.Clean(directory)
	if !filepath.IsAbs(rootDir) || !filepath.IsAbs(directory) {
		return errors.New("runtime observation path must be absolute")
	}
	relative, err := filepath.Rel(rootDir, directory)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("runtime observation path escapes the Supervisor root")
	}
	current := rootDir
	if err := requirePrivateRealDirectory(current); err != nil {
		return err
	}
	if relative == "." {
		return nil
	}
	for _, segment := range strings.Split(relative, string(filepath.Separator)) {
		if !safeSegment(segment) {
			return errors.New("runtime observation path contains an unsafe segment")
		}
		current = filepath.Join(current, segment)
		if err := requirePrivateRealDirectory(current); err != nil {
			return err
		}
	}
	return nil
}

func requirePrivateRealDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("runtime observation directory must be a real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("runtime observation directory must be private")
	}
	return nil
}
