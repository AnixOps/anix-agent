package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/AnixOps/anix-agent/v4/common/maintenance"
	"github.com/AnixOps/anix-agent/v4/plugin/machinetelemetry"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const maintenanceInterval = 30 * time.Second

func (s *Supervisor) MaintenanceStore() *maintenance.Store { return s.maintenance }

func (s *Supervisor) startMaintenanceMonitor() {
	if s.maintenance == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.maintenanceCancel = cancel
	s.maintenanceDone = make(chan struct{})
	go func() {
		defer close(s.maintenanceDone)
		ticker := time.NewTicker(maintenanceInterval)
		defer ticker.Stop()
		for {
			if err := s.CheckMaintenance(ctx); err != nil && ctx.Err() == nil {
				log.WithError(err).Error("plugin maintenance observation failed; durable evidence or restart may be deferred")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// CheckMaintenance probes the installed signed plugin instances. It uses the
// same per-plugin lifecycle lock as operator commands, so disable/update cannot
// race an automatic restart. Only machine-telemetry is on the automatic allowlist.
func (s *Supervisor) CheckMaintenance(ctx context.Context) error {
	if s.maintenance == nil {
		return nil
	}
	release, err := s.lifecycle.enter(ctx)
	if err != nil {
		return err
	}
	defer release()
	if err := s.checkOpen(); err != nil {
		return err
	}
	s.mu.Lock()
	ids := make([]string, 0, len(s.state.Plugins))
	for id, state := range s.state.Plugins {
		if state.Enabled || state.Health == "unhealthy" {
			ids = append(ids, id)
		}
	}
	s.mu.Unlock()
	sort.Strings(ids)
	var result error
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return errors.Join(result, err)
		}
		unlock, err := s.lockPlugin(ctx, id)
		if err != nil {
			return errors.Join(result, err)
		}
		err = s.checkMaintenanceInstance(ctx, id)
		unlock()
		result = errors.Join(result, err)
	}
	return result
}
func (s *Supervisor) checkMaintenanceInstance(ctx context.Context, id string) error {
	s.mu.Lock()
	state := s.state.Plugins[id]
	process := s.processes[id]
	s.mu.Unlock()
	if !state.Enabled && state.Health != "unhealthy" {
		return nil
	}
	if state.DesiredVersion == "" {
		return nil
	}
	observation := maintenanceObservation(state)
	manifest, probeErr := s.verifyInstalledVersion(id, state.DesiredVersion)
	if probeErr != nil {
		observation.ErrorCode = "PLUGIN_SIGNATURE_INVALID"
	} else if id == machinetelemetry.ID && s.validateTelemetryConfig(state) != nil {
		observation.ErrorCode = "PLUGIN_CONFIG_INVALID"
	} else if state.CleanupPending {
		observation.ErrorCode = "PLUGIN_PERMISSION_DENIED"
	} else if process == nil {
		observation.ErrorCode = "PLUGIN_PROCESS_EXITED"
		if code := maintenanceErrorCode(errors.New(state.LastError)); code != "PLUGIN_HEALTH_FAILED" {
			observation.ErrorCode = code
		}
	} else {
		checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		probeErr = s.health.Check(checkCtx, s.socketPath(id))
		cancel()
		if probeErr != nil {
			observation.ErrorCode = maintenanceErrorCode(probeErr)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	decision, err := s.maintenance.Observe(observation, s.now())
	if err != nil {
		return err
	}
	if observation.ErrorCode != "" {
		s.mu.Lock()
		current := s.state.Plugins[id]
		current.Health = "unhealthy"
		current.LastError = observation.ErrorCode
		current.UpdatedAt = s.now()
		s.state.Plugins[id] = current
		persistErr := s.persistLocked()
		s.mu.Unlock()
		if persistErr != nil {
			return persistErr
		}
	} else {
		s.mu.Lock()
		current := s.state.Plugins[id]
		current.Health = "healthy"
		current.LastError = ""
		current.UpdatedAt = s.now()
		s.state.Plugins[id] = current
		persistErr := s.persistLocked()
		s.mu.Unlock()
		if persistErr != nil {
			return persistErr
		}
	}
	if !decision.Restart {
		return nil
	}
	// The attempt and its rolling budget were fsynced together with the fault
	// event before any process mutation. A crash may consume an attempt, never add one.
	if manifest == nil {
		return errors.New("restart requires verified plugin manifest")
	}
	restartErr := s.restartMaintenanceInstance(ctx, state, process, manifest)
	auditErr := s.maintenance.CompleteRestart(observation, s.now(), restartErr)
	return errors.Join(restartErr, auditErr)
}
func maintenanceObservation(state PluginState) maintenance.Observation {
	return maintenance.Observation{PluginID: state.ID, InstanceID: state.ID, PluginVersion: state.DesiredVersion, ConfigVersion: strconv.FormatUint(state.DesiredRevision, 10), RestartAllowed: state.ID == "machine-telemetry"}
}
func maintenanceErrorCode(err error) string {
	if errors.Is(err, os.ErrPermission) || status.Code(err) == codes.PermissionDenied {
		return "PLUGIN_PERMISSION_DENIED"
	}
	if status.Code(err) == codes.Unauthenticated {
		return "PLUGIN_CREDENTIAL_INVALID"
	}
	if status.Code(err) == codes.InvalidArgument {
		return "PLUGIN_CONFIG_INVALID"
	}
	// Wrapped runner/config errors do not always retain a typed gRPC status. These
	// checks can only suppress restarts; raw error text never enters an event.
	text := strings.ToLower(err.Error())
	if strings.Contains(text, "signature") || strings.Contains(text, "checksum") {
		return "PLUGIN_SIGNATURE_INVALID"
	}
	if strings.Contains(text, "permission") || strings.Contains(text, "access denied") {
		return "PLUGIN_PERMISSION_DENIED"
	}
	if strings.Contains(text, "credential") || strings.Contains(text, "unauthenticated") || strings.Contains(text, "unauthorized") {
		return "PLUGIN_CREDENTIAL_INVALID"
	}
	if strings.Contains(text, "config") || strings.Contains(text, "invalid argument") {
		return "PLUGIN_CONFIG_INVALID"
	}
	return "PLUGIN_HEALTH_FAILED"
}
func (s *Supervisor) restartMaintenanceInstance(ctx context.Context, state PluginState, process Process, manifest *Manifest) error {
	s.mu.Lock()
	s.removeProcessLocked(state.ID)
	s.mu.Unlock()
	stopCtx, cancel := context.WithTimeout(ctx, cleanupTimeout)
	pending, err := s.stopAndCleanupInstalledVersion(stopCtx, manifest, state, process)
	cancel()
	if err != nil {
		s.recordTransitionFailure(state, state.DesiredRevision, err, "")
		if pending {
			s.markCleanupPending(state.ID, state.DesiredVersion, err)
		}
		return err
	}
	if err := removeSocket(s.socketPath(state.ID)); err != nil {
		return err
	}
	process, err = s.startVersion(ctx, state.ID, state.DesiredVersion)
	if err != nil {
		s.recordPluginError(state.ID, "unhealthy", err)
		return err
	}
	s.mu.Lock()
	current := s.state.Plugins[state.ID]
	current.Enabled, current.Health, current.LastError, current.ObservedVersion = true, "healthy", "", state.DesiredVersion
	current.CleanupPending, current.CleanupVersion = false, ""
	current.UpdatedAt = s.now()
	s.state.Plugins[state.ID] = current
	s.setProcessLocked(state.ID, process)
	err = s.persistLocked()
	if err != nil {
		s.removeProcessLocked(state.ID)
		s.state.Plugins[state.ID] = state
	}
	s.mu.Unlock()
	if err != nil {
		_ = stopProcess(process)
	}
	return err
}

func logMaintenanceFailure(err error) {
	log.WithError(err).Error("persist plugin process exit maintenance event")
}

func (s *Supervisor) validateTelemetryConfig(state PluginState) error {
	path := filepath.Join(s.versionDir(state.ID, state.DesiredVersion), "config.json")
	if _, err := machinetelemetry.LoadConfig(path); err != nil {
		return err
	}
	data, err := readRegularFile(path, 64<<10)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	if state.ConfigHash != "" && !strings.EqualFold(state.ConfigHash, hex.EncodeToString(digest[:])) {
		return errors.New("plugin config no longer matches the verified operation")
	}
	return nil
}
