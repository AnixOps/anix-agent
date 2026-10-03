package plugin

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/AnixOps/anix-agent/v4/plugin/machinetelemetry"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/AnixOps/anix-control/sdk/telemetry/systemdreport"
)

const (
	maxPluginHeartbeatMetrics  = 128
	maxTelemetryManifestBytes  = 1 << 20
	maxTelemetrySignatureBytes = 4 << 10
)

type telemetryTarget struct {
	id      string
	version string
	socket  string
}

// TelemetryMetrics returns namespaced scalar metrics from enabled official
// plugins. It never returns untrusted plugin keys directly into the control
// protocol and keeps useful partial results when another plugin is unhealthy.
func (s *Supervisor) TelemetryMetrics(ctx context.Context) (map[string]float64, error) {
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
	targets := make([]telemetryTarget, 0, len(s.state.Plugins))
	for id, state := range s.state.Plugins {
		if !state.Enabled || state.Health != "healthy" || state.DesiredVersion == "" || s.processes[id] == nil {
			continue
		}
		targets = append(targets, telemetryTarget{id: id, version: state.DesiredVersion, socket: s.socketPath(id)})
	}
	s.mu.Unlock()
	sort.Slice(targets, func(left, right int) bool { return targets[left].id < targets[right].id })

	metrics := make(map[string]float64)
	var result error
	now := time.Now()
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return metrics, errors.Join(result, err)
		}
		manifest, err := s.verifyTelemetryManifest(target.id, target.version)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("verify telemetry plugin %s: %w", target.id, err))
			continue
		}
		if !manifestSupportsCapability(manifest, "telemetry.read") {
			continue
		}
		snapshot, err := machinetelemetry.FetchSnapshot(ctx, target.socket, machinetelemetry.DefaultClientTimeout)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("collect telemetry plugin %s: %w", target.id, err))
			continue
		}
		metricKeys := make([]string, 0, len(snapshot.Metrics))
		for key := range snapshot.Metrics {
			metricKeys = append(metricKeys, key)
		}
		sort.Strings(metricKeys)
		for _, key := range metricKeys {
			value := snapshot.Metrics[key]
			if len(metrics) >= maxPluginHeartbeatMetrics {
				result = errors.Join(result, fmt.Errorf("plugin telemetry exceeds %d heartbeat metrics", maxPluginHeartbeatMetrics))
				break
			}
			if math.IsNaN(value) || math.IsInf(value, 0) {
				continue
			}
			metrics[pluginHeartbeatMetricKey(target.id, key)] = value
		}
		age := now.Sub(time.UnixMilli(snapshot.ObservedAtUnixMs)).Seconds()
		if age < 0 {
			age = 0
		}
		if len(metrics) < maxPluginHeartbeatMetrics {
			metrics[pluginHeartbeatMetricKey(target.id, "sample_age_seconds")] = age
		}
	}
	return metrics, result
}

// PackageReports returns the latest package report of each enabled
// official plugin that makes one (package-reports.v1): today the
// systemd.services table of machine-telemetry. A plugin reports only when
// it runs its assigned release (the version Control's operation targeted,
// which is the version the report names, as Control requires), healthy, and
// that release's verified manifest declares the kind's capability. A plugin
// with nothing to report (collection off for the node, nothing collected
// yet, a release before the collector) is skipped. Partial results come
// with the errors of the others.
func (s *Supervisor) PackageReports(ctx context.Context) ([]*agentv1pb.PackageReport, error) {
	if s == nil {
		return nil, errors.New("plugin Supervisor is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	release, err := s.lifecycle.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	s.mu.Lock()
	targets := make([]telemetryTarget, 0, len(s.state.Plugins))
	for id, state := range s.state.Plugins {
		if !state.Enabled || state.Health != "healthy" || state.DesiredVersion == "" ||
			state.ObservedVersion != state.DesiredVersion || s.processes[id] == nil {
			continue
		}
		targets = append(targets, telemetryTarget{id: id, version: state.DesiredVersion, socket: s.socketPath(id)})
	}
	s.mu.Unlock()
	sort.Slice(targets, func(left, right int) bool { return targets[left].id < targets[right].id })

	var reports []*agentv1pb.PackageReport
	var result error
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return reports, errors.Join(result, err)
		}
		manifest, err := s.verifyTelemetryManifest(target.id, target.version)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("verify plugin %s: %w", target.id, err))
			continue
		}
		if !manifestSupportsCapability(manifest, systemdreport.Capability) {
			continue
		}
		report, ok, err := machinetelemetry.FetchSystemdServices(ctx, target.socket, machinetelemetry.DefaultClientTimeout)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("collect plugin %s package report: %w", target.id, err))
			continue
		}
		if !ok {
			continue
		}
		reports = append(reports, &agentv1pb.PackageReport{
			PluginId: target.id, Kind: report.Kind, Version: target.version,
			PayloadJson: append([]byte(nil), report.PayloadJSON...), ObservedAtUnixMs: report.ObservedAtUnixMs,
		})
	}
	return reports, result
}

func (s *Supervisor) verifyTelemetryManifest(id, version string) (*Manifest, error) {
	if !safeSegment(id) || !safeSegment(version) {
		return nil, errors.New("plugin id and version must be safe path segments")
	}
	directory := s.versionDir(id, version)
	manifestJSON, err := readRegularFile(filepath.Join(directory, manifestFileName), maxTelemetryManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("read installed plugin manifest: %w", err)
	}
	signature, err := readRegularFile(filepath.Join(directory, signatureFileName), maxTelemetrySignatureBytes)
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

func pluginHeartbeatMetricKey(pluginID, key string) string {
	return "plugin." + strings.TrimSpace(pluginID) + "." + strings.TrimSpace(key)
}
