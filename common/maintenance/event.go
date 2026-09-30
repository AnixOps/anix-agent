// Package maintenance implements the durable Agent-to-Control maintenance boundary.
package maintenance

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const Version = "anixops.maintenance/v1"
const MaxBatchSize = 50
const MaxPayloadBytes = 256 << 10

var identityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var errorPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_.-]{0,127}$`)
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
var nodePattern = regexp.MustCompile(`^[1-9][0-9]{0,127}$`)

type Event struct {
	SchemaVersion       int        `json:"schema_version"`
	EventID             string     `json:"event_id"`
	OccurredAt          time.Time  `json:"occurred_at"`
	Environment         string     `json:"environment"`
	Source              string     `json:"source"`
	NodeID              string     `json:"node_id"`
	AgentVersion        string     `json:"agent_version,omitempty"`
	ConfigVersion       string     `json:"config_version,omitempty"`
	PluginID            string     `json:"plugin_id,omitempty"`
	PluginVersion       string     `json:"plugin_version,omitempty"`
	InstanceID          string     `json:"instance_id,omitempty"`
	ErrorCode           string     `json:"error_code"`
	Severity            string     `json:"severity"`
	Status              string     `json:"status"`
	FirstFailedAt       *time.Time `json:"first_failed_at,omitempty"`
	ConsecutiveFailures int        `json:"consecutive_failures,omitempty"`
	HealthySince        *time.Time `json:"healthy_since,omitempty"`
	SelfHealAction      string     `json:"self_heal_action,omitempty"`
	SelfHealResult      string     `json:"self_heal_result,omitempty"`
	DiagnosticRef       string     `json:"diagnostic_ref,omitempty"`
	TicketKey           string     `json:"ticket_key,omitempty"`
	RedactedSummary     string     `json:"redacted_summary,omitempty"`
}

type Batch struct {
	Version string  `json:"version"`
	Events  []Event `json:"events"`
}

type Acknowledgment struct {
	Version string        `json:"version"`
	Events  []EventResult `json:"events"`
}

type EventResult struct {
	EventID   string `json:"event_id"`
	Persisted bool   `json:"persisted"`
	Error     string `json:"error,omitempty"`
}

func (e Event) Validate() error { return e.ValidateAt(time.Now()) }
func (e Event) ValidateAt(now time.Time) error {
	if e.SchemaVersion != 1 {
		return errors.New("invalid schema_version")
	}
	node, nodeErr := strconv.ParseUint(e.NodeID, 10, 64)
	if !nodePattern.MatchString(e.NodeID) || nodeErr != nil || node == 0 {
		return errors.New("invalid node_id")
	}
	for name, value := range map[string]string{"event_id": e.EventID, "plugin_id": e.PluginID, "instance_id": e.InstanceID} {
		if !identityPattern.MatchString(value) {
			return fmt.Errorf("invalid %s", name)
		}
	}
	for name, value := range map[string]string{"agent_version": e.AgentVersion, "config_version": e.ConfigVersion, "plugin_version": e.PluginVersion} {
		if value != "" && !versionPattern.MatchString(value) {
			return fmt.Errorf("invalid %s", name)
		}
	}
	if !versionPattern.MatchString(e.PluginVersion) {
		return errors.New("invalid plugin_version")
	}
	if !errorPattern.MatchString(e.ErrorCode) {
		return errors.New("invalid error_code")
	}
	if e.OccurredAt.Before(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)) || e.OccurredAt.After(now.Add(5*time.Minute)) {
		return errors.New("invalid occurred_at")
	}
	if e.Environment != "production" && e.Environment != "staging" && e.Environment != "development" {
		return errors.New("invalid environment")
	}
	if e.Source != "agent" && e.Source != "control" && e.Source != "networkcore" && e.Source != "deployment" {
		return errors.New("invalid source")
	}
	if !oneOf(e.Severity, "P0", "P1", "P2", "P3") {
		return errors.New("invalid severity")
	}
	if !oneOf(e.Status, "open", "degraded", "recovered") {
		return errors.New("invalid status")
	}
	if !oneOf(e.SelfHealAction, "", "none", "retry", "restart", "circuit_break") {
		return errors.New("invalid self_heal_action")
	}
	if !oneOf(e.SelfHealResult, "", "not_attempted", "succeeded", "failed", "blocked") {
		return errors.New("invalid self_heal_result")
	}
	if e.ConsecutiveFailures < 0 || e.ConsecutiveFailures > 1000000 {
		return errors.New("invalid consecutive_failures")
	}
	if e.FirstFailedAt != nil && (e.FirstFailedAt.Before(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)) || e.FirstFailedAt.After(e.OccurredAt)) {
		return errors.New("invalid first_failed_at")
	}
	if e.HealthySince != nil && (e.HealthySince.Before(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)) || e.HealthySince.After(e.OccurredAt)) {
		return errors.New("invalid healthy_since")
	}
	if len(e.DiagnosticRef) > 256 || len(e.TicketKey) > 256 || len(e.RedactedSummary) > 2000 || strings.ContainsAny(e.DiagnosticRef+e.TicketKey+e.RedactedSummary, "\x00") {
		return errors.New("invalid diagnostic fields")
	}
	if e.Status == "recovered" && (e.HealthySince == nil || e.ConsecutiveFailures != 0) {
		return errors.New("invalid recovery")
	}
	if e.Status != "recovered" && (e.FirstFailedAt == nil || e.ConsecutiveFailures == 0 || e.HealthySince != nil) {
		return errors.New("invalid failure")
	}
	return nil
}
func oneOf(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}
func (e Event) DedupeKey() string {
	return strings.Join([]string{e.Environment, e.NodeID, e.PluginID, e.InstanceID}, "|")
}
