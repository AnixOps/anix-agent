package maintenance

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testEvent(id string) Event {
	first := time.Now().Add(-time.Hour - 2*time.Minute)
	return Event{FirstFailedAt: &first, ConsecutiveFailures: 3, SchemaVersion: 1, EventID: id, OccurredAt: time.Now().Add(-time.Hour), Environment: "development", Source: "agent", NodeID: "42", PluginID: "machine-telemetry", InstanceID: "machine-telemetry", PluginVersion: "1.0.0", ErrorCode: "PLUGIN_HEALTH_FAILED", Severity: "P2", Status: "open"}
}
func openStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path, "42", "development", "1.0.0")
	require.NoError(t, err)
	return s
}
func TestOutboxDurableAcknowledgmentsAndDiskFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "maintenance.json")
	s := openStore(t, path)
	a := testEvent("a")
	require.NoError(t, s.Queue(a))
	require.NoError(t, s.Queue(a))
	require.NoError(t, s.Queue(testEvent("b")))
	s = openStore(t, path)
	events, err := s.Pending(50)
	require.NoError(t, err)
	require.Len(t, events, 2)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	require.NoError(t, s.Acknowledge(Acknowledgment{Version: Version, Events: []EventResult{{EventID: "a", Persisted: true}, {EventID: "b", Persisted: false, Error: "database_failure"}}}))
	s = openStore(t, path)
	events, err = s.Pending(50)
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, "b", events[0].EventID)
	s.write = func([]byte) error { return errors.New("disk full") }
	require.Error(t, s.Acknowledge(Acknowledgment{Version: Version, Events: []EventResult{{EventID: "b", Persisted: true}}}))
	require.Error(t, s.Queue(testEvent("c")))
	s = openStore(t, path)
	events, err = s.Pending(50)
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, "b", events[0].EventID)
	wrong := testEvent("wrong")
	wrong.NodeID = "43"
	require.Error(t, s.Queue(wrong))
}
func TestQualificationRecoveryAndPersistentRestartBudget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "maintenance.json")
	s := openStore(t, path)
	base := time.Now().Add(-time.Hour)
	observation := Observation{PluginID: "machine-telemetry", InstanceID: "machine-telemetry", PluginVersion: "1.0.0", ErrorCode: "PLUGIN_HEALTH_FAILED", RestartAllowed: true}
	for _, elapsed := range []time.Duration{0, time.Second, 119 * time.Second} {
		decision, err := s.Observe(observation, base.Add(elapsed))
		require.NoError(t, err)
		require.False(t, decision.Restart)
	}
	events, err := s.Pending(50)
	require.NoError(t, err)
	require.Empty(t, events)
	decision, err := s.Observe(observation, base.Add(2*time.Minute))
	require.NoError(t, err)
	require.True(t, decision.Restart)
	s = openStore(t, path)
	decision, err = s.Observe(observation, base.Add(150*time.Second))
	require.NoError(t, err)
	require.True(t, decision.Restart)
	s = openStore(t, path)
	decision, err = s.Observe(observation, base.Add(3*time.Minute))
	require.NoError(t, err)
	require.False(t, decision.Restart)
	require.NoError(t, s.CompleteRestart(observation, base.Add(3*time.Minute), errors.New("failure secret should not appear")))
	events, err = s.Pending(50)
	require.NoError(t, err)
	require.Len(t, events, 4)
	for _, event := range events {
		require.Empty(t, event.RedactedSummary)
		require.True(t, base.Equal(*event.FirstFailedAt))
	}
	healthy := observation
	healthy.ErrorCode = ""
	for minute := 4; minute <= 9; minute++ {
		_, err := s.Observe(healthy, base.Add(time.Duration(minute)*time.Minute))
		require.NoError(t, err)
	}
	events, err = s.Pending(50)
	require.NoError(t, err)
	require.Len(t, events, 5)
	require.Equal(t, "recovered", events[4].Status)
	_, err = s.Observe(healthy, base.Add(10*time.Minute))
	require.NoError(t, err)
	events, err = s.Pending(50)
	require.NoError(t, err)
	require.Len(t, events, 5)
	for _, minute := range []int{11, 12, 13} {
		decision, err = s.Observe(observation, base.Add(time.Duration(minute)*time.Minute))
		require.NoError(t, err)
		require.False(t, decision.Restart)
	}
	decision, err = s.Observe(observation, base.Add(32*time.Minute))
	require.NoError(t, err)
	require.True(t, decision.Restart)
}
func TestConsecutiveFailuresAndHealthyContinuity(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "state.json"))
	base := time.Now().Add(-time.Hour)
	o := Observation{PluginID: "machine-telemetry", PluginVersion: "1", ErrorCode: "PLUGIN_HEALTH_FAILED", RestartAllowed: true}
	_, err := s.Observe(o, base)
	require.NoError(t, err)
	healthy := o
	healthy.ErrorCode = ""
	_, err = s.Observe(healthy, base.Add(time.Minute))
	require.NoError(t, err)
	for _, seconds := range []int{121, 122, 123} {
		d, err := s.Observe(o, base.Add(time.Duration(seconds)*time.Second))
		require.NoError(t, err)
		require.False(t, d.Restart)
	}
	d, err := s.Observe(o, base.Add(241*time.Second))
	require.NoError(t, err)
	require.True(t, d.Restart)
	_, err = s.Observe(healthy, base.Add(5*time.Minute))
	require.NoError(t, err)
	_, err = s.Observe(healthy, base.Add(11*time.Minute))
	require.NoError(t, err)
	events, err := s.Pending(50)
	require.NoError(t, err)
	require.Len(t, events, 1)
}
func TestManualErrorsNeverRestartAndPersistenceFailureBlocksAction(t *testing.T) {
	for _, code := range []string{"PLUGIN_CREDENTIAL_INVALID", "PLUGIN_PERMISSION_DENIED", "PLUGIN_SIGNATURE_INVALID", "PLUGIN_CONFIG_INVALID"} {
		t.Run(code, func(t *testing.T) {
			s := openStore(t, filepath.Join(t.TempDir(), "state.json"))
			o := Observation{PluginID: "machine-telemetry", PluginVersion: "1", ErrorCode: code, RestartAllowed: true}
			d, err := s.Observe(o, time.Now().Add(-time.Hour))
			require.NoError(t, err)
			require.False(t, d.Restart)
			events, err := s.Pending(50)
			require.NoError(t, err)
			require.Len(t, events, 1)
			require.Equal(t, "blocked", events[0].SelfHealResult)
		})
	}
	s := openStore(t, filepath.Join(t.TempDir(), "state.json"))
	base := time.Now().Add(-time.Hour)
	o := Observation{PluginID: "machine-telemetry", PluginVersion: "1", ErrorCode: "PLUGIN_HEALTH_FAILED", RestartAllowed: true}
	_, err := s.Observe(o, base)
	require.NoError(t, err)
	_, err = s.Observe(o, base.Add(time.Minute))
	require.NoError(t, err)
	s.write = func([]byte) error { return errors.New("disk full") }
	d, err := s.Observe(o, base.Add(2*time.Minute))
	require.Error(t, err)
	require.False(t, d.Restart)
}
func TestOutboxConcurrentWritersAndBatchLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	a, b := openStore(t, path), openStore(t, path)
	var wg sync.WaitGroup
	for i := 0; i < 80; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store := a
			if i%2 == 0 {
				store = b
			}
			require.NoError(t, store.Queue(testEvent("event-"+strconv.Itoa(i))))
		}(i)
	}
	wg.Wait()
	events, err := a.Pending(10000)
	require.NoError(t, err)
	require.Len(t, events, MaxBatchSize)
	results := make([]EventResult, len(events))
	for i, event := range events {
		results[i] = EventResult{EventID: event.EventID, Persisted: true}
	}
	require.NoError(t, b.Acknowledge(Acknowledgment{Version: Version, Events: results}))
	events, err = a.Pending(50)
	require.NoError(t, err)
	require.Len(t, events, 30)
}
func TestOutboxCrossProcess(t *testing.T) {
	if path := os.Getenv("ANIX_MAINTENANCE_TEST_CHILD_PATH"); path != "" {
		store := openStore(t, path)
		for i := 0; i < 20; i++ {
			require.NoError(t, store.Queue(testEvent(os.Getenv("ANIX_MAINTENANCE_TEST_CHILD_ID")+strconv.Itoa(i))))
		}
		return
	}
	path := filepath.Join(t.TempDir(), "state.json")
	openStore(t, path)
	commands := make([]*exec.Cmd, 2)
	for i := range commands {
		commands[i] = exec.Command(os.Args[0], "-test.run=^TestOutboxCrossProcess$")
		commands[i].Env = append(os.Environ(), "ANIX_MAINTENANCE_TEST_CHILD_PATH="+path, "ANIX_MAINTENANCE_TEST_CHILD_ID="+strconv.Itoa(i)+"-")
		require.NoError(t, commands[i].Start())
	}
	for _, cmd := range commands {
		require.NoError(t, cmd.Wait())
	}
	events, err := openStore(t, path).Pending(50)
	require.NoError(t, err)
	require.Len(t, events, 40)
}
func TestEventRejectsInvalidBoundaries(t *testing.T) {
	now := time.Now()
	for name, mutate := range map[string]func(*Event){"schema": func(e *Event) { e.SchemaVersion = 2 }, "node": func(e *Event) { e.NodeID = "other" }, "plugin": func(e *Event) { e.PluginID = "" }, "version": func(e *Event) { e.PluginVersion = "bad/version" }, "future": func(e *Event) { e.OccurredAt = now.Add(6 * time.Minute) }, "zero": func(e *Event) { e.OccurredAt = time.Time{} }, "closed": func(e *Event) { e.Status = "closed" }, "rollback": func(e *Event) { e.SelfHealAction = "rollback" }, "enum": func(e *Event) { e.Severity = "fatal" }, "error": func(e *Event) { e.ErrorCode = "1INVALID" }, "count": func(e *Event) { e.ConsecutiveFailures = 1000001 }} {
		t.Run(name, func(t *testing.T) {
			event := testEvent("valid")
			mutate(&event)
			require.Error(t, event.ValidateAt(now))
		})
	}
	old := testEvent("old")
	old.OccurredAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	old.FirstFailedAt = &old.OccurredAt
	require.NoError(t, old.ValidateAt(now))
}

func TestCorruptStateFailsClosed(t *testing.T) {
	for name, data := range map[string]string{"empty-object": "{}", "truncated": "{", "missing-identity": `{"events":{},"instances":{}}`} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			require.NoError(t, os.WriteFile(path, []byte(data), 0600))
			_, err := Open(path, "42", "development", "1")
			require.Error(t, err)
			stored, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, data, string(stored))
		})
	}
}
