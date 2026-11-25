package mesh

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
)

// fakeSystemd answers systemctl for services: enabled and active per name.
type fakeSystemd struct {
	enabled, active map[string]bool
	calls           []string
}

func (f *fakeSystemd) run(args ...string) error {
	f.calls = append(f.calls, strings.Join(args, " "))
	service := args[len(args)-1]
	switch args[0] {
	case "is-enabled":
		if !f.enabled[service] {
			return os.ErrNotExist
		}
	case "is-active":
		if !f.active[service] {
			return os.ErrNotExist
		}
	case "disable":
		f.enabled[service] = false
	case "enable":
		f.enabled[service] = true
	case "stop":
		f.active[service] = false
	case "start":
		f.active[service] = true
	}
	return nil
}

func TestTakeoverStopsAndRestoresServices(t *testing.T) {
	systemd := &fakeSystemd{enabled: map[string]bool{"old.service": true}, active: map[string]bool{"old.service": true, "manual.service": true}}
	takeover := &Takeover{StatePath: filepath.Join(t.TempDir(), "state", "takeover.json"), Proc: t.TempDir(), Run: systemd.run}
	spec := &panel.MeshTakeover{ServiceNames: []string{"old.service", "manual.service", "absent.service"}}

	if running := takeover.Detect(spec); !reflect.DeepEqual(running, []string{"service old.service", "service manual.service"}) {
		t.Fatalf("detect = %v", running)
	}
	systemd.calls = nil
	result := takeover.Stop(spec)
	if !result.Found || result.Error != "" || !reflect.DeepEqual(result.Stopped, []string{"service old.service", "service manual.service"}) {
		t.Fatalf("stop = %+v", result)
	}
	// Start at boot goes before the service.
	if systemd.calls[2] != "disable old.service" || systemd.calls[3] != "stop old.service" {
		t.Fatalf("calls = %v", systemd.calls)
	}
	if len(takeover.Detect(spec)) != 0 || !reflect.DeepEqual(takeover.Stopped(), []string{"old.service", "manual.service"}) {
		t.Fatalf("after stop: detect %v, stopped %v", takeover.Detect(spec), takeover.Stopped())
	}

	restored, err := takeover.Restore()
	if err != nil || !reflect.DeepEqual(restored, []string{"old.service", "manual.service"}) {
		t.Fatalf("restore = %v, %v", restored, err)
	}
	if !systemd.enabled["old.service"] || systemd.enabled["manual.service"] || !systemd.active["manual.service"] {
		t.Fatalf("after restore: enabled %v, active %v", systemd.enabled, systemd.active)
	}
	if len(takeover.Stopped()) != 0 {
		t.Fatal("restore forgets what it started")
	}
}

func TestTakeoverStopsProcessesByName(t *testing.T) {
	sleep := exec.Command("sleep", "30")
	if err := sleep.Start(); err != nil {
		t.Skip(err)
	}
	done := make(chan struct{})
	go func() { _ = sleep.Wait(); close(done) }()
	proc := t.TempDir()
	dir := filepath.Join(proc, strconv.Itoa(sleep.Process.Pid))
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte("mesh-old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	takeover := &Takeover{StatePath: filepath.Join(t.TempDir(), "takeover.json"), Proc: proc, Run: (&fakeSystemd{}).run}
	spec := &panel.MeshTakeover{ProcessNames: []string{"mesh-old"}}
	if running := takeover.Detect(spec); len(running) != 1 {
		t.Fatalf("detect = %v", running)
	}
	if result := takeover.Stop(spec); !result.Found || result.Error != "" || len(result.Stopped) != 1 {
		t.Fatalf("stop = %+v", result)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the process still runs")
	}
}
