// Package mesh takes over the existing mesh program of a node before the
// kernel joins its network, and gives it back (requirement R12, docs/mesh.md).
// What the program is called is deployment data (panel.MeshTakeover, the
// deployment's arguments of `anix-agent mesh takeover`); this package knows
// no program.
//
// The Agent runs unprivileged: it only detects the program (Detect) and
// holds the networks back while it runs. Stopping and restoring need root
// and run as `anix-agent mesh takeover` and `anix-agent mesh restore`, with
// the names given on the command line, never read from a file the Agent's
// user can write.
package mesh

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/common/layout"
)

// DefaultStatePath records what a takeover stopped, for Restore. Its
// directory belongs to root, not the Agent's user: Restore starts what it
// lists.
var DefaultStatePath = filepath.Join("/var/lib", layout.Name+"-mesh", "takeover.json")

// stopWait is how long a process has to exit after SIGTERM before SIGKILL.
var stopWait = 5 * time.Second

// Takeover stops the existing program: first the services' start at boot,
// then the services and the processes. Files and configuration stay, so
// Restore brings the program back.
type Takeover struct {
	// StatePath records the stopped services; empty is DefaultStatePath.
	StatePath string
	// Proc is the proc file system; empty is /proc.
	Proc string
	// Run runs systemctl; nil runs it.
	Run func(args ...string) error
}

// state is what Restore brings back.
type state struct {
	// Services were stopped; Enabled of them also started at boot.
	Services []string `json:"services,omitempty"`
	Enabled  []string `json:"enabled,omitempty"`
}

func (t *Takeover) statePath() string {
	if t.StatePath != "" {
		return t.StatePath
	}
	return DefaultStatePath
}

func (t *Takeover) systemctl(args ...string) error {
	if t.Run != nil {
		return t.Run(args...)
	}
	out, err := exec.Command("systemctl", args...).CombinedOutput() // #nosec G204 -- names are checked by panel.ParseMesh.
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Detect answers what of spec runs now: active services and processes.
// It needs no privileges.
func (t *Takeover) Detect(spec *panel.MeshTakeover) []string {
	if spec.Empty() {
		return nil
	}
	var running []string
	for _, service := range spec.ServiceNames {
		if t.systemctl("is-active", "--quiet", service) == nil {
			running = append(running, "service "+service)
		}
	}
	for _, pid := range t.processes(spec.ProcessNames) {
		running = append(running, "process "+strconv.Itoa(pid))
	}
	return running
}

// Stopped answers the services a takeover stopped and Restore would start.
func (t *Takeover) Stopped() []string {
	saved, _ := t.load()
	return saved.Services
}

// Stop takes the program of spec over (as root). The result lists what was
// stopped; Found also counts configuration files that exist.
func (t *Takeover) Stop(spec *panel.MeshTakeover) panel.MeshTakeoverResult {
	var result panel.MeshTakeoverResult
	if spec.Empty() {
		return result
	}
	saved, err := t.load()
	var errs []error
	if err != nil {
		errs = append(errs, err)
	}
	for _, service := range spec.ServiceNames {
		enabled := t.systemctl("is-enabled", "--quiet", service) == nil
		active := t.systemctl("is-active", "--quiet", service) == nil
		if !enabled && !active {
			continue
		}
		result.Found = true
		if enabled {
			if err := t.systemctl("disable", service); err != nil {
				errs = append(errs, err)
				continue
			}
			saved.Enabled = appendNew(saved.Enabled, service)
		}
		saved.Services = appendNew(saved.Services, service)
		if err := t.systemctl("stop", service); err != nil {
			errs = append(errs, err)
			continue
		}
		result.Stopped = append(result.Stopped, "service "+service)
	}
	if err := t.save(saved); err != nil {
		errs = append(errs, err)
	}
	for _, pid := range t.processes(spec.ProcessNames) {
		result.Found = true
		if err := stopProcess(pid); err != nil {
			errs = append(errs, err)
			continue
		}
		result.Stopped = append(result.Stopped, "process "+strconv.Itoa(pid))
	}
	for _, path := range spec.ConfigPaths {
		if _, err := os.Stat(path); err == nil {
			result.Found = true
		}
	}
	if err := errors.Join(errs...); err != nil {
		result.Error = err.Error()
	}
	return result
}

// Restore starts the services Stop stopped again, at boot too where they
// were, and forgets them. A process started by hand is not restarted.
func (t *Takeover) Restore() ([]string, error) {
	saved, err := t.load()
	if err != nil {
		return nil, err
	}
	var restored []string
	var errs []error
	for _, service := range saved.Services {
		if slices.Contains(saved.Enabled, service) {
			if err := t.systemctl("enable", service); err != nil {
				errs = append(errs, err)
			}
		}
		if err := t.systemctl("start", service); err != nil {
			errs = append(errs, err)
			continue
		}
		restored = append(restored, service)
	}
	if err := errors.Join(errs...); err != nil {
		return restored, err
	}
	if err := os.Remove(t.statePath()); err != nil && !os.IsNotExist(err) {
		return restored, err
	}
	return restored, nil
}

func (t *Takeover) load() (state, error) {
	var saved state
	data, err := os.ReadFile(t.statePath())
	if os.IsNotExist(err) {
		return saved, nil
	}
	if err != nil {
		return saved, err
	}
	if err := json.Unmarshal(data, &saved); err != nil {
		return state{}, fmt.Errorf("%s: %w", t.statePath(), err)
	}
	return saved, nil
}

func (t *Takeover) save(saved state) error {
	if len(saved.Services) == 0 {
		return nil
	}
	data, err := json.Marshal(saved)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(t.statePath()), 0o755); err != nil { // #nosec G301 -- the Agent reads it.
		return err
	}
	// Readable by the Agent, which reports what was stopped.
	return os.WriteFile(t.statePath(), data, 0o644) // #nosec G306 -- names only, no secret.
}

// processes answers the pids whose command name is one of names.
func (t *Takeover) processes(names []string) []int {
	if len(names) == 0 {
		return nil
	}
	proc := t.Proc
	if proc == "" {
		proc = "/proc"
	}
	entries, _ := os.ReadDir(proc)
	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		comm, err := os.ReadFile(filepath.Join(proc, entry.Name(), "comm"))
		if err == nil && slices.Contains(names, strings.TrimSpace(string(comm))) {
			pids = append(pids, pid)
		}
	}
	return pids
}

// stopProcess ends pid: SIGTERM, then SIGKILL after stopWait.
func stopProcess(pid int) error {
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return fmt.Errorf("stop process %d: %w", pid, err)
	}
	for deadline := time.Now().Add(stopWait); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if syscall.Kill(pid, 0) != nil {
			return nil
		}
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("kill process %d: %w", pid, err)
	}
	return nil
}

func appendNew(list []string, value string) []string {
	if slices.Contains(list, value) {
		return list
	}
	return append(list, value)
}
