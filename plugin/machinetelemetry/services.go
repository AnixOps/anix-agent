package machinetelemetry

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AnixOps/anix-control/sdk/telemetry/systemdreport"
)

const (
	// ServicesCollectInterval is how often the systemd services collector
	// samples the units, independent of interval_seconds.
	ServicesCollectInterval = 30 * time.Second
	// ServicesWindow is the averaging window of CPU and memory peaks.
	ServicesWindow = systemdreport.WindowSeconds * time.Second
	// DefaultCgroupRoot is the cgroup v2 unified hierarchy mount point.
	DefaultCgroupRoot = "/sys/fs/cgroup"
	// DefaultSystemdRuntimeDir exists only when systemd is PID 1
	// (sd_booted(3)).
	DefaultSystemdRuntimeDir = "/run/systemd/system"
	servicesListTimeout      = 10 * time.Second
	maxCgroupFileBytes       = 64 << 10
)

// Reasons a node cannot report its services. Each is short printable ASCII
// (systemdreport.MaxReasonLength).
const (
	ReasonNotLinux      = "systemd services are collected on Linux only"
	ReasonNoSystemd     = "systemd is not the init system (no /run/systemd/system)"
	ReasonCgroupV1      = "cgroup v2 is not mounted (cgroup v1 or hybrid hierarchy)"
	ReasonDBusFailed    = "the systemd D-Bus API is unavailable"
	ReasonListingFailed = "listing systemd units failed"
)

// ServiceUnit is what the collector needs of one systemd unit. The D-Bus
// lister never fills in, keeps or forwards any other unit property:
// Description and ExecStart in particular never leave the lister.
type ServiceUnit struct {
	Name        string
	LoadState   string
	ActiveState string
	SubState    string
	// ControlGroup is the unit's cgroup path relative to the cgroup root,
	// such as /system.slice/nginx.service, or empty when it has none.
	ControlGroup string
}

// ServiceLister lists the units of the system manager.
type ServiceLister interface {
	// ListServices returns the loaded units. It may return non-service units;
	// the collector filters them.
	ListServices(ctx context.Context) ([]ServiceUnit, error)
	// ControlGroup returns the ControlGroup property of one unit.
	ControlGroup(ctx context.Context, unit ServiceUnit) (string, error)
	Close() error
}

// ServicesPlatform is where the collector reads from. Tests use a fake
// lister and a temporary cgroupfs tree.
type ServicesPlatform struct {
	// CgroupRoot is the cgroup v2 mount point.
	CgroupRoot string
	// SystemdRuntimeDir is /run/systemd/system on a systemd host.
	SystemdRuntimeDir string
	// Unsupported, when not empty, is the reason this platform cannot
	// collect at all (non-Linux builds).
	Unsupported string
	// Connect opens the D-Bus lister.
	Connect func(ctx context.Context) (ServiceLister, error)
}

// Probe returns "" when the platform can collect, otherwise the reason it
// cannot: systemd and the cgroup v2 unified hierarchy are both required.
func (p ServicesPlatform) Probe() string {
	if p.Unsupported != "" {
		return p.Unsupported
	}
	if info, err := os.Stat(p.SystemdRuntimeDir); err != nil || !info.IsDir() {
		return ReasonNoSystemd
	}
	if info, err := os.Stat(filepath.Join(p.CgroupRoot, "cgroup.controllers")); err != nil || !info.Mode().IsRegular() {
		return ReasonCgroupV1
	}
	return ""
}

// ServicesReport is the latest systemd.services payload of the plugin, the
// exact payload_json Control's systemdreport.Sanitize accepts.
type ServicesReport struct {
	Kind             string
	PayloadJSON      []byte
	ObservedAtUnixMs int64
}

type cgroupSample struct {
	at        time.Time
	usageUsec uint64
	memory    uint64
}

// unitSeries is the 10-minute sample ring of one unit.
type unitSeries struct {
	cgroup string
	// samples hold memory.current too: their maximum is the memory peak on
	// kernels without memory.peak (before 5.19).
	samples  []cgroupSample
	lastSeen time.Time
}

// add appends a sample and drops the samples that fell out of the window.
// A CPU counter that went backwards means a new cgroup (a restart); the
// series then starts again, rather than producing a negative interval.
func (s *unitSeries) add(sample cgroupSample, window time.Duration) {
	if n := len(s.samples); n > 0 {
		last := s.samples[n-1]
		if sample.usageUsec < last.usageUsec || !sample.at.After(last.at) {
			s.samples = s.samples[:0]
		}
	}
	s.samples = append(s.samples, sample)
	cutoff := sample.at.Add(-window)
	drop := 0
	for drop < len(s.samples)-1 && s.samples[drop].at.Before(cutoff) {
		drop++
	}
	if drop > 0 {
		s.samples = append(s.samples[:0], s.samples[drop:]...)
	}
}

// cpu returns the average and the peak CPU use over the window, in percent
// of one CPU: 100 means one CPU fully busy, 400 four. The average is the
// counter's growth over the covered time; the peak is the busiest interval
// between two samples. One sample gives no rate: both are 0.
func (s *unitSeries) cpu() (avg, peak float64) {
	if len(s.samples) < 2 {
		return 0, 0
	}
	first, last := s.samples[0], s.samples[len(s.samples)-1]
	avg = cpuPercent(first, last)
	for index := 1; index < len(s.samples); index++ {
		peak = math.Max(peak, cpuPercent(s.samples[index-1], s.samples[index]))
	}
	return avg, peak
}

func cpuPercent(from, to cgroupSample) float64 {
	elapsed := to.at.Sub(from.at).Microseconds()
	if elapsed <= 0 || to.usageUsec < from.usageUsec {
		return 0
	}
	percent := float64(to.usageUsec-from.usageUsec) / float64(elapsed) * 100
	if math.IsNaN(percent) || math.IsInf(percent, 0) || percent < 0 {
		return 0
	}
	return math.Min(percent, systemdreport.MaxCPUPercent)
}

func (s *unitSeries) memoryMax() uint64 {
	var peak uint64
	for _, sample := range s.samples {
		if sample.memory > peak {
			peak = sample.memory
		}
	}
	return peak
}

// ServicesCollector samples the selected units every ServicesCollectInterval
// and keeps the latest report.
type ServicesCollector struct {
	platform ServicesPlatform
	node     ServicesNodeConfig
	now      func() time.Time

	// mu guards the collection state. Collect holds it across D-Bus calls,
	// so the latest report has its own lock: a slow systemd must not delay
	// the hand-off of the previous report.
	mu     sync.Mutex
	lister ServiceLister
	series map[string]*unitSeries

	latestMu sync.RWMutex
	latest   *ServicesReport
}

// NewServicesCollector returns a collector for one node's settings.
func NewServicesCollector(platform ServicesPlatform, node ServicesNodeConfig, now func() time.Time) *ServicesCollector {
	if now == nil {
		now = time.Now
	}
	return &ServicesCollector{platform: platform, node: node, now: now, series: map[string]*unitSeries{}}
}

// Latest returns the latest report, if one was collected.
func (c *ServicesCollector) Latest() (ServicesReport, bool) {
	if c == nil {
		return ServicesReport{}, false
	}
	c.latestMu.RLock()
	defer c.latestMu.RUnlock()
	if c.latest == nil {
		return ServicesReport{}, false
	}
	report := *c.latest
	report.PayloadJSON = append([]byte(nil), c.latest.PayloadJSON...)
	return report, true
}

// Close releases the D-Bus connection.
func (c *ServicesCollector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lister == nil {
		return nil
	}
	err := c.lister.Close()
	c.lister = nil
	return err
}

// Collect takes one sample of every selected unit and stores the report.
func (c *ServicesCollector) Collect(ctx context.Context) (ServicesReport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	report, err := c.collect(ctx, now)
	if err != nil {
		return ServicesReport{}, err
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return ServicesReport{}, fmt.Errorf("encode systemd services report: %w", err)
	}
	// The same sanitizer Control runs: never hand off a payload Control
	// would refuse, and never one with a field it does not know.
	if _, err := systemdreport.Sanitize(payload); err != nil {
		return ServicesReport{}, fmt.Errorf("systemd services report does not pass the SDK sanitizer: %w", err)
	}
	latest := ServicesReport{Kind: systemdreport.Kind, PayloadJSON: payload, ObservedAtUnixMs: now.UnixMilli()}
	c.latestMu.Lock()
	c.latest = &latest
	c.latestMu.Unlock()
	result := latest
	result.PayloadJSON = append([]byte(nil), payload...)
	return result, nil
}

func unsupportedReport(reason string) systemdreport.Report {
	return systemdreport.Report{
		Supported:         false,
		UnsupportedReason: reason,
		WindowSeconds:     systemdreport.WindowSeconds,
		Units:             []systemdreport.Unit{},
	}
}

func (c *ServicesCollector) collect(ctx context.Context, now time.Time) (systemdreport.Report, error) {
	if reason := c.platform.Probe(); reason != "" {
		c.series = map[string]*unitSeries{}
		return unsupportedReport(reason), nil
	}
	if c.lister == nil {
		if c.platform.Connect == nil {
			return unsupportedReport(ReasonDBusFailed), nil
		}
		connectCtx, cancel := context.WithTimeout(ctx, servicesListTimeout)
		lister, err := c.platform.Connect(connectCtx)
		cancel()
		if err != nil || lister == nil {
			return unsupportedReport(ReasonDBusFailed), nil
		}
		c.lister = lister
	}
	listCtx, cancel := context.WithTimeout(ctx, servicesListTimeout)
	defer cancel()
	units, err := c.lister.ListServices(listCtx)
	if err != nil {
		// Reconnect on the next round: systemd may have been re-executed.
		_ = c.lister.Close()
		c.lister = nil
		if ctx.Err() != nil {
			return systemdreport.Report{}, ctx.Err()
		}
		return unsupportedReport(ReasonListingFailed), nil
	}
	selected := c.selectUnits(units)

	report := systemdreport.Report{
		Supported:     true,
		WindowSeconds: systemdreport.WindowSeconds,
		Units:         make([]systemdreport.Unit, 0, len(selected)),
	}
	for _, unit := range selected {
		if unit.ControlGroup == "" && unit.ActiveState != "inactive" {
			if cgroup, err := c.lister.ControlGroup(listCtx, unit); err == nil {
				unit.ControlGroup = cgroup
			}
		}
		report.Units = append(report.Units, c.sample(unit, now))
	}
	// Forget the units that are gone.
	for name, series := range c.series {
		if series.lastSeen.Before(now) {
			delete(c.series, name)
		}
	}
	return report, nil
}

// selectUnits keeps the collectable, selected, well-formed .service units,
// sorted by name and capped at systemdreport.MaxUnits.
func (c *ServicesCollector) selectUnits(units []ServiceUnit) []ServiceUnit {
	selected := make([]ServiceUnit, 0, len(units))
	seen := make(map[string]struct{}, len(units))
	for _, unit := range units {
		if unit.LoadState == "not-found" || !validReportUnit(unit) || !c.node.Selected(unit.Name) {
			continue
		}
		if _, duplicate := seen[unit.Name]; duplicate {
			continue
		}
		seen[unit.Name] = struct{}{}
		selected = append(selected, ServiceUnit{
			Name: unit.Name, ActiveState: unit.ActiveState, SubState: unit.SubState, ControlGroup: unit.ControlGroup,
		})
	}
	sort.Slice(selected, func(left, right int) bool { return selected[left].Name < selected[right].Name })
	if len(selected) > systemdreport.MaxUnits {
		selected = selected[:systemdreport.MaxUnits]
	}
	return selected
}

var (
	reportUnitNamePattern = regexp.MustCompile(`^[A-Za-z0-9:_.\\@-]+$`)
	reportStatePattern    = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
)

// validReportUnit mirrors systemdreport.Sanitize's per-unit checks, so one
// odd unit is skipped instead of failing the whole report.
func validReportUnit(unit ServiceUnit) bool {
	if unit.Name == "" || len(unit.Name) > systemdreport.MaxNameLength || !reportUnitNamePattern.MatchString(unit.Name) {
		return false
	}
	for _, state := range []string{unit.ActiveState, unit.SubState} {
		if len(state) > systemdreport.MaxStateLength || !reportStatePattern.MatchString(state) {
			return false
		}
	}
	return true
}

// sample reads the unit's cgroup and returns its report line.
func (c *ServicesCollector) sample(unit ServiceUnit, now time.Time) systemdreport.Unit {
	line := systemdreport.Unit{Name: unit.Name, ActiveState: unit.ActiveState, SubState: unit.SubState}
	dir, ok := cgroupDir(c.platform.CgroupRoot, unit.ControlGroup)
	if !ok {
		delete(c.series, unit.Name)
		return line
	}
	usage, err := readCPUUsageUsec(filepath.Join(dir, "cpu.stat"))
	if err != nil {
		delete(c.series, unit.Name)
		return line
	}
	memory, _ := readCgroupUint(filepath.Join(dir, "memory.current"))
	series := c.series[unit.Name]
	if series == nil || series.cgroup != unit.ControlGroup {
		series = &unitSeries{cgroup: unit.ControlGroup}
		c.series[unit.Name] = series
	}
	series.add(cgroupSample{at: now, usageUsec: usage, memory: memory}, ServicesWindow)
	series.lastSeen = now
	line.CPUAvgPercent, line.CPUPeakPercent = series.cpu()
	line.CPUAvgPercent = roundHundredths(line.CPUAvgPercent)
	line.CPUPeakPercent = roundHundredths(line.CPUPeakPercent)
	line.MemoryBytes = memory
	line.MemoryPeakBytes = series.memoryMax()
	// memory.peak (Linux 5.19+) is the cgroup's high-water mark since it
	// was created, which also catches spikes between two samples.
	if peak, err := readCgroupUint(filepath.Join(dir, "memory.peak")); err == nil && peak > line.MemoryPeakBytes {
		line.MemoryPeakBytes = peak
	}
	return line
}

func roundHundredths(value float64) float64 {
	return math.Round(value*100) / 100
}

// cgroupDir resolves a unit's ControlGroup below the cgroup root, refusing
// a path that would leave it.
func cgroupDir(root, controlGroup string) (string, bool) {
	if controlGroup == "" || !strings.HasPrefix(controlGroup, "/") || strings.ContainsRune(controlGroup, 0) {
		return "", false
	}
	cleaned := path.Clean(controlGroup)
	if cleaned == "/" || cleaned != controlGroup || strings.Contains(cleaned, "/../") || strings.HasSuffix(cleaned, "/..") {
		return "", false
	}
	return filepath.Join(root, filepath.FromSlash(cleaned)), true
}

func readCgroupFile(file string) ([]byte, error) {
	handle, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	contents, err := io.ReadAll(io.LimitReader(handle, maxCgroupFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(contents) > maxCgroupFileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", file, maxCgroupFileBytes)
	}
	return contents, nil
}

// readCPUUsageUsec reads usage_usec from a cgroup v2 cpu.stat.
func readCPUUsageUsec(file string) (uint64, error) {
	contents, err := readCgroupFile(file)
	if err != nil {
		return 0, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[0] == "usage_usec" {
			return strconv.ParseUint(fields[1], 10, 64)
		}
	}
	return 0, errors.New("cpu.stat has no usage_usec")
}

// readCgroupUint reads a single-number cgroup file such as memory.current.
func readCgroupUint(file string) (uint64, error) {
	contents, err := readCgroupFile(file)
	if err != nil {
		return 0, err
	}
	value := strings.TrimSpace(string(contents))
	if value == "max" {
		return 0, errors.New("unbounded value")
	}
	return strconv.ParseUint(value, 10, 64)
}

// RunServicesCollector collects immediately and then every
// ServicesCollectInterval until ctx is cancelled.
func RunServicesCollector(ctx context.Context, collector *ServicesCollector, interval time.Duration, logf func(string, ...any)) {
	if interval <= 0 {
		interval = ServicesCollectInterval
	}
	defer collector.Close()
	collectOnce := func() {
		if _, err := collector.Collect(ctx); err != nil && ctx.Err() == nil && logf != nil {
			logf("systemd services collection failed: %v", err)
		}
	}
	collectOnce()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collectOnce()
		}
	}
}
