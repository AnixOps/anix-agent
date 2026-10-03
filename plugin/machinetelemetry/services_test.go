package machinetelemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AnixOps/anix-control/sdk/telemetry/systemdreport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCgroupfs is a temporary cgroup v2 tree plus /run/systemd/system.
type fakeCgroupfs struct {
	t          *testing.T
	root       string
	cgroupRoot string
	runtimeDir string
}

func newFakeCgroupfs(t *testing.T) *fakeCgroupfs {
	t.Helper()
	root := t.TempDir()
	fs := &fakeCgroupfs{t: t, root: root, cgroupRoot: filepath.Join(root, "sys/fs/cgroup"), runtimeDir: filepath.Join(root, "run/systemd/system")}
	require.NoError(t, os.MkdirAll(fs.cgroupRoot, 0o755))
	require.NoError(t, os.MkdirAll(fs.runtimeDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(fs.cgroupRoot, "cgroup.controllers"), []byte("cpuset cpu io memory pids\n"), 0o644))
	return fs
}

// set writes a unit's cpu.stat usage_usec and memory files. peak < 0 leaves
// memory.peak out (kernels before 5.19).
func (fs *fakeCgroupfs) set(cgroup string, usageUsec, memory uint64, peak int64) {
	fs.t.Helper()
	dir := filepath.Join(fs.cgroupRoot, filepath.FromSlash(cgroup))
	require.NoError(fs.t, os.MkdirAll(dir, 0o755))
	stat := fmt.Sprintf("usage_usec %d\nuser_usec %d\nsystem_usec 0\nnr_periods 0\n", usageUsec, usageUsec)
	require.NoError(fs.t, os.WriteFile(filepath.Join(dir, "cpu.stat"), []byte(stat), 0o644))
	require.NoError(fs.t, os.WriteFile(filepath.Join(dir, "memory.current"), []byte(fmt.Sprintf("%d\n", memory)), 0o644))
	peakPath := filepath.Join(dir, "memory.peak")
	if peak < 0 {
		_ = os.Remove(peakPath)
		return
	}
	require.NoError(fs.t, os.WriteFile(peakPath, []byte(fmt.Sprintf("%d\n", peak)), 0o644))
}

func (fs *fakeCgroupfs) remove(cgroup string) {
	require.NoError(fs.t, os.RemoveAll(filepath.Join(fs.cgroupRoot, filepath.FromSlash(cgroup))))
}

// fakeLister stands in for systemd's D-Bus API.
type fakeLister struct {
	mu        sync.Mutex
	units     []ServiceUnit
	cgroups   map[string]string
	listErr   error
	closed    int
	cgroupGet []string
}

func (f *fakeLister) ListServices(context.Context) ([]ServiceUnit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]ServiceUnit(nil), f.units...), nil
}

func (f *fakeLister) ControlGroup(_ context.Context, unit ServiceUnit) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cgroupGet = append(f.cgroupGet, unit.Name)
	cgroup, ok := f.cgroups[unit.Name]
	if !ok {
		return "", errors.New("no such unit")
	}
	return cgroup, nil
}

func (f *fakeLister) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
	return nil
}

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time                 { return c.now }
func (c *fakeClock) Advance(duration time.Duration) { c.now = c.now.Add(duration) }

func running(name string) ServiceUnit {
	return ServiceUnit{Name: name, LoadState: "loaded", ActiveState: "active", SubState: "running"}
}

func (fs *fakeCgroupfs) platform(lister ServiceLister) ServicesPlatform {
	return ServicesPlatform{
		CgroupRoot:        fs.cgroupRoot,
		SystemdRuntimeDir: fs.runtimeDir,
		Connect:           func(context.Context) (ServiceLister, error) { return lister, nil },
	}
}

func decodeReport(t *testing.T, report ServicesReport) systemdreport.Report {
	t.Helper()
	require.Equal(t, systemdreport.Kind, report.Kind)
	sanitized, err := systemdreport.Sanitize(report.PayloadJSON)
	require.NoError(t, err)
	return sanitized
}

func unitByName(t *testing.T, report systemdreport.Report, name string) systemdreport.Unit {
	t.Helper()
	for _, unit := range report.Units {
		if unit.Name == name {
			return unit
		}
	}
	t.Fatalf("unit %s is not in the report", name)
	return systemdreport.Unit{}
}

func TestServicesCollectorComputesWindowedCPUAndMemory(t *testing.T) {
	fs := newFakeCgroupfs(t)
	lister := &fakeLister{
		units:   []ServiceUnit{running("nginx.service")},
		cgroups: map[string]string{"nginx.service": "/system.slice/nginx.service"},
	}
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	collector := NewServicesCollector(fs.platform(lister), ServicesNodeConfig{Enabled: true}, clock.Now)

	// First sample: no interval yet, so no CPU rate.
	fs.set("/system.slice/nginx.service", 1_000_000, 50<<20, -1)
	report, err := collector.Collect(context.Background())
	require.NoError(t, err)
	assert.Equal(t, clock.now.UnixMilli(), report.ObservedAtUnixMs)
	parsed := decodeReport(t, report)
	require.True(t, parsed.Supported)
	assert.Equal(t, systemdreport.WindowSeconds, parsed.WindowSeconds)
	nginx := unitByName(t, parsed, "nginx.service")
	assert.Zero(t, nginx.CPUAvgPercent)
	assert.Zero(t, nginx.CPUPeakPercent)
	assert.Equal(t, uint64(50<<20), nginx.MemoryBytes)
	assert.Equal(t, uint64(50<<20), nginx.MemoryPeakBytes)

	// 30 s later the unit used 3 s of CPU: 10% of one CPU.
	clock.Advance(30 * time.Second)
	fs.set("/system.slice/nginx.service", 4_000_000, 80<<20, -1)
	parsed = decodeReport(t, mustCollect(t, collector))
	nginx = unitByName(t, parsed, "nginx.service")
	assert.InDelta(t, 10, nginx.CPUAvgPercent, 0.001)
	assert.InDelta(t, 10, nginx.CPUPeakPercent, 0.001)

	// Then 60 s at two full CPUs (120 s of CPU): 200%. Over the 90 s the
	// average is (3 + 120) s / 90 s = 136.67%; the peak is 200%.
	clock.Advance(60 * time.Second)
	fs.set("/system.slice/nginx.service", 124_000_000, 60<<20, -1)
	parsed = decodeReport(t, mustCollect(t, collector))
	nginx = unitByName(t, parsed, "nginx.service")
	assert.InDelta(t, 136.67, nginx.CPUAvgPercent, 0.001)
	assert.InDelta(t, 200, nginx.CPUPeakPercent, 0.001)
	assert.Equal(t, uint64(60<<20), nginx.MemoryBytes, "current memory")
	assert.Equal(t, uint64(80<<20), nginx.MemoryPeakBytes, "max observed without memory.peak")

	// memory.peak (5.19+) is used when it is higher than what was sampled.
	clock.Advance(30 * time.Second)
	fs.set("/system.slice/nginx.service", 124_000_000, 60<<20, 200<<20)
	parsed = decodeReport(t, mustCollect(t, collector))
	nginx = unitByName(t, parsed, "nginx.service")
	assert.Equal(t, uint64(200<<20), nginx.MemoryPeakBytes)
	assert.InDelta(t, 0, unitCPUAt(t, collector, "nginx.service"), 0.001)
}

// unitCPUAt returns the last interval's rate of a unit.
func unitCPUAt(t *testing.T, collector *ServicesCollector, name string) float64 {
	t.Helper()
	series := collector.series[name]
	require.NotNil(t, series)
	require.GreaterOrEqual(t, len(series.samples), 2)
	return cpuPercent(series.samples[len(series.samples)-2], series.samples[len(series.samples)-1])
}

func mustCollect(t *testing.T, collector *ServicesCollector) ServicesReport {
	t.Helper()
	report, err := collector.Collect(context.Background())
	require.NoError(t, err)
	return report
}

func TestServicesWindowDropsOldSamples(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	series := &unitSeries{}
	// A busy first minute (one full CPU), then 10 idle minutes.
	series.add(cgroupSample{at: start, usageUsec: 0, memory: 900}, ServicesWindow)
	series.add(cgroupSample{at: start.Add(time.Minute), usageUsec: 60_000_000, memory: 100}, ServicesWindow)
	avg, peak := series.cpu()
	assert.InDelta(t, 100, avg, 0.001)
	assert.InDelta(t, 100, peak, 0.001)
	for minute := 2; minute <= 12; minute++ {
		series.add(cgroupSample{at: start.Add(time.Duration(minute) * time.Minute), usageUsec: 60_000_000, memory: 100}, ServicesWindow)
	}
	avg, peak = series.cpu()
	assert.Zero(t, avg, "the busy minute left the 10-minute window")
	assert.Zero(t, peak)
	assert.Equal(t, uint64(100), series.memoryMax(), "the old memory high left the window")
	first, last := series.samples[0], series.samples[len(series.samples)-1]
	assert.Equal(t, ServicesWindow, last.at.Sub(first.at))

	// 30-second samples over the window: at most 21 are kept.
	series = &unitSeries{}
	for index := 0; index < 100; index++ {
		series.add(cgroupSample{at: start.Add(time.Duration(index) * ServicesCollectInterval), usageUsec: uint64(index) * 1_000_000}, ServicesWindow)
	}
	assert.Len(t, series.samples, 21)
	avg, peak = series.cpu()
	assert.InDelta(t, 3.333, avg, 0.001)
	assert.InDelta(t, 3.333, peak, 0.001)
}

func TestServicesSeriesRestartsWhenTheCounterGoesBack(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	series := &unitSeries{}
	series.add(cgroupSample{at: start, usageUsec: 50_000_000}, ServicesWindow)
	series.add(cgroupSample{at: start.Add(30 * time.Second), usageUsec: 80_000_000}, ServicesWindow)
	// The service restarted into a new cgroup: its counter starts again.
	series.add(cgroupSample{at: start.Add(60 * time.Second), usageUsec: 1_000_000}, ServicesWindow)
	require.Len(t, series.samples, 1)
	avg, peak := series.cpu()
	assert.Zero(t, avg)
	assert.Zero(t, peak)
	series.add(cgroupSample{at: start.Add(90 * time.Second), usageUsec: 4_000_000}, ServicesWindow)
	avg, peak = series.cpu()
	assert.InDelta(t, 10, avg, 0.001)
	assert.InDelta(t, 10, peak, 0.001)
}

func TestCPUPercentIsCappedAndNeverNegative(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	from := cgroupSample{at: start, usageUsec: 0}
	assert.Equal(t, float64(systemdreport.MaxCPUPercent), cpuPercent(from, cgroupSample{at: start.Add(time.Second), usageUsec: 1 << 62}))
	assert.Zero(t, cpuPercent(cgroupSample{at: start, usageUsec: 10}, cgroupSample{at: start.Add(time.Second), usageUsec: 5}))
	assert.Zero(t, cpuPercent(from, cgroupSample{at: start, usageUsec: 5}))
}

func TestServicesCollectorFiltersAndCapsUnits(t *testing.T) {
	fs := newFakeCgroupfs(t)
	units := []ServiceUnit{
		running("nginx.service"),
		running("nginx-debug.service"),
		running("sshd.service"),
		running("cron.service"),
		running("user@1000.service"),
		running("run-r1234.service"),
		running("session-3.scope"),
		running("docker.socket"),
		running("init.scope"),
		{Name: "ghost.service", LoadState: "not-found", ActiveState: "inactive", SubState: "dead"},
		{Name: "bad name.service", LoadState: "loaded", ActiveState: "active", SubState: "running"},
		{Name: "weird.service", LoadState: "loaded", ActiveState: "Active", SubState: "running"},
		running("nginx.service"), // listed twice
	}
	lister := &fakeLister{units: units, cgroups: map[string]string{}}
	collector := NewServicesCollector(fs.platform(lister), ServicesNodeConfig{Enabled: true}, nil)
	parsed := decodeReport(t, mustCollect(t, collector))
	names := make([]string, 0, len(parsed.Units))
	for _, unit := range parsed.Units {
		names = append(names, unit.Name)
	}
	assert.Equal(t, []string{"cron.service", "nginx-debug.service", "nginx.service", "sshd.service"}, names)

	node := ServicesNodeConfig{Enabled: true, Include: []string{"nginx*.service", "ssh?.service"}, Exclude: []string{"*-debug.service"}}
	collector = NewServicesCollector(fs.platform(lister), node, nil)
	parsed = decodeReport(t, mustCollect(t, collector))
	names = names[:0]
	for _, unit := range parsed.Units {
		names = append(names, unit.Name)
	}
	assert.Equal(t, []string{"nginx.service", "sshd.service"}, names)

	// More than 512 selected units: the first 512 by name are reported.
	many := make([]ServiceUnit, 0, systemdreport.MaxUnits+40)
	for index := systemdreport.MaxUnits + 39; index >= 0; index-- {
		many = append(many, running(fmt.Sprintf("unit-%04d.service", index)))
	}
	lister = &fakeLister{units: many, cgroups: map[string]string{}}
	collector = NewServicesCollector(fs.platform(lister), ServicesNodeConfig{Enabled: true}, nil)
	parsed = decodeReport(t, mustCollect(t, collector))
	require.Len(t, parsed.Units, systemdreport.MaxUnits)
	assert.Equal(t, "unit-0000.service", parsed.Units[0].Name)
	assert.Equal(t, fmt.Sprintf("unit-%04d.service", systemdreport.MaxUnits-1), parsed.Units[len(parsed.Units)-1].Name)
	assert.LessOrEqual(t, len(lister.cgroupGet), systemdreport.MaxUnits, "cgroups are read only for reported units")
}

func TestServicesReportCarriesOnlyTheWhitelistedFields(t *testing.T) {
	fs := newFakeCgroupfs(t)
	fs.set("/system.slice/nginx.service", 1, 2, 3)
	lister := &fakeLister{units: []ServiceUnit{running("nginx.service")}, cgroups: map[string]string{"nginx.service": "/system.slice/nginx.service"}}
	report := mustCollect(t, NewServicesCollector(fs.platform(lister), ServicesNodeConfig{Enabled: true}, nil))

	var document map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(report.PayloadJSON, &document))
	keys := make([]string, 0, len(document))
	for key := range document {
		keys = append(keys, key)
	}
	assert.ElementsMatch(t, []string{"supported", "window_seconds", "units"}, keys)
	var units []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(document["units"], &units))
	require.Len(t, units, 1)
	unitKeys := make([]string, 0, len(units[0]))
	for key := range units[0] {
		unitKeys = append(unitKeys, key)
	}
	assert.ElementsMatch(t, []string{"name", "active_state", "sub_state", "cpu_avg_percent", "cpu_peak_percent", "memory_bytes", "memory_peak_bytes"}, unitKeys)
	lower := strings.ToLower(string(report.PayloadJSON))
	assert.NotContains(t, lower, "description")
	assert.NotContains(t, lower, "exec")
}

func TestServicesCollectorHandlesUnitsWithoutACgroup(t *testing.T) {
	fs := newFakeCgroupfs(t)
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	lister := &fakeLister{
		units: []ServiceUnit{
			running("nginx.service"),
			{Name: "backup.service", LoadState: "loaded", ActiveState: "inactive", SubState: "dead"},
			{Name: "broken.service", LoadState: "loaded", ActiveState: "failed", SubState: "failed"},
			running("escape.service"),
		},
		cgroups: map[string]string{
			"nginx.service":  "/system.slice/nginx.service",
			"broken.service": "",
			"escape.service": "/../../etc",
		},
	}
	fs.set("/system.slice/nginx.service", 0, 10, -1)
	collector := NewServicesCollector(fs.platform(lister), ServicesNodeConfig{Enabled: true}, clock.Now)
	parsed := decodeReport(t, mustCollect(t, collector))
	assert.NotContains(t, lister.cgroupGet, "backup.service", "inactive units have no cgroup to read")
	for _, name := range []string{"backup.service", "broken.service", "escape.service"} {
		unit := unitByName(t, parsed, name)
		assert.Zero(t, unit.MemoryBytes, name)
		assert.Zero(t, unit.CPUAvgPercent, name)
	}
	assert.Equal(t, "failed", unitByName(t, parsed, "broken.service").ActiveState)

	// The unit stops and its cgroup goes away; its series is dropped.
	clock.Advance(30 * time.Second)
	fs.remove("/system.slice/nginx.service")
	parsed = decodeReport(t, mustCollect(t, collector))
	assert.Zero(t, unitByName(t, parsed, "nginx.service").MemoryBytes)
	assert.NotContains(t, collector.series, "nginx.service")

	// A unit that is no longer listed is forgotten.
	fs.set("/system.slice/nginx.service", 0, 10, -1)
	mustCollect(t, collector)
	require.Contains(t, collector.series, "nginx.service")
	lister.mu.Lock()
	lister.units = lister.units[1:]
	lister.mu.Unlock()
	clock.Advance(30 * time.Second)
	mustCollect(t, collector)
	assert.NotContains(t, collector.series, "nginx.service")
}

func TestCgroupDirStaysBelowTheRoot(t *testing.T) {
	root := filepath.FromSlash("/sys/fs/cgroup")
	dir, ok := cgroupDir(root, "/system.slice/nginx.service")
	require.True(t, ok)
	assert.Equal(t, filepath.Join(root, "system.slice", "nginx.service"), dir)
	for _, bad := range []string{"", "/", "system.slice/x.service", "/../etc", "/system.slice/../../etc", "/a//b", "/a/./b", "/a/b/", "/a\x00b"} {
		_, ok := cgroupDir(root, bad)
		assert.False(t, ok, bad)
	}
}

func TestCgroupFileParsing(t *testing.T) {
	dir := t.TempDir()
	stat := filepath.Join(dir, "cpu.stat")
	require.NoError(t, os.WriteFile(stat, []byte("user_usec 5\nusage_usec 12345\n"), 0o644))
	usage, err := readCPUUsageUsec(stat)
	require.NoError(t, err)
	assert.Equal(t, uint64(12345), usage)
	require.NoError(t, os.WriteFile(stat, []byte("user_usec 5\n"), 0o644))
	_, err = readCPUUsageUsec(stat)
	require.Error(t, err)

	current := filepath.Join(dir, "memory.current")
	require.NoError(t, os.WriteFile(current, []byte("4096\n"), 0o644))
	value, err := readCgroupUint(current)
	require.NoError(t, err)
	assert.Equal(t, uint64(4096), value)
	require.NoError(t, os.WriteFile(current, []byte("max\n"), 0o644))
	_, err = readCgroupUint(current)
	require.Error(t, err)
	require.NoError(t, os.WriteFile(current, []byte(strings.Repeat("1", maxCgroupFileBytes+1)), 0o644))
	_, err = readCgroupUint(current)
	require.Error(t, err)
}

func TestServicesUnsupportedPaths(t *testing.T) {
	assertUnsupported := func(t *testing.T, platform ServicesPlatform, reason string) {
		t.Helper()
		parsed := decodeReport(t, mustCollect(t, NewServicesCollector(platform, ServicesNodeConfig{Enabled: true}, nil)))
		assert.False(t, parsed.Supported)
		assert.Equal(t, reason, parsed.UnsupportedReason)
		assert.Empty(t, parsed.Units)
		assert.LessOrEqual(t, len(reason), systemdreport.MaxReasonLength)
	}
	lister := &fakeLister{units: []ServiceUnit{running("nginx.service")}}

	t.Run("not linux", func(t *testing.T) {
		assertUnsupported(t, ServicesPlatform{Unsupported: ReasonNotLinux}, ReasonNotLinux)
	})
	t.Run("no systemd (Alpine/OpenRC)", func(t *testing.T) {
		fs := newFakeCgroupfs(t)
		require.NoError(t, os.RemoveAll(fs.runtimeDir))
		assertUnsupported(t, fs.platform(lister), ReasonNoSystemd)
	})
	t.Run("cgroup v1", func(t *testing.T) {
		fs := newFakeCgroupfs(t)
		require.NoError(t, os.Remove(filepath.Join(fs.cgroupRoot, "cgroup.controllers")))
		require.NoError(t, os.MkdirAll(filepath.Join(fs.cgroupRoot, "cpu,cpuacct"), 0o755))
		assertUnsupported(t, fs.platform(lister), ReasonCgroupV1)
	})
	t.Run("hybrid hierarchy", func(t *testing.T) {
		fs := newFakeCgroupfs(t)
		require.NoError(t, os.Remove(filepath.Join(fs.cgroupRoot, "cgroup.controllers")))
		unified := filepath.Join(fs.cgroupRoot, "unified")
		require.NoError(t, os.MkdirAll(unified, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(unified, "cgroup.controllers"), nil, 0o644))
		assertUnsupported(t, fs.platform(lister), ReasonCgroupV1)
	})
	t.Run("no D-Bus", func(t *testing.T) {
		fs := newFakeCgroupfs(t)
		platform := fs.platform(nil)
		platform.Connect = func(context.Context) (ServiceLister, error) { return nil, errors.New("no bus") }
		assertUnsupported(t, platform, ReasonDBusFailed)
	})
	t.Run("listing fails, then recovers", func(t *testing.T) {
		fs := newFakeCgroupfs(t)
		failing := &fakeLister{listErr: errors.New("systemd re-executing")}
		connects := 0
		platform := fs.platform(nil)
		platform.Connect = func(context.Context) (ServiceLister, error) {
			connects++
			return failing, nil
		}
		collector := NewServicesCollector(platform, ServicesNodeConfig{Enabled: true}, nil)
		parsed := decodeReport(t, mustCollect(t, collector))
		assert.False(t, parsed.Supported)
		assert.Equal(t, ReasonListingFailed, parsed.UnsupportedReason)
		assert.Equal(t, 1, failing.closed, "a failed connection is closed and reopened")
		failing.mu.Lock()
		failing.listErr = nil
		failing.units = []ServiceUnit{running("nginx.service")}
		failing.mu.Unlock()
		parsed = decodeReport(t, mustCollect(t, collector))
		assert.True(t, parsed.Supported)
		assert.Equal(t, 2, connects)
	})
}

func TestRunServicesCollectorStopsAndCloses(t *testing.T) {
	fs := newFakeCgroupfs(t)
	lister := &fakeLister{units: []ServiceUnit{running("nginx.service")}}
	collector := NewServicesCollector(fs.platform(lister), ServicesNodeConfig{Enabled: true}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunServicesCollector(ctx, collector, time.Hour, nil)
	}()
	require.Eventually(t, func() bool {
		_, ok := collector.Latest()
		return ok
	}, 2*time.Second, 10*time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("collector did not stop")
	}
	assert.Equal(t, 1, lister.closed)
}

// blockingLister holds ListServices until released, like a hung systemd.
type blockingLister struct {
	fakeLister
	entered chan struct{}
	release chan struct{}
}

func (b *blockingLister) ListServices(ctx context.Context) ([]ServiceUnit, error) {
	b.entered <- struct{}{}
	<-b.release
	return b.fakeLister.ListServices(ctx)
}

func TestLatestDoesNotWaitForASlowCollection(t *testing.T) {
	fs := newFakeCgroupfs(t)
	lister := &blockingLister{fakeLister: fakeLister{units: []ServiceUnit{running("nginx.service")}}, entered: make(chan struct{}, 2), release: make(chan struct{}, 2)}
	collector := NewServicesCollector(fs.platform(lister), ServicesNodeConfig{Enabled: true}, nil)
	lister.release <- struct{}{}
	mustCollect(t, collector)
	<-lister.entered

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = collector.Collect(context.Background())
	}()
	<-lister.entered
	report, ok := collector.Latest()
	require.True(t, ok, "the previous report is served while a collection is in progress")
	decodeReport(t, report)
	lister.release <- struct{}{}
	<-done
}
