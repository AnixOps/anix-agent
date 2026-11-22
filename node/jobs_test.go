package node

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJobRunsEveryIntervalAndSurvivesErrors(t *testing.T) {
	var runs, running, overlaps atomic.Int32
	j := startJob("job-tag", "test", 10*time.Millisecond, false, func() error {
		if running.Add(1) > 1 {
			overlaps.Add(1)
		}
		defer running.Add(-1)
		time.Sleep(15 * time.Millisecond)
		runs.Add(1)
		return errors.New("failing run")
	})
	require.Eventually(t, func() bool { return runs.Load() >= 3 }, 5*time.Second, 5*time.Millisecond)
	j.Stop()
	stopped := runs.Load()
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, stopped, runs.Load(), "no run after Stop")
	assert.Zero(t, overlaps.Load(), "runs never overlap")
	j.Stop() // twice
	var never *job
	never.Stop()
	never.reset(time.Second)
}

func TestJobFirstRun(t *testing.T) {
	ran := make(chan struct{}, 1)
	now := startJob("job-tag", "now", time.Hour, true, func() error { ran <- struct{}{}; return nil })
	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("a job with a first run at once did not run")
	}
	now.Stop()

	var runs atomic.Int32
	later := startJob("job-tag", "later", time.Hour, false, func() error { runs.Add(1); return nil })
	time.Sleep(30 * time.Millisecond)
	later.Stop()
	assert.Zero(t, runs.Load(), "the first run is after one interval")
}

func TestJobStopWaitsForTheRunInProgress(t *testing.T) {
	started, finished := make(chan struct{}), atomic.Bool{}
	j := startJob("job-tag", "slow", time.Millisecond, false, func() error {
		select {
		case <-started:
		default:
			close(started)
		}
		time.Sleep(50 * time.Millisecond)
		finished.Store(true)
		return nil
	})
	<-started
	j.Stop()
	assert.True(t, finished.Load())
}

func TestJobReset(t *testing.T) {
	var runs atomic.Int32
	j := startJob("job-tag", "reset", time.Hour, false, func() error { runs.Add(1); return nil })
	t.Cleanup(j.Stop)
	j.reset(0)
	j.reset(time.Hour)
	assert.Equal(t, time.Hour, j.interval)
	j.reset(5 * time.Millisecond)
	assert.Equal(t, 5*time.Millisecond, j.interval)
	require.Eventually(t, func() bool { return runs.Load() >= 2 }, 5*time.Second, 5*time.Millisecond)
}

// rateCore is a recordingCore that applies rate limits itself.
type rateCore struct {
	*recordingCore
	rates map[string]int
}

func (c *rateCore) UpdateUserRateLimit(_, uuid string, bytesPerSecond int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rates[uuid] = bytesPerSecond
	return nil
}

func (c *rateCore) rate(uuid string) (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rate, ok := c.rates[uuid]
	return rate, ok
}

func dynamicController(core *rateCore) *Controller {
	users := []panel.UserInfo{{Id: 1, Uuid: "heavy"}, {Id: 2, Uuid: "light", SpeedLimit: 8}}
	return &Controller{
		server: core, tag: "speed-tag", userList: users,
		Options: &conf.Options{LimitConfig: conf.LimitConfig{
			SpeedLimit: 80, EnableDynamicSpeedLimit: true,
			DynamicSpeedLimitConfig: &conf.DynamicSpeedLimitConfig{Periodic: 1, Traffic: 1000, SpeedLimit: 4, ExpireTime: 10},
		}},
		rates:   newRateLimits(80, users),
		traffic: map[string]int64{"heavy": 1000, "light": 999},
	}
}

func TestDynamicSpeedLimitPenalisesHeavyUsers(t *testing.T) {
	core := &rateCore{recordingCore: newRecordingCore(), rates: map[string]int{}}
	controller := dynamicController(core)
	require.NoError(t, controller.checkDynamicSpeedLimit())
	assert.Equal(t, map[string]int64{"light": 999}, controller.traffic, "a penalised user is counted again")
	assert.Equal(t, 500_000, controller.rates.rate("heavy"))
	assert.Equal(t, 1_000_000, controller.rates.rate("light"))
	heavy, _ := core.rate("heavy")
	light, _ := core.rate("light")
	assert.Equal(t, 500_000, heavy, "the core gets the penalty")
	assert.Equal(t, 1_000_000, light)
}

func TestStartJobsStartsTheConfiguredJobs(t *testing.T) {
	core := &rateCore{recordingCore: newRecordingCore(), rates: map[string]int{}}
	controller := dynamicController(core)
	controller.CertConfig = &conf.CertConfig{CertMode: "dns"}
	info := &panel.NodeInfo{PushInterval: time.Hour}
	controller.startJobs(info)
	assert.NotNil(t, controller.reportJob)
	assert.Nil(t, controller.certJob, "no renewal for a node without TLS")
	require.NotNil(t, controller.speedJob)
	assert.Equal(t, time.Second, controller.speedJob.interval)
	controller.reconcileMu.Lock()
	assert.Empty(t, controller.traffic, "starting the speed check resets the counter")
	controller.reconcileMu.Unlock()
	controller.stopJobs()
	controller.stopJobs()

	plain := &Controller{server: newRecordingCore(), Options: &conf.Options{LimitConfig: conf.LimitConfig{EnableDynamicSpeedLimit: true}}}
	plain.startJobs(&panel.NodeInfo{})
	assert.Equal(t, defaultJobInterval, plain.reportJob.interval, "a node without a push interval")
	assert.Nil(t, plain.speedJob, "the dynamic speed limit needs its configuration")
	plain.stopJobs()

	// A TLS node with an ACME certificate renews it at once and then daily;
	// a failing renewal is logged only.
	tls := &Controller{server: newRecordingCore(), Options: &conf.Options{CertConfig: &conf.CertConfig{
		CertMode: "http", CertFile: t.TempDir() + "/missing.pem", KeyFile: t.TempDir() + "/missing.key"}}}
	tls.startJobs(&panel.NodeInfo{Security: panel.Tls, PushInterval: time.Hour})
	require.NotNil(t, tls.certJob)
	assert.Equal(t, certificateRenewEvery, tls.certJob.interval)
	tls.stopJobs()
}

func TestReconcileRestartsTheReportJobOnANewInterval(t *testing.T) {
	core := newReloadCore()
	controller := runningController(t, core, vlessNode(443))
	controller.reportJob = startJob(controller.tag, "report", time.Hour, false, func() error { return nil })
	controller.traffic = map[string]int64{"user-1": 5}
	t.Cleanup(controller.stopJobs)

	next := vlessNode(8443)
	next.PushInterval = 2 * time.Hour
	require.NoError(t, reconcile(controller, next, nil))
	assert.Equal(t, 2*time.Hour, controller.reportJob.interval)
	assert.Empty(t, controller.traffic, "a changed node resets the speed counter")

	// No interval: the job keeps its own.
	next = vlessNode(9443)
	next.PushInterval = 0
	require.NoError(t, reconcile(controller, next, nil))
	assert.Equal(t, 2*time.Hour, controller.reportJob.interval)
}
