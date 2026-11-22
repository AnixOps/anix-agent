package node

import (
	"sync"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	log "github.com/sirupsen/logrus"
)

const (
	defaultJobInterval    = 60 * time.Second
	certificateRenewEvery = 24 * time.Hour
)

// job runs a function periodically on one goroutine, so runs never
// overlap. A failing run is logged and the job keeps running.
type job struct {
	interval time.Duration
	ticker   *time.Ticker
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once
}

// startJob runs run every interval, the first time at once when now is set.
func startJob(tag, name string, interval time.Duration, now bool, run func() error) *job {
	j := &job{
		interval: interval,
		ticker:   time.NewTicker(interval),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	runOnce := func() {
		if err := run(); err != nil {
			log.WithFields(log.Fields{"tag": tag, "job": name, "err": err}).Error("Periodic job failed")
		}
	}
	go func() {
		defer close(j.done)
		defer j.ticker.Stop()
		if now {
			runOnce()
		}
		for {
			select {
			case <-j.stop:
				return
			case <-j.ticker.C:
			}
			select {
			case <-j.stop:
				return
			default:
				runOnce()
			}
		}
	}()
	return j
}

// reset makes the job run every interval from now on, when that is
// positive and differs. reconcileMu is held.
func (j *job) reset(interval time.Duration) {
	if j == nil || interval <= 0 || interval == j.interval {
		return
	}
	j.interval = interval
	j.ticker.Reset(interval)
}

// Stop stops the job, after the run in progress. It is safe on a nil job
// and more than once.
func (j *job) Stop() {
	if j == nil {
		return
	}
	j.once.Do(func() { close(j.stop) })
	<-j.done
}

// dynamicSpeedLimit tells whether the node runs the dynamic speed limit.
func (c *Controller) dynamicSpeedLimit() bool {
	return c.LimitConfig.EnableDynamicSpeedLimit && c.LimitConfig.DynamicSpeedLimitConfig != nil
}

// startJobs starts the node's periodic jobs: the report, the certificate
// renewal and the dynamic speed limit check.
func (c *Controller) startJobs(info *panel.NodeInfo) {
	interval := info.PushInterval
	if interval <= 0 {
		interval = defaultJobInterval
	}
	c.reportJob = startJob(c.tag, "report", interval, false, c.reportUserTrafficTask)
	if info.Security == panel.Tls && c.CertConfig != nil && (c.CertConfig.CertMode == "http" || c.CertConfig.CertMode == "dns") {
		c.certJob = startJob(c.tag, "renew certificate", certificateRenewEvery, true, c.renewCertificate)
	}
	if c.dynamicSpeedLimit() {
		c.reconcileMu.Lock()
		c.traffic = make(map[string]int64)
		c.reconcileMu.Unlock()
		periodic := time.Duration(c.LimitConfig.DynamicSpeedLimitConfig.Periodic) * time.Second
		if periodic <= 0 {
			periodic = defaultJobInterval
		}
		c.speedJob = startJob(c.tag, "dynamic speed limit", periodic, false, c.checkDynamicSpeedLimit)
	}
}

// stopJobs stops the periodic jobs.
func (c *Controller) stopJobs() {
	c.reportJob.Stop()
	c.certJob.Stop()
	c.speedJob.Stop()
}

// checkDynamicSpeedLimit penalises every user whose counted traffic
// reached the configured amount and starts counting them again.
func (c *Controller) checkDynamicSpeedLimit() error {
	config := c.LimitConfig.DynamicSpeedLimitConfig
	until := time.Now().Add(time.Duration(config.ExpireTime) * time.Minute)
	c.reconcileMu.Lock()
	for uuid, used := range c.traffic {
		if used >= config.Traffic {
			c.rates.penalize(uuid, config.SpeedLimit, until)
			delete(c.traffic, uuid)
		}
	}
	c.reconcileMu.Unlock()
	c.syncCoreUserRateLimits()
	return nil
}
