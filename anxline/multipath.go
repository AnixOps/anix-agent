package anxline

import (
	"context"
	"slices"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// PathStatus is the state of one watched MPTCP path.
type PathStatus struct {
	Link     string `json:"link"`
	Endpoint int    `json:"endpoint"`
	Addr     string `json:"addr"`
	// Healthy is the probes' verdict; Demoted means the Agent took the
	// endpoint out (deleted it or marked it backup).
	Healthy  bool      `json:"healthy"`
	Demoted  bool      `json:"demoted"`
	Since    time.Time `json:"since"`
	LastErr  string    `json:"last_error,omitempty"`
	Demotes  int       `json:"demotes"`
	Restores int       `json:"restores"`
}

type pathState struct {
	path      Path
	healthy   bool
	demoted   bool
	failures  int
	successes int
	since     time.Time
	lastErr   string
	demotes   int
	restores  int
}

// monitor probes the paths of one multipath link.
type monitor struct {
	link   string
	mp     Multipath
	ip     string
	runner Runner
	prober Prober
	now    func() time.Time

	mu    sync.Mutex
	paths []*pathState
	stop  chan struct{}
	done  chan struct{}
}

func newMonitor(link string, mp Multipath, ip string, runner Runner, prober Prober, now func() time.Time) *monitor {
	m := &monitor{link: link, mp: mp, ip: ip, runner: runner, prober: prober, now: now}
	for _, path := range mp.Paths {
		m.paths = append(m.paths, &pathState{path: path, healthy: true, since: now()})
	}
	return m
}

// ensureEndpoints adds the endpoints the kernel does not have yet; existing
// ones are left alone so an Agent restart does not drop live subflows.
func (m *monitor) ensureEndpoints(ctx context.Context) error {
	for _, state := range m.paths {
		id := strconv.Itoa(state.path.Endpoint)
		if _, err := m.runner.Run(ctx, "", m.ip, "mptcp", "endpoint", "show", "id", id); err == nil {
			continue
		}
		if err := m.addEndpoint(ctx, state.path); err != nil {
			return err
		}
	}
	return nil
}

func (m *monitor) addEndpoint(ctx context.Context, path Path) error {
	args := []string{"mptcp", "endpoint", "add", path.Addr}
	if path.Dev != "" {
		args = append(args, "dev", path.Dev)
	}
	args = append(args, "id", strconv.Itoa(path.Endpoint))
	args = append(args, path.flags()...)
	_, err := m.runner.Run(ctx, "", m.ip, args...)
	return err
}

func (m *monitor) start() {
	m.stop = make(chan struct{})
	m.done = make(chan struct{})
	go func() {
		defer close(m.done)
		ticker := time.NewTicker(m.mp.interval())
		defer ticker.Stop()
		for {
			select {
			case <-m.stop:
				return
			case <-ticker.C:
				m.check(context.Background())
			}
		}
	}()
}

// close stops probing and gives the kernel back every endpoint the Agent
// took out: without the Agent nobody would restore them.
func (m *monitor) close(ctx context.Context) {
	if m.stop != nil {
		close(m.stop)
		<-m.done
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, state := range m.paths {
		if state.demoted {
			m.restore(ctx, state)
		}
	}
}

// check runs one probe round on every path in parallel, then demotes the
// paths that failed FailAfter times in a row and restores the ones that
// succeeded RecoverAfter times in a row.
func (m *monitor) check(ctx context.Context) {
	results := make([]error, len(m.paths))
	var wg sync.WaitGroup
	for i, state := range m.paths {
		wg.Add(1)
		go func() {
			defer wg.Done()
			probeCtx, cancel := context.WithTimeout(ctx, m.mp.timeout())
			defer cancel()
			results[i] = m.prober.Probe(probeCtx, state.path, m.mp.timeout())
		}()
	}
	wg.Wait()

	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for i, state := range m.paths {
		if err := results[i]; err != nil {
			state.successes = 0
			state.failures++
			state.lastErr = err.Error()
			if state.healthy && state.failures >= m.mp.failAfter() {
				state.healthy = false
				state.since = now
			}
		} else {
			state.failures = 0
			state.successes++
			state.lastErr = ""
			if !state.healthy && state.successes >= m.mp.recoverAfter() {
				state.healthy = true
				state.since = now
			}
		}
	}
	for _, state := range m.paths {
		switch {
		case !state.healthy && !state.demoted:
			// Keep the last path in: with every path dead, taking all out
			// only stops the kernel from retrying.
			if !m.otherUsable(state) {
				continue
			}
			m.demote(ctx, state)
		case state.healthy && state.demoted:
			m.restore(ctx, state)
		}
	}
}

func (m *monitor) otherUsable(self *pathState) bool {
	for _, state := range m.paths {
		if state != self && state.healthy && !state.demoted {
			return true
		}
	}
	return false
}

func (m *monitor) demote(ctx context.Context, state *pathState) {
	id := strconv.Itoa(state.path.Endpoint)
	var err error
	switch m.mp.action() {
	case ActionBackup:
		if slices.Contains(state.path.flags(), "backup") {
			return
		}
		_, err = m.runner.Run(ctx, "", m.ip, "mptcp", "endpoint", "change", "id", id, "backup")
	default:
		_, err = m.runner.Run(ctx, "", m.ip, "mptcp", "endpoint", "delete", "id", id)
	}
	fields := log.Fields{"link": m.link, "endpoint": state.path.Endpoint, "addr": state.path.Addr, "action": m.mp.action(), "probe_err": state.lastErr}
	if err != nil {
		log.WithFields(fields).WithError(err).Error("ANX-Line: taking a dead MPTCP path out failed")
		return
	}
	state.demoted = true
	state.demotes++
	log.WithFields(fields).Warn("ANX-Line: MPTCP path dead, taken out")
}

func (m *monitor) restore(ctx context.Context, state *pathState) {
	var err error
	switch m.mp.action() {
	case ActionBackup:
		_, err = m.runner.Run(ctx, "", m.ip, "mptcp", "endpoint", "change", "id", strconv.Itoa(state.path.Endpoint), "nobackup")
	default:
		err = m.addEndpoint(ctx, state.path)
	}
	fields := log.Fields{"link": m.link, "endpoint": state.path.Endpoint, "addr": state.path.Addr, "action": m.mp.action()}
	if err != nil {
		log.WithFields(fields).WithError(err).Error("ANX-Line: restoring an MPTCP path failed")
		return
	}
	state.demoted = false
	state.restores++
	log.WithFields(fields).Info("ANX-Line: MPTCP path recovered, restored")
}

func (m *monitor) status() []PathStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PathStatus, 0, len(m.paths))
	for _, state := range m.paths {
		out = append(out, PathStatus{
			Link: m.link, Endpoint: state.path.Endpoint, Addr: state.path.Addr,
			Healthy: state.healthy, Demoted: state.demoted, Since: state.since,
			LastErr: state.lastErr, Demotes: state.demotes, Restores: state.restores,
		})
	}
	return out
}
