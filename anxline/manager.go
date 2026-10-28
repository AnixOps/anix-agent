package anxline

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	log "github.com/sirupsen/logrus"
)

const commandTimeout = 10 * time.Second

// Options are the Manager's host hooks; zero values use the real host.
type Options struct {
	Runner Runner
	Prober Prober
	Now    func() time.Time
}

// Manager applies the AnxLine section: the RST rules once, the path
// monitors until Close.
type Manager struct {
	config   Config
	runner   Runner
	prober   Prober
	now      func() time.Time
	monitors []*monitor
}

// Start validates config, installs the fake-TCP RST rules (replacing the
// Agent's table) and starts one monitor per multipath link. Linux only.
func Start(config Config, options Options) (*Manager, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("ANX-Line host support (fake-TCP RST rules, MPTCP paths) is Linux only")
	}
	return start(config, options)
}

func start(config Config, options Options) (*Manager, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	m := &Manager{config: config, runner: options.Runner, prober: options.Prober, now: options.Now}
	if m.runner == nil {
		m.runner = ExecRunner{}
	}
	if m.prober == nil {
		m.prober = &NetProber{}
	}
	if m.now == nil {
		m.now = time.Now
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	if err := applyRST(ctx, m.runner, config.nft(), config.table(), config.Links); err != nil {
		return nil, fmt.Errorf("ANX-Line fake-TCP RST rules: %w", err)
	}
	for _, link := range config.Links {
		if link.Multipath == nil {
			continue
		}
		monitor := newMonitor(link.ID, *link.Multipath, config.ip(), m.runner, m.prober, m.now)
		if err := monitor.ensureEndpoints(ctx); err != nil {
			m.Close()
			return nil, fmt.Errorf("ANX-Line link %q MPTCP endpoints: %w", link.ID, err)
		}
		monitor.start()
		m.monitors = append(m.monitors, monitor)
	}
	log.WithField("links", len(config.Links)).Info("ANX-Line host support started")
	return m, nil
}

// Status reports every watched MPTCP path.
func (m *Manager) Status() []PathStatus {
	var out []PathStatus
	for _, monitor := range m.monitors {
		out = append(out, monitor.status()...)
	}
	return out
}

// Close stops the monitors and restores the endpoints they took out. The
// RST rules stay: anx-server keeps its fake-TCP carriers when the Agent
// stops, and middleboxes must keep seeing no RST.
func (m *Manager) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	for _, monitor := range m.monitors {
		monitor.close(ctx)
	}
	m.monitors = nil
}
