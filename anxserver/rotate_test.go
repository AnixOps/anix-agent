package anxserver

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRotationConfigValidate(t *testing.T) {
	var off *RotationConfig
	assert.NoError(t, off.Validate())
	assert.NoError(t, (&RotationConfig{Enable: true}).Validate(), "defaults: 30 days, 7 days grace")
	assert.ErrorContains(t, (&RotationConfig{Enable: true, IntervalDays: 7}).Validate(), "must exceed")
	assert.ErrorContains(t, (&RotationConfig{Enable: true, IntervalDays: 60, GraceDays: 31}).Validate(), "at most 30")
	assert.ErrorContains(t, (&RotationConfig{Enable: true, PublishDelaySeconds: 10}).Validate(), "at least 60")
	assert.ErrorContains(t, (&RotationConfig{Enable: true, GraceDays: -1}).Validate(), "negative")
	assert.NoError(t, (&RotationConfig{IntervalDays: 1}).Validate(), "off: not checked")
}

// rotationHost is a Manager whose anx-server keygen and rotate-key write
// numbered keys, and a clock.
type rotationHost struct {
	m       *Manager
	now     time.Time
	rotates [][]string
	slept   []time.Duration
	fail    bool
}

func newRotationHost(t *testing.T) *rotationHost {
	h := &rotationHost{now: time.Unix(1_800_000_000, 0)}
	keys := 0
	h.m = &Manager{
		Binary: "/usr/bin/anx-server", Dir: filepath.Join(t.TempDir(), "anx-server"),
		Run: func(name string, args ...string) ([]byte, error) {
			if args[0] == "rotate-key" {
				h.rotates = append(h.rotates, args)
				if h.fail {
					return nil, os.ErrInvalid
				}
			}
			keys++
			secret := "secret-" + string(rune('0'+keys))
			require.NoError(t, os.WriteFile(filepath.Join(h.m.Dir, keyFile), []byte(secret), 0o600))
			return []byte("public: PUBLIC-" + string(rune('0'+keys)) + "\nprevious: x\n"), nil
		},
	}
	return h
}

func (h *rotationHost) rotator(config RotationConfig) *Rotator {
	config.Enable = true
	return &Rotator{
		Manager: h.m, Config: config,
		Now: func() time.Time { return h.now },
		Sleep: func(d time.Duration, _ <-chan struct{}) bool {
			h.slept = append(h.slept, d)
			return true
		},
	}
}

func TestRotatorRotatesOnItsSchedule(t *testing.T) {
	h := newRotationHost(t)
	r := h.rotator(RotationConfig{})

	r.Step()
	assert.Empty(t, h.rotates, "no key yet: nothing to rotate")
	public, err := h.m.PublicKey()
	require.NoError(t, err)
	require.Equal(t, "PUBLIC-1", public)

	r.Step()
	assert.Empty(t, h.rotates, "turning rotation on only starts the clock")
	h.now = h.now.Add(29 * 24 * time.Hour)
	r.Step()
	assert.Empty(t, h.rotates)

	// Due: a reverse A2 rendezvous keeps the old key, the new key is
	// reported only after the processes had time to load it.
	h.m.Run = wrapRun(h.m.Run, func() {
		_, err := os.Stat(filepath.Join(h.m.Dir, ReverseA2KeyFile))
		assert.NoError(t, err, "the reverse A2 key is copied before the server key rotates")
	})
	h.now = h.now.Add(24 * time.Hour)
	var reportedWhilePending string
	r.Sleep = func(d time.Duration, _ <-chan struct{}) bool {
		h.slept = append(h.slept, d)
		reportedWhilePending, _ = h.m.PublicKey()
		return true
	}
	r.Step()
	require.Len(t, h.rotates, 1)
	assert.Equal(t, []string{"rotate-key", "--key", filepath.Join(h.m.Dir, keyFile), "--grace", "604800"}, h.rotates[0])
	assert.Equal(t, "PUBLIC-1", reportedWhilePending)
	assert.Equal(t, []time.Duration{90 * time.Second}, h.slept)
	public, err = h.m.PublicKey()
	require.NoError(t, err)
	assert.Equal(t, "PUBLIC-2", public)
	reverse, err := h.m.ReverseA2PublicKey()
	require.NoError(t, err)
	assert.Equal(t, "PUBLIC-1", reverse, "the reverse A2 key does not rotate")
	secret, err := os.ReadFile(filepath.Join(h.m.Dir, ReverseA2KeyFile))
	require.NoError(t, err)
	assert.Equal(t, "secret-1", string(secret))

	// The next one waits a whole interval again.
	h.now = h.now.Add(24 * time.Hour)
	r.Step()
	assert.Len(t, h.rotates, 1)
}

func wrapRun(run Runner, before func()) Runner {
	return func(name string, args ...string) ([]byte, error) {
		if args[0] == "rotate-key" {
			before()
		}
		return run(name, args...)
	}
}

func TestRotatorFinishesAPendingKeyAfterARestart(t *testing.T) {
	h := newRotationHost(t)
	_, err := h.m.PublicKey()
	require.NoError(t, err)
	_, err = h.m.RotateKey(time.Hour)
	require.NoError(t, err)
	assert.Equal(t, "3600", h.rotates[0][4])
	public, _ := h.m.PublicKey()
	require.Equal(t, "PUBLIC-1", public)

	r := h.rotator(RotationConfig{PublishDelaySeconds: 120})
	r.Step()
	assert.Equal(t, []time.Duration{120 * time.Second}, h.slept)
	public, _ = h.m.PublicKey()
	assert.Equal(t, "PUBLIC-2", public)
	assert.Len(t, h.rotates, 1)
}

func TestRotatorKeepsTheKeyWhenRotateKeyFails(t *testing.T) {
	h := newRotationHost(t)
	_, err := h.m.PublicKey()
	require.NoError(t, err)
	r := h.rotator(RotationConfig{})
	r.Step()
	h.now = h.now.Add(31 * 24 * time.Hour)
	h.fail = true
	r.Step()
	assert.Len(t, h.rotates, 1)
	assert.Empty(t, h.slept)
	public, _ := h.m.PublicKey()
	assert.Equal(t, "PUBLIC-1", public)
	assert.False(t, h.m.rotationPending())
}

func TestRotatorStartAndClose(t *testing.T) {
	h := newRotationHost(t)
	r := &Rotator{Manager: h.m, Config: RotationConfig{Enable: true}}
	r.Start()
	r.Close()
}
