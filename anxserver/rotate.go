package anxserver

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// Files of a key rotation, in the Manager's directory.
const (
	// rotatedAtFile holds the unix time of the last rotation (or of the
	// moment rotation was turned on, so turning it on rotates nothing).
	rotatedAtFile = "rotated-at"
	// nextPublicFile is the new public key while the processes still load
	// the new key; it replaces server.pub once they all serve it.
	nextPublicFile = "server.pub.next"
)

// Key rotation defaults and bounds (anx §2.6: anx-server rotate-key).
const (
	DefaultRotationIntervalDays = 30
	DefaultRotationGraceDays    = 7
	// MaxRotationGraceDays is the longest grace anx-server accepts.
	MaxRotationGraceDays = 30
	// DefaultPublishDelaySeconds is how long a new key waits before it is
	// reported: every anx-server and anx-node reloads its key file within
	// 30 s, a client handed the new key must find it served.
	DefaultPublishDelaySeconds = 90
	minPublishDelaySeconds     = 60
)

// RotationConfig turns on periodic rotation of the anx-server key (the key
// of the anx_line accepting ends and of anx-node's ANX inbound). Off by
// default. The reverse A2 key (ReverseA2KeyFile) never rotates.
type RotationConfig struct {
	Enable bool `json:"Enable"`
	// IntervalDays is the time between rotations (DefaultRotationIntervalDays
	// when 0); it must exceed GraceDays, as anx-server keeps one previous
	// key only.
	IntervalDays int `json:"IntervalDays"`
	// GraceDays is how long the previous key is still accepted
	// (DefaultRotationGraceDays when 0, at most MaxRotationGraceDays):
	// clients must refresh their subscription within it.
	GraceDays int `json:"GraceDays"`
	// PublishDelaySeconds is how long a new key waits before it is
	// reported to Control (DefaultPublishDelaySeconds when 0, at least 60).
	PublishDelaySeconds int `json:"PublishDelaySeconds"`
}

// Enabled reports whether rotation is on.
func (c *RotationConfig) Enabled() bool { return c != nil && c.Enable }

func (c *RotationConfig) interval() time.Duration {
	return time.Duration(positiveOr(c.IntervalDays, DefaultRotationIntervalDays)) * 24 * time.Hour
}

func (c *RotationConfig) grace() time.Duration {
	return time.Duration(positiveOr(c.GraceDays, DefaultRotationGraceDays)) * 24 * time.Hour
}

func (c *RotationConfig) publishDelay() time.Duration {
	return time.Duration(positiveOr(c.PublishDelaySeconds, DefaultPublishDelaySeconds)) * time.Second
}

func positiveOr(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

// Validate checks an enabled configuration.
func (c *RotationConfig) Validate() error {
	if !c.Enabled() {
		return nil
	}
	if c.IntervalDays < 0 || c.GraceDays < 0 || c.PublishDelaySeconds < 0 {
		return errors.New("AnxKeyRotation: values must not be negative")
	}
	if grace := positiveOr(c.GraceDays, DefaultRotationGraceDays); grace > MaxRotationGraceDays {
		return fmt.Errorf("AnxKeyRotation.GraceDays %d: at most %d", grace, MaxRotationGraceDays)
	}
	if c.interval() <= c.grace() {
		return fmt.Errorf("AnxKeyRotation.IntervalDays %d must exceed GraceDays %d: anx-server keeps one previous key",
			positiveOr(c.IntervalDays, DefaultRotationIntervalDays), positiveOr(c.GraceDays, DefaultRotationGraceDays))
	}
	if c.PublishDelaySeconds != 0 && c.PublishDelaySeconds < minPublishDelaySeconds {
		return fmt.Errorf("AnxKeyRotation.PublishDelaySeconds %d: at least %d (processes reload the key every 30 s)",
			c.PublishDelaySeconds, minPublishDelaySeconds)
	}
	return nil
}

// RotateKey rotates the server key with anx-server rotate-key, keeping the
// previous key for grace, and leaves the new public key pending: Publish
// makes it the reported one. The reverse A2 key is copied first if it was
// not yet, so it keeps the key its egresses pinned. It answers the new
// public key.
func (m *Manager) RotateKey(grace time.Duration) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := filepath.Join(m.Dir, keyFile)
	if _, err := os.Stat(key); err != nil {
		return "", fmt.Errorf("anx-server key: %w", err)
	}
	if _, err := m.reverseA2PublicKey(); err != nil {
		return "", err
	}
	seconds := int64(grace / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	out, err := m.run()(m.Binary, "rotate-key", "--key", key, "--grace", strconv.FormatInt(seconds, 10))
	if err != nil {
		return "", fmt.Errorf("anx-server rotate-key: %w", err)
	}
	public := ""
	for _, line := range strings.Split(string(out), "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "public:"); ok {
			public = strings.TrimSpace(value)
		}
	}
	if public == "" {
		return "", errors.New("anx-server rotate-key printed no public key")
	}
	if err := writeFileAtomic(filepath.Join(m.Dir, nextPublicFile), []byte(public+"\n")); err != nil {
		return "", fmt.Errorf("pending public key: %w", err)
	}
	return public, nil
}

// PublishRotatedKey makes a pending new public key the reported one; it
// does nothing when none is pending.
func (m *Manager) PublishRotatedKey() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := filepath.Join(m.Dir, nextPublicFile)
	if _, err := os.Stat(next); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return os.Rename(next, filepath.Join(m.Dir, publicFile))
}

// rotationPending reports whether a new public key waits to be published.
func (m *Manager) rotationPending() bool {
	_, err := os.Stat(filepath.Join(m.Dir, nextPublicFile))
	return err == nil
}

// Rotator rotates the server key on its schedule.
type Rotator struct {
	Manager *Manager
	Config  RotationConfig
	// Now and Sleep reach the clock; nil uses the real one. Sleep answers
	// false when the Rotator was closed meanwhile.
	Now   func() time.Time
	Sleep func(d time.Duration, stop <-chan struct{}) bool

	stop    chan struct{}
	stopped chan struct{}
}

// rotationCheck is how often the Rotator looks whether a rotation is due.
var rotationCheck = time.Hour

// Start runs the Rotator until Close.
func (r *Rotator) Start() {
	r.stop, r.stopped = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(r.stopped)
		for {
			r.Step()
			if !r.sleep(rotationCheck) {
				return
			}
		}
	}()
}

// Close stops the Rotator and waits for it.
func (r *Rotator) Close() {
	if r.stop == nil {
		return
	}
	close(r.stop)
	<-r.stopped
}

func (r *Rotator) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Rotator) sleep(d time.Duration) bool {
	if r.Sleep != nil {
		return r.Sleep(d, r.stop)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-r.stop:
		return false
	}
}

// Step does what is due now: publishes a pending key once every process
// serves it, else rotates when the interval has passed. The first Step on
// a host only starts the clock.
func (r *Rotator) Step() {
	m := r.Manager
	if m.rotationPending() {
		// Left by a rotation the Agent did not finish (restart): the
		// processes have had time to reload since only if we wait again.
		if !r.sleep(r.Config.publishDelay()) {
			return
		}
		r.publish()
		return
	}
	if _, err := os.Stat(filepath.Join(m.Dir, keyFile)); err != nil {
		// No key yet: nothing to rotate.
		return
	}
	stamp := filepath.Join(m.Dir, rotatedAtFile)
	last, err := readUnix(stamp)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.WithField("err", err).Warn("anx-server key rotation: unreadable rotated-at, starting the clock again")
		}
		if err := writeFileAtomic(stamp, unixLine(r.now())); err != nil {
			log.WithField("err", err).Warn("anx-server key rotation: cannot start the clock")
		}
		return
	}
	if r.now().Sub(last) < r.Config.interval() {
		return
	}
	public, err := m.RotateKey(r.Config.grace())
	if err != nil {
		log.WithField("err", err).Error("anx-server key rotation failed (needs an anx-server with rotate-key)")
		return
	}
	if err := writeFileAtomic(stamp, unixLine(r.now())); err != nil {
		log.WithField("err", err).Warn("anx-server key rotation: cannot record the rotation")
	}
	log.WithField("public", public).Info("anx-server key rotated; reporting it once every process serves it")
	if !r.sleep(r.Config.publishDelay()) {
		return
	}
	r.publish()
}

func (r *Rotator) publish() {
	if err := r.Manager.PublishRotatedKey(); err != nil {
		log.WithField("err", err).Error("anx-server key rotation: cannot publish the new public key")
		return
	}
	log.Info("anx-server key rotation: new public key reported from now on")
}

func readUnix(path string) (time.Time, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	seconds, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(seconds, 0), nil
}

func unixLine(t time.Time) []byte {
	return []byte(strconv.FormatInt(t.Unix(), 10) + "\n")
}
