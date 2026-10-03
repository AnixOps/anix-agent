// Package spool is the Agent's durable queue of report batches waiting for
// Control's ReportAck (reports.v1; node-ops-service.md 5.5, "The spool").
//
// Each batch is one file in the spool directory, named by a sequence that
// keeps the order across restarts (%016x.pb), holding the AgentToControl
// message to send: a TrafficReport or a LogBatch with its batch_id and, in
// sent_at_unix_ms, when the batch was made. Files are written to a
// temporary name, synced and renamed, so a crash leaves a whole batch or
// none. The directory is mode 0700 and the files 0600.
//
// The spool is bounded: by bytes (the oldest batches go first when a new one
// does not fit), by age (a batch older than MaxAge is dropped; Control
// remembers batch ids for 7 days, so a batch is never resent after Control
// forgot it), and by count. Every drop is counted.
package spool

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"google.golang.org/protobuf/proto"
)

const (
	dirMode  fs.FileMode = 0o700
	fileMode fs.FileMode = 0o600
	suffix               = ".pb"

	// DefaultMaxEntries bounds the number of batches.
	DefaultMaxEntries = 100000
	// MaxRetention is the longest MaxAge allowed: Control remembers a
	// batch id for 7 days, and a batch resent after that would count
	// twice.
	MaxRetention = 6 * 24 * time.Hour
)

// ErrTooLarge means a batch is larger than the spool itself.
var ErrTooLarge = errors.New("report batch exceeds the spool size")

// Limits bound a spool.
type Limits struct {
	MaxBytes   int64
	MaxAge     time.Duration
	MaxEntries int
}

// Entry is one spooled batch.
type Entry struct {
	Seq       uint64
	BatchID   string
	Size      int64
	CreatedAt time.Time
	path      string
}

// Drops counts batches the spool dropped, by reason.
type Drops struct {
	Size  uint64 `json:"size"`
	Age   uint64 `json:"age"`
	Count uint64 `json:"count"`
}

// Spool is one directory of batches.
type Spool struct {
	dir    string
	limits Limits
	now    func() time.Time

	mu      sync.Mutex
	entries []*Entry
	byBatch map[string]*Entry
	bytes   int64
	nextSeq uint64
	drops   Drops
}

// Open opens (creating it 0700) the spool in dir and indexes its batches. A
// file that is not a whole batch is removed.
func Open(dir string, limits Limits, now func() time.Time) (*Spool, error) {
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("report spool directory %q must be an absolute path", dir)
	}
	if limits.MaxBytes <= 0 {
		return nil, errors.New("report spool needs a size bound")
	}
	if limits.MaxAge <= 0 || limits.MaxAge > MaxRetention {
		return nil, fmt.Errorf("report spool age bound must be within (0, %s]", MaxRetention)
	}
	if limits.MaxEntries <= 0 {
		limits.MaxEntries = DefaultMaxEntries
	}
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		return nil, err
	}
	spool := &Spool{dir: dir, limits: limits, now: now, byBatch: map[string]*Entry{}, nextSeq: 1}
	if err := spool.index(); err != nil {
		return nil, err
	}
	return spool, nil
}

// index reads the batches on disk.
func (s *Spool) index() error {
	names, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	for _, name := range names {
		path := filepath.Join(s.dir, name.Name())
		if strings.HasPrefix(name.Name(), ".") {
			// An interrupted write.
			_ = os.Remove(path)
			continue
		}
		seq, err := strconv.ParseUint(strings.TrimSuffix(name.Name(), suffix), 16, 64)
		if err != nil || !strings.HasSuffix(name.Name(), suffix) || !name.Type().IsRegular() {
			continue
		}
		message, size, err := readBatch(path)
		if err != nil {
			_ = os.Remove(path)
			continue
		}
		entry := &Entry{Seq: seq, BatchID: batchID(message), Size: size, CreatedAt: time.UnixMilli(message.GetSentAtUnixMs()), path: path}
		if entry.BatchID == "" || s.byBatch[entry.BatchID] != nil {
			_ = os.Remove(path)
			continue
		}
		s.entries = append(s.entries, entry)
		s.byBatch[entry.BatchID] = entry
		s.bytes += size
		if seq >= s.nextSeq {
			s.nextSeq = seq + 1
		}
	}
	sort.Slice(s.entries, func(i, j int) bool { return s.entries[i].Seq < s.entries[j].Seq })
	return nil
}

func readBatch(path string) (*agentv1pb.AgentToControl, int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	message := &agentv1pb.AgentToControl{}
	if err := proto.Unmarshal(data, message); err != nil {
		return nil, 0, err
	}
	return message, int64(len(data)), nil
}

// batchID returns the batch id of a spooled message.
func batchID(message *agentv1pb.AgentToControl) string {
	switch payload := message.GetPayload().(type) {
	case *agentv1pb.AgentToControl_Traffic:
		return payload.Traffic.GetBatchId()
	case *agentv1pb.AgentToControl_Logs:
		return payload.Logs.GetBatchId()
	}
	return ""
}

// Append stores message (a TrafficReport or LogBatch envelope whose
// sent_at_unix_ms is when the batch was made) durably, dropping the oldest
// batches when the spool would exceed its bounds. A batch id already in the
// spool is kept once.
func (s *Spool) Append(message *agentv1pb.AgentToControl) error {
	id := batchID(message)
	if id == "" {
		return errors.New("report spool: the message carries no batch")
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return err
	}
	size := int64(len(data))
	if size > s.limits.MaxBytes {
		return fmt.Errorf("%w (%d > %d bytes)", ErrTooLarge, size, s.limits.MaxBytes)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byBatch[id] != nil {
		return nil
	}
	s.expireLocked()
	for len(s.entries) > 0 && (s.bytes+size > s.limits.MaxBytes || len(s.entries)+1 > s.limits.MaxEntries) {
		if s.bytes+size > s.limits.MaxBytes {
			s.drops.Size++
		} else {
			s.drops.Count++
		}
		s.removeLocked(s.entries[0])
	}
	seq := s.nextSeq
	path := filepath.Join(s.dir, fmt.Sprintf("%016x%s", seq, suffix))
	if err := writeFile(path, data); err != nil {
		return err
	}
	s.nextSeq++
	entry := &Entry{Seq: seq, BatchID: id, Size: size, CreatedAt: time.UnixMilli(message.GetSentAtUnixMs()), path: path}
	s.entries = append(s.entries, entry)
	s.byBatch[id] = entry
	s.bytes += size
	return nil
}

// Pending returns the batches in order, after dropping expired ones.
func (s *Spool) Pending() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	entries := make([]Entry, 0, len(s.entries))
	for _, entry := range s.entries {
		entries = append(entries, *entry)
	}
	return entries
}

// Read returns a pending batch's message, ok false when it is gone.
func (s *Spool) Read(id string) (*agentv1pb.AgentToControl, bool, error) {
	s.mu.Lock()
	entry := s.byBatch[id]
	s.mu.Unlock()
	if entry == nil {
		return nil, false, nil
	}
	message, _, err := readBatch(entry.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return message, true, nil
}

// Remove drops a batch (acknowledged); it reports whether it was spooled.
func (s *Spool) Remove(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.byBatch[id]
	if entry == nil {
		return false
	}
	s.removeLocked(entry)
	return true
}

// Stats returns the spool's size and drops.
func (s *Spool) Stats() (count int, bytes int64, drops Drops) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries), s.bytes, s.drops
}

// expireLocked drops the batches older than MaxAge (wherever they are:
// sequence order follows creation unless the clock went back).
func (s *Spool) expireLocked() {
	cutoff := s.now().Add(-s.limits.MaxAge)
	kept := s.entries[:0]
	for _, entry := range s.entries {
		if entry.CreatedAt.Before(cutoff) {
			s.drops.Age++
			_ = os.Remove(entry.path)
			delete(s.byBatch, entry.BatchID)
			s.bytes -= entry.Size
			continue
		}
		kept = append(kept, entry)
	}
	s.entries = kept
}

func (s *Spool) removeLocked(entry *Entry) {
	_ = os.Remove(entry.path)
	delete(s.byBatch, entry.BatchID)
	s.bytes -= entry.Size
	for index, candidate := range s.entries {
		if candidate == entry {
			s.entries = append(s.entries[:index], s.entries[index+1:]...)
			break
		}
	}
}

// writeFile writes data to path, 0600, through a synced temporary file.
func writeFile(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer func() {
		if name != "" {
			_ = os.Remove(name)
		}
	}()
	if err := temporary.Chmod(fileMode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	name = ""
	if handle, err := os.Open(filepath.Dir(path)); err == nil {
		_ = handle.Sync()
		_ = handle.Close()
	}
	return nil
}
