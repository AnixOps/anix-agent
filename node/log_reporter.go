package node

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	apiclient "github.com/AnixOps/anix-agent/v4/api/client"
	"github.com/AnixOps/anix-agent/v4/api/panel"
	log "github.com/sirupsen/logrus"
)

type RemoteLogHook struct {
	// report sends a batch: the control stream's LogBatch while it carries
	// reports.v1, else the legacy transport (Controller.reportNodeLogs).
	report func([]panel.NodeLogEntry) error
	tag    string

	active atomic.Bool
	stop   chan struct{}
	done   chan struct{}
	once   sync.Once
	queue  chan panel.NodeLogEntry
}

func NewRemoteLogHook(client apiclient.NodeAPI, tag string) *RemoteLogHook {
	var report func([]panel.NodeLogEntry) error
	if client != nil {
		report = client.ReportNodeLogs
	}
	return newRemoteLogHook(report, tag)
}

func newRemoteLogHook(report func([]panel.NodeLogEntry) error, tag string) *RemoteLogHook {
	hook := &RemoteLogHook{
		report: report,
		tag:    tag,
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		queue:  make(chan panel.NodeLogEntry, 256),
	}
	hook.active.Store(true)
	go hook.run()
	return hook
}

func (h *RemoteLogHook) Levels() []log.Level {
	return log.AllLevels
}

func (h *RemoteLogHook) Fire(entry *log.Entry) error {
	if h == nil || !h.active.Load() || h.report == nil || entry == nil {
		return nil
	}

	tagValue := strings.TrimSpace(fmt.Sprint(entry.Data["tag"]))
	if h.tag != "" && tagValue != h.tag {
		return nil
	}

	fields := make(map[string]any, len(entry.Data))
	source := h.tag
	traceID := ""
	for key, value := range entry.Data {
		switch key {
		case "tag":
			continue
		case "trace_id":
			traceID = fmt.Sprint(value)
		case "component", "source", "module":
			if source == "" {
				source = fmt.Sprint(value)
			}
			fields[key] = value
		default:
			fields[key] = value
		}
	}

	fieldsJSON := ""
	if len(fields) > 0 {
		if raw, err := json.Marshal(fields); err == nil {
			fieldsJSON = string(raw)
		}
	}

	ts := entry.Time
	if ts.IsZero() {
		ts = time.Now()
	}

	payload := panel.NodeLogEntry{
		Level:      entry.Level.String(),
		Source:     source,
		Message:    entry.Message,
		Timestamp:  ts,
		TraceID:    traceID,
		FieldsJSON: fieldsJSON,
	}

	select {
	case h.queue <- payload:
	default:
	}

	return nil
}

func (h *RemoteLogHook) run() {
	defer close(h.done)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	batch := make([]panel.NodeLogEntry, 0, 20)
	flush := func() {
		if len(batch) == 0 || !h.active.Load() || h.report == nil {
			batch = batch[:0]
			return
		}
		if err := h.report(append([]panel.NodeLogEntry(nil), batch...)); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "remote node log report failed for %s: %v\n", h.tag, err)
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-h.stop:
			flush()
			return
		case entry := <-h.queue:
			batch = append(batch, entry)
			if len(batch) >= 20 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (h *RemoteLogHook) Close() {
	if h == nil {
		return
	}
	h.once.Do(func() {
		h.active.Store(false)
		close(h.stop)
		<-h.done
	})
}
