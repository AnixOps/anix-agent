package cmd

import (
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
)

// The log names a node by its id, never its protocol or Control host.
func TestLogHidesNodeTags(t *testing.T) {
	f := &LocalTimeFormatter{TextFormatter: log.TextFormatter{DisableTimestamp: true}}
	entry := log.WithField("tag", "[new-x.example.com]-vless:62")
	entry.Message = "inbound [new-x.example.com]-vless:62 refused"
	line, err := f.Format(entry)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(line); strings.Contains(got, "vless") || strings.Contains(got, "example.com") || strings.Count(got, "node-62") != 2 {
		t.Fatalf("log line %q", got)
	}
}
