package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v4/api/agent/pki"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
)

func TestIdentityStatusesListConfiguredAndStoredNodes(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "proxy-3"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "proxy-3", "identity.pem"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	nodes := map[string][]agentcontrol.AgentNode{root: {{Kind: agentcontrol.NodeKindProxy, ID: 12}}}
	statuses, err := collectIdentityStatuses([]string{root}, nodes, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 2 || statuses[0].Node != "proxy-12" || statuses[0].State != pki.StateNotEnrolled ||
		statuses[1].Node != "proxy-3" || statuses[1].State != pki.StateInvalid {
		t.Fatalf("statuses = %+v", statuses)
	}

	var table bytes.Buffer
	if err := printIdentityStatuses(&table, statuses, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"NODE", "proxy-12", "not-enrolled", "proxy-3", "invalid", "proxy-3: "} {
		if !strings.Contains(table.String(), want) {
			t.Fatalf("table output misses %q:\n%s", want, table.String())
		}
	}

	var encoded bytes.Buffer
	if err := printIdentityStatuses(&encoded, statuses, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	var decoded []pki.Status
	if err := json.Unmarshal(encoded.Bytes(), &decoded); err != nil || len(decoded) != 2 {
		t.Fatalf("JSON output = %s (%v)", encoded.String(), err)
	}
}

func TestIdentityStatusesWithoutIdentities(t *testing.T) {
	var out bytes.Buffer
	if err := printIdentityStatuses(&out, nil, false, time.Now()); err != nil || !strings.Contains(out.String(), "No agent identity") {
		t.Fatalf("output = %q, %v", out.String(), err)
	}
	out.Reset()
	if err := printIdentityStatuses(&out, nil, true, time.Now()); err != nil || strings.TrimSpace(out.String()) != "[]" {
		t.Fatalf("JSON output = %q, %v", out.String(), err)
	}
}

func TestHumanDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		-time.Second:                  "expired",
		6*24*time.Hour + 23*time.Hour: "in 6d 23h",
		5*time.Hour + 10*time.Minute:  "in 5h 10m",
		42 * time.Minute:              "in 42m",
	} {
		if got := humanDuration(d); got != want {
			t.Fatalf("humanDuration(%s) = %q, want %q", d, got, want)
		}
	}
}
