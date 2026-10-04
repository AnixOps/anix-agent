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
)

// `anix-agent identity --json` on a forward node configured by the O1
// installer: the forward-<id> identity under its CertDir.
func TestIdentityForwardNode(t *testing.T) {
	dir := t.TempDir()
	certDir := filepath.Join(dir, "pki")
	path := filepath.Join(dir, "config.json")
	document := `{"Cores": [], "Nodes": [{"GRPCHost": "control.anixops.net:50051", "GRPCUseTLS": true, "AgentControlEnabled": true,
		"AgentNode": "forward-41", "AgentIdentity": {"Enroll": "auto", "CertDir": "` + certDir + `", "EnrollCredentialFile": "/var/lib/anixops-agent/enroll.credential"}}]}`
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := config
	config = path
	t.Cleanup(func() { config = previous })
	roots, nodes := identityRoots()
	if len(roots) != 1 || roots[0] != certDir || len(nodes[certDir]) != 1 || nodes[certDir][0].String() != "forward-41" {
		t.Fatalf("roots %v, nodes %v", roots, nodes)
	}
	statuses, err := collectIdentityStatuses(roots, nodes, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := printIdentityStatuses(&out, statuses, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	var decoded []pki.Status
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0].Node != "forward-41" || !strings.HasSuffix(decoded[0].Dir, "forward-41") {
		t.Fatalf("identity --json: %s", out.String())
	}
}
