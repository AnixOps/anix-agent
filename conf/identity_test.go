package conf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentIdentityDefaultsToAutoEnrollmentUnderVarLib(t *testing.T) {
	var api ApiConfig
	if err := json.Unmarshal([]byte(`{"AgentControlEnabled":true}`), &api); err != nil {
		t.Fatal(err)
	}
	if got := api.AgentIdentity.EnrollMode(); got != AgentIdentityEnrollAuto {
		t.Fatalf("EnrollMode() = %q, want auto", got)
	}
	if got := api.AgentIdentity.Dir(); got != "/var/lib/anixops-agent/pki" {
		t.Fatalf("Dir() = %q", got)
	}
	if err := api.AgentIdentity.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestAgentIdentityParsesAndValidates(t *testing.T) {
	var api ApiConfig
	if err := json.Unmarshal([]byte(`{"AgentIdentity":{"Enroll":"OFF","CertDir":"/srv/pki/","EnrollCredentialFile":"/etc/anixops/agent/enroll.token","Cluster":"prod-1"}}`), &api); err != nil {
		t.Fatal(err)
	}
	identity := api.AgentIdentity
	if identity.EnrollMode() != AgentIdentityEnrollOff || identity.Dir() != "/srv/pki" ||
		identity.EnrollCredentialFile != "/etc/anixops/agent/enroll.token" || identity.Cluster != "prod-1" {
		t.Fatalf("unexpected identity config %+v", identity)
	}
	if err := identity.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	for _, invalid := range []AgentIdentityConfig{
		{Enroll: "always"},
		{CertDir: "pki"},
		{EnrollCredentialFile: "enroll.token"},
		{Cluster: "Prod"},
	} {
		if err := invalid.Validate(); err == nil {
			t.Fatalf("Validate(%+v) accepted an invalid setting", invalid)
		}
	}
}

func TestLoadFromPathRejectsInvalidAgentIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := `{"Nodes":[{"ApiHost":"https://panel.example.com","NodeID":1,"ApiKey":"key","AgentIdentity":{"Enroll":"sometimes"}}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	err := New().LoadFromPath(path)
	if err == nil || !strings.Contains(err.Error(), "AgentIdentity.Enroll") {
		t.Fatalf("LoadFromPath() = %v, want an AgentIdentity.Enroll error", err)
	}
}
