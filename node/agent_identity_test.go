package node

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AnixOps/anix-agent/v4/conf"
)

func TestAgentControlIdentityDefaultsToAutoEnrollmentOnTLS(t *testing.T) {
	identity, err := agentControlIdentity(&conf.ApiConfig{}, 12, true)
	if err != nil {
		t.Fatal(err)
	}
	if identity == nil || !identity.Enroll || identity.Dir != "/var/lib/anix-agent/pki" || identity.EnrollCredentialFile != "" {
		t.Fatalf("identity = %+v, want auto enrollment under /var/lib/anix-agent/pki", identity)
	}

	identity, err = agentControlIdentity(&conf.ApiConfig{AgentIdentity: conf.AgentIdentityConfig{
		Enroll: "off", CertDir: "/srv/pki", EnrollCredentialFile: "/etc/anixops/agent/enroll.token", Cluster: "prod",
	}}, 12, true)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Enroll || identity.Dir != "/srv/pki" || identity.EnrollCredentialFile != "/etc/anixops/agent/enroll.token" || identity.Cluster != "prod" {
		t.Fatalf("identity = %+v", identity)
	}
}

func TestAgentControlIdentityNeedsTLS(t *testing.T) {
	identity, err := agentControlIdentity(&conf.ApiConfig{}, 12, false)
	if err != nil || identity != nil {
		t.Fatalf("plaintext stream identity = %+v, %v; want none", identity, err)
	}
	if _, err := agentControlIdentity(&conf.ApiConfig{AgentIdentity: conf.AgentIdentityConfig{Enroll: "never"}}, 12, true); err == nil ||
		!strings.Contains(err.Error(), "AgentIdentity.Enroll") {
		t.Fatalf("invalid Enroll error = %v", err)
	}
}

func TestAgentControlIdentityForceReRegisterDropsTheStoredIdentity(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "proxy-12")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"identity.pem", "identity.json", "ca.pem"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := agentControlIdentity(&conf.ApiConfig{ForceReRegister: true, AgentIdentity: conf.AgentIdentityConfig{CertDir: root}}, 12, true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"identity.pem", "identity.json", "ca.pem"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s survived a forced re-registration: %v", name, err)
		}
	}
}
