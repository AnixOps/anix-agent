package node

import (
	"strings"
	"testing"

	"github.com/AnixOps/anix-agent/v5/conf"
)

func TestAgentControlIdentityDefaultsToAutoEnrollment(t *testing.T) {
	identity, err := agentControlIdentity(&conf.ApiConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if identity == nil || !identity.Enroll || identity.Dir != "/var/lib/anixops-agent/pki" || identity.EnrollCredentialFile != "" {
		t.Fatalf("identity = %+v, want auto enrollment under /var/lib/anixops-agent/pki", identity)
	}

	identity, err = agentControlIdentity(&conf.ApiConfig{AgentIdentity: conf.AgentIdentityConfig{
		Enroll: "off", CertDir: "/srv/pki", EnrollCredentialFile: "/etc/anixops/agent/enroll.token", Cluster: "prod",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if identity.Enroll || identity.Dir != "/srv/pki" || identity.EnrollCredentialFile != "/etc/anixops/agent/enroll.token" || identity.Cluster != "prod" {
		t.Fatalf("identity = %+v", identity)
	}
}

func TestAgentControlIdentityRejectsAnInvalidEnrollMode(t *testing.T) {
	if _, err := agentControlIdentity(&conf.ApiConfig{AgentIdentity: conf.AgentIdentityConfig{Enroll: "never"}}); err == nil ||
		!strings.Contains(err.Error(), "AgentIdentity.Enroll") {
		t.Fatalf("invalid Enroll error = %v", err)
	}
}
