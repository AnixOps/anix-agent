package conf

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Agent identity enrollment modes (AgentIdentity.Enroll).
const (
	// AgentIdentityEnrollAuto enrolls with Control's AgentEnrollment when
	// the node has no valid certificate: with EnrollCredentialFile when set,
	// else once with the node API key. The default.
	AgentIdentityEnrollAuto = "auto"
	// AgentIdentityEnrollOff never enrolls. A stored identity is still used
	// and renewed.
	AgentIdentityEnrollOff = "off"
)

// DefaultAgentIdentityCertDir is where node identities live.
const DefaultAgentIdentityCertDir = "/var/lib/anixops-agent/pki"

var agentIdentityClusterPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// AgentIdentityConfig is the mTLS identity of the Agent control stream
// (AgentControlEnabled). Control issues the certificate; the Agent keeps
// its key and certificate in CertDir/proxy-<NodeID>, mode 0600, renews at
// two thirds of the lifetime, and stops sending the node API key on the
// stream once enrolled. Identities need TLS to Control.
type AgentIdentityConfig struct {
	// Enroll is "auto" (default) or "off".
	Enroll string `json:"Enroll"`
	// CertDir is the identity root, an absolute path; default
	// /var/lib/anixops-agent/pki.
	CertDir string `json:"CertDir"`
	// EnrollCredentialFile is an absolute path to a one-time anixagt_
	// enrollment credential (`anix-control agent token create`), mode 0600.
	// Control 4.2 (agent_control.mtls: required) enrolls only with one. The
	// file is removed after use.
	EnrollCredentialFile string `json:"EnrollCredentialFile"`
	// Cluster pins the SPIFFE cluster of the certificate; empty accepts
	// Control's.
	Cluster string `json:"Cluster"`
}

// EnrollMode is Enroll, defaulted and lowercased.
func (c AgentIdentityConfig) EnrollMode() string {
	if mode := strings.ToLower(strings.TrimSpace(c.Enroll)); mode != "" {
		return mode
	}
	return AgentIdentityEnrollAuto
}

// Dir is CertDir, defaulted.
func (c AgentIdentityConfig) Dir() string {
	if dir := strings.TrimSpace(c.CertDir); dir != "" {
		return filepath.Clean(dir)
	}
	return DefaultAgentIdentityCertDir
}

// Validate checks the settings.
func (c AgentIdentityConfig) Validate() error {
	switch c.EnrollMode() {
	case AgentIdentityEnrollAuto, AgentIdentityEnrollOff:
	default:
		return fmt.Errorf("AgentIdentity.Enroll must be %q or %q, not %q", AgentIdentityEnrollAuto, AgentIdentityEnrollOff, c.Enroll)
	}
	if dir := strings.TrimSpace(c.CertDir); dir != "" && !filepath.IsAbs(dir) {
		return fmt.Errorf("AgentIdentity.CertDir %q must be an absolute path", c.CertDir)
	}
	if file := strings.TrimSpace(c.EnrollCredentialFile); file != "" && !filepath.IsAbs(file) {
		return fmt.Errorf("AgentIdentity.EnrollCredentialFile %q must be an absolute path", c.EnrollCredentialFile)
	}
	if cluster := strings.TrimSpace(c.Cluster); cluster != "" && !agentIdentityClusterPattern.MatchString(cluster) {
		return fmt.Errorf("AgentIdentity.Cluster %q must be lowercase letters, digits and dashes", c.Cluster)
	}
	return nil
}

// validateAgentIdentities checks every node's AgentIdentity and AgentStream.
func (p *Conf) validateAgentIdentities() error {
	for i := range p.NodeConfig {
		if err := p.NodeConfig[i].ApiConfig.AgentIdentity.Validate(); err != nil {
			return fmt.Errorf("node %d: %w", i, err)
		}
		if err := p.NodeConfig[i].ApiConfig.AgentStream.Validate(); err != nil {
			return fmt.Errorf("node %d: %w", i, err)
		}
	}
	return nil
}
