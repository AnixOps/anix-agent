package conf

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// A proxy node authenticates to Control with its client certificate only.
// It enrolls with a one-time credential (AgentIdentity.EnrollCredentialFile)
// or already holds an enrolled identity, and its configuration, users and
// reports go over the stream's data plane (AgentStream); the cores are
// configured from the stream's configuration (core.NewForConfig).

// UsesTLS tells whether the control stream runs over TLS.
func (a ApiConfig) UsesTLS() bool {
	if a.GRPCUseTLS {
		return true
	}
	parsed, err := url.Parse(strings.TrimSpace(a.APIHost))
	return err == nil && strings.EqualFold(parsed.Scheme, "https")
}

// IdentityEnrolled tells whether the node has an identity on disk
// (CertDir/proxy-<NodeID>/identity.pem, api/agent/pki).
func (a ApiConfig) IdentityEnrolled() bool {
	if a.NodeID <= 0 {
		return false
	}
	info, err := os.Stat(filepath.Join(a.AgentIdentity.Dir(), "proxy-"+strconv.Itoa(a.NodeID), "identity.pem"))
	return err == nil && info.Mode().IsRegular()
}

// validateCredentials checks what a node needs to reach Control: TLS, and
// an enrollment credential or an enrolled identity.
func (a ApiConfig) validateCredentials() error {
	var problems []string
	if !a.UsesTLS() {
		problems = append(problems, "the control stream must use TLS (GRPCUseTLS or an https ApiHost): the client certificate is the only credential")
	}
	switch {
	case a.AgentIdentity.EnrollMode() == AgentIdentityEnrollAuto && strings.TrimSpace(a.AgentIdentity.EnrollCredentialFile) != "":
	case a.IdentityEnrolled():
	case a.AgentIdentity.EnrollMode() == AgentIdentityEnrollAuto:
		problems = append(problems, "AgentIdentity.EnrollCredentialFile is required until the node is enrolled")
	default:
		problems = append(problems, `the node is not enrolled and AgentIdentity.Enroll is "off"`)
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

// validateNodeCredentials checks every proxy node: a NodeID, the stream over
// TLS, and an enrollment credential or an enrolled identity.
func (p *Conf) validateNodeCredentials() error {
	for i := range p.NodeConfig {
		api := p.NodeConfig[i].ApiConfig
		if api.NodeID <= 0 {
			return fmt.Errorf("node %d: NodeID (or AgentNode proxy-<id>) is required", i)
		}
		if err := api.validateCredentials(); err != nil {
			return fmt.Errorf("node %d authenticates with its agent identity: %w", i, err)
		}
	}
	return nil
}
