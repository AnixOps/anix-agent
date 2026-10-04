package conf

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Credential-only proxy nodes (the O1 installer's configuration): a node
// with no ApiKey authenticates to Control with its client certificate only.
// It enrolls with a one-time credential (AgentIdentity.EnrollCredentialFile)
// or already holds an enrolled identity, and its configuration, users and
// reports go over the stream's data plane (AgentStream); the cores are
// configured from the stream's configuration (core.NewForConfig).

// KeyLess tells whether the node has no API key and does not register one.
func (a ApiConfig) KeyLess() bool {
	return strings.TrimSpace(a.Key) == "" && !a.AutoRegister
}

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

// StreamCredentialOnly tells whether the node is credential-only and can
// run: no ApiKey, the control stream with its data plane, over TLS, and an
// enrollment credential or an enrolled identity.
func (a ApiConfig) StreamCredentialOnly() bool {
	return a.KeyLess() && a.validateKeyLess() == nil
}

// validateKeyLess checks what a node without an ApiKey needs.
func (a ApiConfig) validateKeyLess() error {
	var problems []string
	if !a.AgentControlEnabled {
		problems = append(problems, "AgentControlEnabled must be true")
	}
	if a.AgentStream.DataPlaneMode() != AgentStreamDataPlaneAuto {
		problems = append(problems, `AgentStream.DataPlane must be "auto"`)
	}
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

// validateNodeCredentials checks every proxy node that speaks to Control
// without an ApiKey (AgentNode set or AgentControlEnabled): it needs the
// stream's data plane over TLS and an enrollment credential or an enrolled
// identity. Older configurations with an ApiKey are not affected.
func (p *Conf) validateNodeCredentials() error {
	for i := range p.NodeConfig {
		api := p.NodeConfig[i].ApiConfig
		if !api.KeyLess() || (strings.TrimSpace(api.AgentNode) == "" && !api.AgentControlEnabled) {
			continue
		}
		if api.NodeID <= 0 {
			return fmt.Errorf("node %d: a node without ApiKey needs NodeID (or AgentNode proxy-<id>)", i)
		}
		if err := api.validateKeyLess(); err != nil {
			return fmt.Errorf("node %d has no ApiKey, so it authenticates with its agent identity only: %w", i, err)
		}
	}
	return nil
}
