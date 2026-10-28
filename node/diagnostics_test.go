package node

import (
	"testing"

	"github.com/AnixOps/anix-agent/v5/diagnostic"
	"github.com/AnixOps/anix-agent/v5/forward"
	"github.com/stretchr/testify/assert"
)

func TestProxyNodeDiagnosticsRunOnEveryProxyNode(t *testing.T) {
	plain := proxyNodeDiagnostics(nil)
	assert.Equal(t, map[string]string{"anix-agent": "anix-agent.service"}, plain.Units)
	assert.Equal(t, diagnostic.AgentService, plain.Self)
	assert.Nil(t, plain.Forward, "a node that does not forward runs no forward check")

	forwarding := proxyNodeDiagnostics(&forward.Component{})
	assert.Equal(t, map[string]string{"anix-agent": "anix-agent.service"}, forwarding.Units)
	assert.Equal(t, diagnostic.AgentService, forwarding.Self)
	assert.NotNil(t, forwarding.Forward)
}
