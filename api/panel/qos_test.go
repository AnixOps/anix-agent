package panel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseQoS(t *testing.T) {
	qos, err := ParseQoS([]byte(`{"kind":"proxy"}`))
	require.NoError(t, err)
	assert.Nil(t, qos)
	qos, err = ParseQoS([]byte(`{"qos":null}`))
	require.NoError(t, err)
	assert.Nil(t, qos)
	qos, err = ParseQoS([]byte(`{"qos": {"egress_mbps": 100, "classes": [{"name": "steam", "priority": "low", "limit_mbps": 5, "domains": ["steamcontent.com"]}]}}`))
	require.NoError(t, err)
	assert.JSONEq(t, `{"egress_mbps": 100, "classes": [{"name": "steam", "priority": "low", "limit_mbps": 5, "domains": ["steamcontent.com"]}]}`, string(qos))
	_, err = ParseQoS([]byte(`{"qos": [1]}`))
	require.Error(t, err)
}
