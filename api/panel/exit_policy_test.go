package panel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseExitPolicy(t *testing.T) {
	for document, want := range map[string]ExitPolicy{
		`{"kind":"proxy"}`:                         {},
		`{"exit_policy":null}`:                     {},
		`{"exit_policy":{"block_mainland":true}}`:  {BlockMainland: true},
		`{"exit_policy":{"block_mainland":false}}`: {},
	} {
		policy, err := ParseExitPolicy([]byte(document))
		require.NoError(t, err, document)
		assert.Equal(t, want, policy, document)
	}
	_, err := ParseExitPolicy([]byte(`{"exit_policy":{"block_mainland":"yes"}}`))
	require.Error(t, err)
}
