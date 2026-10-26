package panel

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseEgress(t *testing.T) {
	none, err := ParseEgress([]byte(`{"kind":"proxy"}`))
	require.NoError(t, err)
	require.Nil(t, none)
	require.True(t, none.Empty())

	parsed, err := ParseEgress([]byte(`{"egress":{
		"routes":[{"id":3,"domains":["openai.com"],"server":{"host":"jp.example","port":24680,"method":"2022-blake3-aes-128-gcm","password":"k"}}],
		"relays":[{"id":4,"port":24681,"method":"2022-blake3-aes-128-gcm","password":"k"}]}}`))
	require.NoError(t, err)
	require.False(t, parsed.Empty())
	require.Equal(t, uint64(3), parsed.Routes[0].ID)
	require.Equal(t, "jp.example", parsed.Routes[0].Server.Host)
	require.Equal(t, 24681, parsed.Relays[0].Port)

	_, err = ParseEgress([]byte(`{"egress":{"relays":[{"id":4,"port":0,"method":"m","password":"k"}]}}`))
	require.ErrorContains(t, err, "invalid port")
	_, err = ParseEgress([]byte(`{"egress":{"routes":[{"id":1,"domains":["a.com"],"server":{"port":1,"method":"m","password":"k"}}]}}`))
	require.ErrorContains(t, err, "no host")
	_, err = ParseEgress([]byte(`{"egress":{"relays":[{"id":4,"port":1,"method":"m","password":"k"},{"id":4,"port":2,"method":"m","password":"k"}]}}`))
	require.ErrorContains(t, err, "repeated")
}
