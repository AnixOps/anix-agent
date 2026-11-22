package cmd

import (
	"bytes"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServerFailsWithoutConfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "config.json")
	err := runServer(missing, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), missing)
}

// runArgs runs the command line with args and answers its output.
func runArgs(t *testing.T, args ...string) (string, error) {
	t.Helper()
	previous := config
	var out bytes.Buffer
	command.SetArgs(args)
	command.SetOut(&out)
	t.Cleanup(func() {
		config = previous
		command.SetArgs(nil)
		command.SetOut(nil)
	})
	err := Run()
	return out.String(), err
}

func TestRun(t *testing.T) {
	out, err := runArgs(t, "version")
	require.NoError(t, err)
	require.Equal(t, productName+" "+version+"\n", out)

	_, err = runArgs(t, "server", "-c", filepath.Join(t.TempDir(), "missing.json"))
	require.Error(t, err)
	require.Equal(t, 1, ExitCode(err))
}

func TestX25519PrintsAKeyPair(t *testing.T) {
	out, err := runArgs(t, "x25519")
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.Len(t, lines, 2)
	for i, prefix := range []string{"Private key: ", "Public key: "} {
		require.True(t, strings.HasPrefix(lines[i], prefix), lines[i])
		key, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(lines[i], prefix))
		require.NoError(t, err)
		require.Len(t, key, 32)
	}
}
