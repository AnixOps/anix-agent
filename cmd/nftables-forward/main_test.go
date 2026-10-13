package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/AnixOps/anix-agent/v5/plugin/nftablesforward"
	"github.com/stretchr/testify/require"
)

const officialManifestVersion = "1.2.0"

func TestVersionMatchesOfficialManifest(t *testing.T) {
	require.Equal(t, officialManifestVersion, nftablesforward.Version)
	exitCode, output := runAndCaptureStdout(t, []string{"--version"})
	require.Equal(t, 0, exitCode)
	require.Equal(t, nftablesforward.ID+" "+officialManifestVersion+"\n", output)
}

func TestRunValidateAndCleanupModes(t *testing.T) {
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	configPath := filepath.Join(directory, "config.json")
	statePath := filepath.Join(directory, "ownership.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{
		"apply":false,
		"rollback_on_exit":true,
		"rules":[]
	}`), 0o600))

	require.Equal(t, 0, run([]string{"--anixops-validate", "--anixops-config", configPath}))
	require.Equal(t, 1, run([]string{"--anixops-validate"}))
	require.Equal(t, 0, run([]string{"--anixops-cleanup", "--anixops-state", statePath}))
	require.Equal(t, 1, run([]string{"--anixops-cleanup"}))
	require.Equal(t, 2, run([]string{"--anixops-cleanup", "--anixops-validate", "--anixops-config", configPath, "--anixops-state", statePath}))
}

func runAndCaptureStdout(t *testing.T, args []string) (int, string) {
	t.Helper()

	read, write, err := os.Pipe()
	require.NoError(t, err)
	original := os.Stdout
	os.Stdout = write
	exitCode := run(args)
	os.Stdout = original
	require.NoError(t, write.Close())

	output, err := io.ReadAll(read)
	require.NoError(t, err)
	require.NoError(t, read.Close())
	return exitCode, string(output)
}
