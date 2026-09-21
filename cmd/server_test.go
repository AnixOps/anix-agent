package cmd

import (
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestRun(t *testing.T) {
	Run()
}

func TestServerHandleReturnsConfigError(t *testing.T) {
	previous := config
	config = filepath.Join(t.TempDir(), "missing.json")
	t.Cleanup(func() { config = previous })
	require.Error(t, serverHandle(&cobra.Command{}, nil))
}
