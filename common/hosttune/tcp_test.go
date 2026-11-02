package hosttune

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func procSys(t *testing.T, lowat, cc string) string {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "net/ipv4"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, notSentLowatPath), []byte(lowat), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, congestionPath), []byte(cc), 0o644))
	return root
}

func read(t *testing.T, root, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, name))
	require.NoError(t, err)
	return string(data)
}

func TestApplyTCPReplacesKernelDefaults(t *testing.T) {
	root := procSys(t, "4294967295\n", "cubic\n")
	changed, err := ApplyTCP(root)
	require.NoError(t, err)
	assert.Equal(t, []string{"tcp_notsent_lowat=131072", "tcp_congestion_control=bbr"}, changed)
	assert.Equal(t, "131072\n", read(t, root, notSentLowatPath))
	assert.Equal(t, "bbr\n", read(t, root, congestionPath))
}

func TestApplyTCPKeepsOperatorValues(t *testing.T) {
	root := procSys(t, "16384\n", "bbr2\n")
	changed, err := ApplyTCP(root)
	require.NoError(t, err)
	assert.Empty(t, changed)
	assert.Equal(t, "16384\n", read(t, root, notSentLowatPath))
	assert.Equal(t, "bbr2\n", read(t, root, congestionPath))
}

func TestApplyTCPReportsMissingSettings(t *testing.T) {
	changed, err := ApplyTCP(t.TempDir())
	assert.Error(t, err)
	assert.Empty(t, changed)
}
