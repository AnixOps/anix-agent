package conf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultPathsFollowTheO1Layout(t *testing.T) {
	require.Equal(t, "/var/lib/anixops-agent/pki", DefaultAgentIdentityCertDir)
	require.Equal(t, "/var/lib/anixops-agent/stream", DefaultAgentStreamStateDir)
	require.Equal(t, "/var/lib/anixops-agent/forward", DefaultForwardStateDir)
	require.Equal(t, "/var/lib/anixops-agent/plugins", DefaultPluginRoot)
	require.Equal(t, "/run/anixops-agent/plugins", DefaultPluginSocketDir)
	var api ApiConfig
	require.Equal(t, DefaultPluginRoot, api.PluginRootDir())
	require.Equal(t, DefaultPluginSocketDir, api.PluginSocketBase())
}

func writeTree(t *testing.T, root string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "proxy-12"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "proxy-12", "identity.pem"), []byte("key and certificate"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "proxy-12", "ca.pem"), []byte("ca"), 0o640))
	require.NoError(t, os.Symlink(filepath.Join(root, "proxy-12", "ca.pem"), filepath.Join(root, "current")))
	require.NoError(t, os.Symlink("proxy-12/identity.pem", filepath.Join(root, "relative")))
}

func TestMigrateLegacyPathCopiesOnceAndKeepsTheOldDirectory(t *testing.T) {
	base := t.TempDir()
	old, next := filepath.Join(base, "anix-agent", "pki"), filepath.Join(base, "anixops-agent", "pki")
	writeTree(t, old)

	outcome, err := MigrateLegacyPath(old, next, MigrateOptions{})
	require.NoError(t, err)
	require.Equal(t, MigrationCopied, outcome)
	data, err := os.ReadFile(filepath.Join(next, "proxy-12", "identity.pem"))
	require.NoError(t, err)
	require.Equal(t, "key and certificate", string(data))
	for path, mode := range map[string]os.FileMode{
		next: 0o700, filepath.Join(next, "proxy-12"): 0o700,
		filepath.Join(next, "proxy-12", "identity.pem"): 0o600, filepath.Join(next, "proxy-12", "ca.pem"): 0o640,
	} {
		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, mode, info.Mode().Perm(), path)
	}
	link, err := os.Readlink(filepath.Join(next, "current"))
	require.NoError(t, err)
	require.Equal(t, filepath.Join(next, "proxy-12", "ca.pem"), link, "a link into the old tree points into the copy")
	link, err = os.Readlink(filepath.Join(next, "relative"))
	require.NoError(t, err)
	require.Equal(t, "proxy-12/identity.pem", link)
	_, err = os.Stat(filepath.Join(old, "proxy-12", "identity.pem"))
	require.NoError(t, err, "identity material keeps its copy in the old directory")
	entries, err := os.ReadDir(filepath.Dir(next))
	require.NoError(t, err)
	require.Len(t, entries, 1, "no staging directory left behind")

	// Once only: an existing new directory is never touched.
	require.NoError(t, os.WriteFile(filepath.Join(old, "proxy-12", "identity.pem"), []byte("changed"), 0o600))
	outcome, err = MigrateLegacyPath(old, next, MigrateOptions{})
	require.NoError(t, err)
	require.Equal(t, MigrationNone, outcome)
	data, err = os.ReadFile(filepath.Join(next, "proxy-12", "identity.pem"))
	require.NoError(t, err)
	require.Equal(t, "key and certificate", string(data))
}

func TestMigrateLegacyPathWithoutAnOldDirectory(t *testing.T) {
	base := t.TempDir()
	outcome, err := MigrateLegacyPath(filepath.Join(base, "missing"), filepath.Join(base, "new"), MigrateOptions{})
	require.NoError(t, err)
	require.Equal(t, MigrationNone, outcome)
	_, err = os.Stat(filepath.Join(base, "new"))
	require.True(t, os.IsNotExist(err))
}

func TestMigrateLegacyDefaultsOnlyMovesDefaultsAndFallsBack(t *testing.T) {
	base := t.TempDir()
	identity := LegacyPath{Name: "identity", Old: filepath.Join(base, "old", "pki"), New: filepath.Join(base, "new", "pki"), kind: legacyIdentity}
	// The stream's new parent is a file: the copy fails.
	blocked := filepath.Join(base, "blocked")
	require.NoError(t, os.WriteFile(blocked, nil, 0o600))
	stream := LegacyPath{Name: "stream", Old: filepath.Join(base, "old", "stream"), New: filepath.Join(blocked, "stream"), kind: legacyStream}
	plugins := LegacyPath{Name: "plugins", Old: filepath.Join(base, "old", "plugins"), New: filepath.Join(base, "new", "plugins"), kind: legacyPlugins}
	writeTree(t, identity.Old)
	writeTree(t, stream.Old)
	writeTree(t, plugins.Old)

	c := &Conf{NodeConfig: []NodeConfig{
		{ApiConfig: ApiConfig{NodeID: 1}},
		{ApiConfig: ApiConfig{NodeID: 2, AgentIdentity: AgentIdentityConfig{CertDir: "/srv/pki"}}},
	}}
	reports := c.migrateLegacy([]LegacyPath{identity, stream, plugins}, MigrateOptions{})
	require.Len(t, reports, 2, "plugins are not used: no supervisor")
	require.Equal(t, MigrationCopied, reports[0].Outcome)
	require.NoError(t, reports[0].Err)
	require.Error(t, reports[1].Err)
	// The default user moved; the explicit path stays.
	require.Equal(t, "", c.NodeConfig[0].ApiConfig.AgentIdentity.CertDir)
	require.Equal(t, "/srv/pki", c.NodeConfig[1].ApiConfig.AgentIdentity.CertDir)
	// The failed copy keeps the Agent on the old directory.
	require.Equal(t, stream.Old, c.NodeConfig[0].ApiConfig.AgentStream.StateDir)
	require.Equal(t, stream.Old, c.NodeConfig[1].ApiConfig.AgentStream.StateDir)
	_, err := os.Stat(plugins.New)
	require.True(t, os.IsNotExist(err))
}
