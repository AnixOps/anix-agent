package conf

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// The AnixOps Agent's file system layout (owner decision H13, the O1
// installer of anix-control): the Agent runs as the user anixops-agent in a
// systemd sandbox (ProtectSystem=strict) and writes only below
//
//	/var/lib/anixops-agent   identity (pki), stream state (stream),
//	                         forwarding state (forward), plugin data (plugins)
//	/var/lib/anixops-gost    gost's configuration and link certificates
//	/run/anixops-agent       runtime files: plugin sockets (RuntimeDirectory)
//
// The configuration lives in /etc/anixops/agent and is read only.
const (
	// DefaultStateRoot holds the Agent's persistent state.
	DefaultStateRoot = "/var/lib/anixops-agent"
	// DefaultRuntimeRoot is the Agent unit's RuntimeDirectory.
	DefaultRuntimeRoot = "/run/anixops-agent"
	// DefaultPluginRoot is PluginRoot when the configuration leaves it out.
	DefaultPluginRoot = DefaultStateRoot + "/plugins"
	// DefaultPluginSocketDir is PluginSocketDir when the configuration
	// leaves it out.
	DefaultPluginSocketDir = DefaultRuntimeRoot + "/plugins"
)

// LegacyPath is a default directory of an earlier Agent release and the
// directory that replaced it.
type LegacyPath struct {
	Name string
	Old  string
	New  string
	kind legacyKind
}

type legacyKind int

const (
	legacyIdentity legacyKind = iota + 1
	legacyStream
	legacyPlugins
)

// LegacyDefaultPaths are the earlier default directories that move to the
// O1 layout. Only defaults move: a path the configuration names is used as
// it is.
var LegacyDefaultPaths = []LegacyPath{
	{Name: "agent identity (AgentIdentity.CertDir)", Old: "/var/lib/anix-agent/pki", New: DefaultAgentIdentityCertDir, kind: legacyIdentity},
	{Name: "stream state (AgentStream.StateDir)", Old: "/var/lib/anix-agent/stream", New: DefaultAgentStreamStateDir, kind: legacyStream},
	{Name: "plugin data (PluginRoot)", Old: "/var/lib/anixops/plugins", New: DefaultPluginRoot, kind: legacyPlugins},
}

// PluginRootDir is PluginRoot, defaulted.
func (a ApiConfig) PluginRootDir() string {
	if dir := strings.TrimSpace(a.PluginRoot); dir != "" {
		return dir
	}
	return DefaultPluginRoot
}

// PluginSocketBase is PluginSocketDir, defaulted.
func (a ApiConfig) PluginSocketBase() string {
	if dir := strings.TrimSpace(a.PluginSocketDir); dir != "" {
		return dir
	}
	return DefaultPluginSocketDir
}

// MigrationOutcome is what MigrateLegacyPath did.
type MigrationOutcome int

// Migration outcomes.
const (
	// MigrationNone: nothing to move (no old directory, or the new one
	// exists already and is kept).
	MigrationNone MigrationOutcome = iota
	// MigrationCopied: the old directory was copied to the new one; the old
	// one is left in place.
	MigrationCopied
)

// MigrateOptions tune MigrateLegacyPath.
type MigrateOptions struct {
	// UID and GID own every copied entry when Chown is set (an installer
	// running as root hands the copy to anixops-agent); otherwise a copy
	// made by root keeps the original owners and any other copy belongs to
	// the copying user.
	Chown    bool
	UID, GID int
}

// MigrateLegacyPath copies the directory old to new when old exists and
// new does not. The copy is made next to new and renamed into place, so new
// appears complete or not at all; old is never removed (identity material
// always keeps a copy, and an earlier release can still be started).
// Regular files, directories and symbolic links are copied with their
// modes; sockets, pipes and devices are skipped.
func MigrateLegacyPath(old, new string, opts MigrateOptions) (MigrationOutcome, error) {
	old, new = filepath.Clean(old), filepath.Clean(new)
	if old == new {
		return MigrationNone, nil
	}
	if _, err := os.Lstat(new); err == nil {
		return MigrationNone, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return MigrationNone, err
	}
	info, err := os.Lstat(old)
	if errors.Is(err, fs.ErrNotExist) {
		return MigrationNone, nil
	}
	if err != nil {
		return MigrationNone, err
	}
	if !info.IsDir() {
		return MigrationNone, fmt.Errorf("%s is not a directory", old)
	}
	parent := filepath.Dir(new)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return MigrationNone, err
	}
	staging, err := os.MkdirTemp(parent, "."+filepath.Base(new)+".migrating-")
	if err != nil {
		return MigrationNone, err
	}
	if err := copyTree(old, staging, new, opts); err != nil {
		_ = os.RemoveAll(staging)
		return MigrationNone, err
	}
	if err := os.Rename(staging, new); err != nil {
		_ = os.RemoveAll(staging)
		return MigrationNone, err
	}
	return MigrationCopied, nil
}

// copyTree copies the directory src into the existing directory dst; a
// symbolic link into src points below final, where dst ends up.
func copyTree(src, dst, final string, opts MigrateOptions) error {
	return filepath.WalkDir(src, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		switch mode := info.Mode(); {
		case mode.IsDir():
			if rel != "." {
				if err := os.Mkdir(target, 0o700); err != nil {
					return err
				}
			}
			if err := os.Chmod(target, mode.Perm()); err != nil {
				return err
			}
		case mode.IsRegular():
			if err := copyFile(path, target, mode.Perm()); err != nil {
				return err
			}
		case mode&fs.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			// A link into the old tree points into the copy.
			if filepath.IsAbs(link) {
				if inner, err := filepath.Rel(src, link); err == nil && inner != ".." && !strings.HasPrefix(inner, ".."+string(filepath.Separator)) {
					link = filepath.Join(final, inner)
				}
			}
			if err := os.Symlink(link, target); err != nil {
				return err
			}
		default:
			// Sockets, pipes and devices are runtime objects.
			return nil
		}
		return chownCopy(target, info, opts)
	})
}

func copyFile(src, dst string, perm fs.FileMode) error {
	in, err := os.Open(src) // #nosec G304 -- the walked legacy directory.
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- inside the staging directory.
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, perm)
}

// chownCopy gives a copied entry its owner: opts' when Chown is set, the
// original's when root copies.
func chownCopy(target string, info fs.FileInfo, opts MigrateOptions) error {
	if opts.Chown {
		return os.Lchown(target, opts.UID, opts.GID)
	}
	if os.Geteuid() != 0 {
		return nil
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return os.Lchown(target, int(stat.Uid), int(stat.Gid))
	}
	return nil
}

// MigrationReport is one legacy directory MigrateLegacyDefaults looked at.
type MigrationReport struct {
	Path    LegacyPath
	Outcome MigrationOutcome
	// Err is set when the copy failed: the configuration then keeps using
	// the old directory (it was set explicitly), so the Agent runs as
	// before.
	Err error
}

// MigrateLegacyDefaults moves the earlier default directories this
// configuration uses (fields left empty) to the O1 layout, once: when the
// old directory exists and the new one does not. When a copy fails the
// fields are pointed at the old directory, so nothing is lost and the Agent
// keeps running on it.
func (p *Conf) MigrateLegacyDefaults(opts MigrateOptions) []MigrationReport {
	return p.migrateLegacy(LegacyDefaultPaths, opts)
}

func (p *Conf) migrateLegacy(paths []LegacyPath, opts MigrateOptions) []MigrationReport {
	if p == nil {
		return nil
	}
	var apis []*ApiConfig
	for i := range p.NodeConfig {
		apis = append(apis, &p.NodeConfig[i].ApiConfig)
	}
	if p.Forward != nil && p.Forward.ForwardNode != nil {
		apis = append(apis, p.Forward.ForwardNode)
	}
	uses := func(path LegacyPath) []*string {
		var fields []*string
		for _, api := range apis {
			switch path.kind {
			case legacyIdentity:
				if strings.TrimSpace(api.AgentIdentity.CertDir) == "" {
					fields = append(fields, &api.AgentIdentity.CertDir)
				}
			case legacyStream:
				if strings.TrimSpace(api.AgentStream.StateDir) == "" {
					fields = append(fields, &api.AgentStream.StateDir)
				}
			case legacyPlugins:
				if api.PluginSupervisorEnabled && strings.TrimSpace(api.PluginRoot) == "" {
					fields = append(fields, &api.PluginRoot)
				}
			}
		}
		return fields
	}
	var reports []MigrationReport
	for _, path := range paths {
		fields := uses(path)
		if len(fields) == 0 {
			continue
		}
		outcome, err := MigrateLegacyPath(path.Old, path.New, opts)
		if err != nil {
			for _, field := range fields {
				*field = path.Old
			}
		}
		if err != nil || outcome != MigrationNone {
			reports = append(reports, MigrationReport{Path: path, Outcome: outcome, Err: err})
		}
	}
	return reports
}
