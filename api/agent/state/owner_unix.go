//go:build unix

package state

import (
	"io/fs"
	"os"
	"syscall"
)

// ownedByCurrentUser reports whether the Agent's effective user owns the
// file (root for the installed service).
func ownedByCurrentUser(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}
