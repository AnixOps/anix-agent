//go:build !windows

package conf

import (
	"io/fs"
	"syscall"
)

// fileOwner answers the owner of a file.
func fileOwner(info fs.FileInfo) (uid, gid int, ok bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(stat.Uid), int(stat.Gid), true
}
