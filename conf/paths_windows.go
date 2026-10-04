package conf

import "io/fs"

// fileOwner answers no owner: Windows has no uid and gid.
func fileOwner(fs.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }
