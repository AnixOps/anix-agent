//go:build !unix

package pki

import "io/fs"

// ownedByCurrentUser cannot read POSIX ownership here; the mode check and
// the directory's ACLs protect the files.
func ownedByCurrentUser(fs.FileInfo) bool { return true }
