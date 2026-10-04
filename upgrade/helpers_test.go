package upgrade

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// releaseKey is a test release key pair.
type releaseKey struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func newReleaseKey(t *testing.T) releaseKey {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return releaseKey{public: public, private: private}
}

func (k releaseKey) sign(data []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(k.private, data))
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// fakeAgent is a shell script that answers `version` like anix-agent:
// the product name, then "<codename> <version> (<intro>)". A broken one
// carries the BROKEN marker, which the fake systemctl reads as a unit
// that does not stay up.
func fakeAgent(version string, broken bool) []byte {
	marker := ""
	if broken {
		marker = "# BROKEN\n"
	}
	return []byte(fmt.Sprintf("#!/bin/sh\n%sif [ \"$1\" = version ]; then printf 'AnixOps Agent\\nAnixOps %s (AnixOps multi-core node agent) \\n'; fi\n", marker, version))
}

type zipEntry struct {
	name    string
	data    []byte
	symlink bool
}

func releaseZip(t *testing.T, entries ...zipEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		if entry.symlink {
			header.SetMode(os.ModeSymlink | 0o777)
		} else {
			header.SetMode(0o755)
		}
		w, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// fakeSystemctl writes a systemctl that logs its arguments to log and
// shows anix-agent.service active with one main process, unless the
// installed binary in lib is broken: then it is failed.
func fakeSystemctl(t *testing.T, dir, lib, log string) string {
	t.Helper()
	path := filepath.Join(dir, "systemctl")
	script := fmt.Sprintf(`#!/bin/sh
echo "$*" >> %q
case "$1" in
show)
  if grep -q BROKEN %q; then
    printf 'ActiveState=failed\nMainPID=0\n'
  else
    printf 'ActiveState=active\nMainPID=4242\n'
  fi ;;
is-active) echo active ;;
esac
exit 0
`, log, filepath.Join(lib, BinaryName))
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test files.
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
