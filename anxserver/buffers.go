package anxserver

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The QUIC listener's buffers (anx ANX-LINE-ONBOARDING §6, BOUNDARY
// `--quic-sockbuf`, `--quic-dgram-buf`).
const (
	QUICSocketBuffer   = 8 << 20
	QUICDatagramBuffer = 1 << 20
)

// SocketBufferLimits are the sysctls that cap a socket's buffers.
var SocketBufferLimits = []string{"net/core/rmem_max", "net/core/wmem_max"}

// RaiseSocketBuffers raises each limit under root (/proc/sys) to at least
// QUICSocketBuffer; a higher limit is kept.
func RaiseSocketBuffers(root string) error {
	var failed error
	for _, name := range SocketBufferLimits {
		path := filepath.Join(root, name)
		data, err := os.ReadFile(path)
		if err != nil {
			failed = errors.Join(failed, err)
			continue
		}
		current, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			failed = errors.Join(failed, fmt.Errorf("%s: %w", path, err))
			continue
		}
		if current >= QUICSocketBuffer {
			continue
		}
		if err := os.WriteFile(path, []byte(strconv.Itoa(QUICSocketBuffer)+"\n"), 0o644); err != nil {
			failed = errors.Join(failed, err)
		}
	}
	return failed
}
