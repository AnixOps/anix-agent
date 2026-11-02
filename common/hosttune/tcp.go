// Package hosttune applies the host TCP settings that keep a busy proxy node
// responsive (anx docs/FUTURE-IMPROVEMENTS.md F-26 / F-33).
//
// Under a full download the kernel otherwise queues megabytes of unsent data
// in each socket, so every other request on the node waits behind it: the
// public WAN bench measured 604 ms of loaded latency on an ANX-A node and
// 230 ms on VLESS, and tcp_notsent_lowat=131072 brought both back to the
// idle level in the lab. BBR keeps throughput up under random loss, where
// cubic backs off on every drop.
//
// Only defaults are changed: an operator's own values (a lower
// tcp_notsent_lowat, a congestion control other than cubic or reno) are
// kept.
package hosttune

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// NotSentLowat is the most unsent data a TCP socket keeps queued before it
// stops reporting itself writable.
const NotSentLowat = 131072

// CongestionControl is the congestion control set in place of the kernel
// defaults.
const CongestionControl = "bbr"

const (
	notSentLowatPath = "net/ipv4/tcp_notsent_lowat"
	congestionPath   = "net/ipv4/tcp_congestion_control"
)

// defaultControls are the kernel defaults that may be replaced.
var defaultControls = map[string]bool{"cubic": true, "reno": true}

// ApplyTCP applies the settings under root (/proc/sys) and returns what it
// changed, as "name=value" entries. A kernel without BBR keeps its congestion
// control and is not an error.
func ApplyTCP(root string) ([]string, error) {
	var changed []string
	var failed error

	lowat := filepath.Join(root, notSentLowatPath)
	if data, err := os.ReadFile(lowat); err != nil {
		failed = errors.Join(failed, err)
	} else if current, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err != nil {
		failed = errors.Join(failed, fmt.Errorf("%s: %w", lowat, err))
	} else if current > NotSentLowat {
		if err := os.WriteFile(lowat, []byte(strconv.Itoa(NotSentLowat)+"\n"), 0o644); err != nil {
			failed = errors.Join(failed, err)
		} else {
			changed = append(changed, "tcp_notsent_lowat="+strconv.Itoa(NotSentLowat))
		}
	}

	cc := filepath.Join(root, congestionPath)
	if data, err := os.ReadFile(cc); err != nil {
		failed = errors.Join(failed, err)
	} else if defaultControls[strings.TrimSpace(string(data))] {
		// Writing the name loads tcp_bbr on kernels built with it as a
		// module; a kernel without it refuses the write.
		if err := os.WriteFile(cc, []byte(CongestionControl+"\n"), 0o644); err == nil {
			changed = append(changed, "tcp_congestion_control="+CongestionControl)
		}
	}
	return changed, failed
}
