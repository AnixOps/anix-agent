//go:build !linux

package anxserver

import (
	"os"
	"os/exec"
)

func setProcessAttributes(*exec.Cmd) {}

func terminate(process *os.Process) error {
	return process.Kill()
}
