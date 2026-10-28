//go:build linux

package anxserver

import (
	"os"
	"os/exec"
	"syscall"
)

// setProcessAttributes ends anx-server with the Agent.
func setProcessAttributes(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}

func terminate(process *os.Process) error {
	return process.Signal(syscall.SIGTERM)
}
