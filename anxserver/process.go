package anxserver

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// stopTimeout is how long a stopped process may take before it is killed.
var stopTimeout = 5 * time.Second

// execProcess is an anx-server started with os/exec; its output goes to the
// Agent's.
type execProcess struct {
	command *exec.Cmd
	done    chan struct{}
	err     error
	once    sync.Once
}

func launchProcess(binary string, args []string) (Process, error) {
	command := exec.Command(binary, args...) // #nosec G204 -- the configured anx-server with arguments built here.
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	setProcessAttributes(command)
	if err := command.Start(); err != nil {
		return nil, err
	}
	process := &execProcess{command: command, done: make(chan struct{})}
	go func() {
		process.err = command.Wait()
		close(process.done)
	}()
	return process, nil
}

func (p *execProcess) Done() <-chan struct{} { return p.done }

func (p *execProcess) Err() error {
	select {
	case <-p.done:
		return p.err
	default:
		return nil
	}
}

func (p *execProcess) Stop() {
	p.once.Do(func() {
		select {
		case <-p.done:
			return
		default:
		}
		_ = terminate(p.command.Process)
		select {
		case <-p.done:
		case <-time.After(stopTimeout):
			_ = p.command.Process.Kill()
			<-p.done
		}
	})
}

func run(name string, args ...string) ([]byte, error) {
	out, err := exec.Command(name, args...).Output() // #nosec G204 -- the configured anx-server with arguments built here.
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return out, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return out, nil
}
