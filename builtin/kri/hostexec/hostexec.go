// Package hostexec runs commands and touches files on the host for the built-in runtimes, behind an
// interface, so command sequences are unit-tested anywhere and the real thing runs only as root on
// Linux.
package hostexec

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"kevaso.com/core/sdk/kri"
)

// Cmd is one command on the host.
type Cmd struct {
	Name   string
	Args   []string
	Env    []string // added to a minimal environment
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// TTY runs the command on a new pseudo-terminal (stdin, stdout and stderr all on it), resized
	// as TTY.Resize says: a CLI like docker exec -t wants its own terminal to pass on.
	TTY *kri.TTY
}

// Runner runs commands and touches files. The real one is Local; tests use a fake.
type Runner interface {
	Run(ctx context.Context, c Cmd) (exitCode int, err error)
	WriteFile(path string, data []byte, mode os.FileMode) error
	ReadFile(path string) ([]byte, error)
	RemoveAll(path string) error
	Glob(pattern string) ([]string, error)
}

// Local runs on this machine (kevasod is root).
type Local struct{}

// WaitDelay bounds how long Run waits, once the command exited or its context ended, for its
// output to close: a process it started that keeps the output open (a daemon it forked, a
// grandchild a kill missed) otherwise holds Run, and the agent's reconcile, until that process
// ends; kevasod's stop then waits for it too.
const WaitDelay = 5 * time.Second

var (
	dirOnce sync.Once
	dirPath string
	dirErr  error
)

func commandDir() (string, error) {
	dirOnce.Do(func() {
		dirPath, dirErr = os.MkdirTemp("", "kevaso-hostexec-")
	})
	return dirPath, dirErr
}

// SetCommandDir runs cmd in an empty directory. A relative path in its arguments is that
// directory, not the process's working directory (for kevasod, the host's root).
func SetCommandDir(cmd *exec.Cmd) error {
	dir, err := commandDir()
	if err != nil {
		return err
	}
	cmd.Dir = dir // no relative path resolves against the host's root
	return nil
}

// Run implements Runner.
func (Local) Run(ctx context.Context, c Cmd) (int, error) {
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	if err := SetCommandDir(cmd); err != nil {
		return -1, err
	}
	cmd.WaitDelay = WaitDelay
	cmd.Env = append([]string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}, c.Env...)
	if c.TTY != nil {
		return runTTY(cmd, c)
	}
	cmd.Stdout, cmd.Stderr = c.Stdout, c.Stderr
	// Stdin through our own pipe: exec.Cmd would otherwise wait for the copy to finish, so a caller
	// that never closes stdin (an interactive kvo exec) would hang after the command exited.
	var stdin io.WriteCloser
	if c.Stdin != nil {
		var err error
		if stdin, err = cmd.StdinPipe(); err != nil {
			return -1, err
		}
	}
	if err := cmd.Start(); err != nil {
		return -1, err
	}
	if stdin != nil {
		go func() {
			_, _ = io.Copy(stdin, c.Stdin)
			_ = stdin.Close()
		}()
	}
	err := cmd.Wait()
	if errors.Is(err, exec.ErrWaitDelay) && ctx.Err() == nil && cmd.ProcessState != nil {
		err = nil // it exited; a process it left holds its output (that output is cut)
		if code := cmd.ProcessState.ExitCode(); code != 0 {
			return code, nil
		}
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}

// WriteFile implements Runner.
func (Local) WriteFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadFile implements Runner.
func (Local) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

// RemoveAll implements Runner.
func (Local) RemoveAll(path string) error { return os.RemoveAll(path) }

// Glob implements Runner.
func (Local) Glob(pattern string) ([]string, error) { return filepath.Glob(pattern) }
