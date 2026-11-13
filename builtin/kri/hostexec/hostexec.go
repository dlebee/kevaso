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

// Run implements Runner.
func (Local) Run(ctx context.Context, c Cmd) (int, error) {
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
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
