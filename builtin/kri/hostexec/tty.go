package hostexec

import (
	"errors"
	"io"
	"os/exec"
	"time"

	"github.com/creack/pty"

	"kevaso.com/core/sdk/kri"
)

// runTTY runs cmd on a new pseudo-terminal: c.Stdin is typed into it, everything it shows goes to
// c.Stdout, and resizes reach it as SIGWINCH.
func runTTY(cmd *exec.Cmd, c Cmd) (int, error) {
	f, err := pty.StartWithSize(cmd, winsize(c.TTY.Size))
	if err != nil {
		return -1, err
	}
	done := make(chan struct{})
	resized := make(chan struct{})
	defer func() { close(done); <-resized; _ = f.Close() }()
	go func() {
		defer close(resized)
		for {
			select {
			case <-done:
				return
			case sz, ok := <-c.TTY.Resize:
				if !ok {
					return
				}
				_ = pty.Setsize(f, winsize(sz))
			}
		}
	}()
	if c.Stdin != nil {
		go func() { _, _ = io.Copy(f, c.Stdin) }()
	}
	out := c.Stdout
	if out == nil {
		out = io.Discard
	}
	copied := make(chan struct{})
	go func() { _, _ = io.Copy(out, f); close(copied) }()
	err = cmd.Wait()
	// The last output is still in the terminal; a process left in the background may hold it open
	// for ever, so don't wait long.
	select {
	case <-copied:
	case <-time.After(time.Second):
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

func winsize(s kri.WindowSize) *pty.Winsize {
	if s.Rows == 0 || s.Cols == 0 {
		s = kri.WindowSize{Rows: 24, Cols: 80}
	}
	return &pty.Winsize{Rows: s.Rows, Cols: s.Cols}
}
