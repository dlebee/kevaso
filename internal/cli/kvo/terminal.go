package kvo

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/term"

	"kevaso.com/core/api/client"
)

// termOpts: kvo exec -t, kvo cp --max-size.
type termOpts struct {
	tty     bool
	maxSize string
}

// terminal runs `kvo exec -it silo NAME -- CMD` or `kvo ssh silo NAME` on a terminal: this one, in
// raw mode and followed as it resizes, when stdin is one; otherwise a 24x80 terminal fed from stdin.
// It returns the command's exit code. Leaving (the stream drops, Ctrl-C kills kvo) stops the
// command in the silo.
func terminal(ctx context.Context, c *client.Client, o opts, cmd string, stdin io.Reader, stdout io.Writer) (int, error) {
	usage := "exec -t needs silo NAME -- COMMAND"
	if cmd == "ssh" {
		usage = "ssh needs silo NAME (a login shell; for a command, kvo exec -it silo NAME -- CMD)"
	}
	if len(o.args) != 2 || (cmd == "ssh") != (len(o.command) == 0) {
		return 0, errors.New(usage)
	}
	if k, err := kindOf(o.args[0]); err != nil || k.Kind != "Silo" {
		return 0, errors.New(usage)
	}
	rows, cols := uint16(24), uint16(80)
	fd := -1
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fd = int(f.Fd())
		if w, h, err := term.GetSize(fd); err == nil && w > 0 && h > 0 {
			rows, cols = uint16(h), uint16(w)
		}
	}
	ns, name := defaultNS(o), o.args[1]
	var s *client.Session
	var err error
	if cmd == "ssh" {
		s, err = c.OpenShell(ctx, ns, name, rows, cols)
	} else {
		s, err = c.OpenExec(ctx, ns, name, client.ExecRequest{Command: o.command, TTY: true, Rows: rows, Cols: cols})
	}
	if err != nil {
		return -1, err
	}
	defer func() { _ = s.Close() }()
	if fd >= 0 {
		st, err := term.MakeRaw(fd)
		if err != nil {
			return -1, err
		}
		defer func() { _ = term.Restore(fd, st) }()
		stop := onResize(func() {
			if w, h, err := term.GetSize(fd); err == nil && w > 0 && h > 0 {
				_ = s.Resize(uint16(h), uint16(w))
			}
		})
		defer stop()
	}
	go s.SendStdin(stdin)
	return s.Wait(stdout, stdout) // a terminal has one output
}
