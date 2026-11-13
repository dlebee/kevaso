package hostexec

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/sdk/kri"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func waitFor(t *testing.T, out *syncBuf, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("no %q in %q", want, out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A command on a terminal sees its size, follows a resize and returns its exit code.
func TestRunOnATerminal(t *testing.T) {
	pr, pw := io.Pipe()
	resize := make(chan kri.WindowSize, 1)
	out := &syncBuf{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type res struct {
		code int
		err  error
	}
	done := make(chan res, 1)
	go func() {
		code, err := Local{}.Run(ctx, Cmd{Name: "sh", Args: []string{"-c", `[ -t 0 ] && echo tty; stty size; read x; stty size; exit 3`},
			Stdin: pr, Stdout: out, TTY: &kri.TTY{Size: kri.WindowSize{Rows: 33, Cols: 77}, Resize: resize}})
		done <- res{code, err}
	}()
	waitFor(t, out, "33 77")
	resize <- kri.WindowSize{Rows: 50, Cols: 132}
	time.Sleep(100 * time.Millisecond) // the resize reaches the terminal before the next line
	_, _ = pw.Write([]byte("go\n"))
	r := <-done
	if r.err != nil || r.code != 3 {
		t.Fatalf("exit %d, %v", r.code, r.err)
	}
	if s := out.String(); !strings.Contains(s, "tty") || !strings.Contains(s, "50 132") {
		t.Fatalf("output %q", s)
	}
}
