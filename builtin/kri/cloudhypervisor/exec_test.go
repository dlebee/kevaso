package cloudhypervisor

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"kevaso.com/core/builtin/kri/hostexec"
	"kevaso.com/core/sdk/kri"
)

func guestRuntime(t *testing.T) (*Runtime, *guest) {
	t.Helper()
	r, _ := runningRuntime(t, ed25519Pub(t))
	g := startGuest(t, r.ExecKey.PublicKey())
	r2, _ := runningRuntime(t, g.hostKey.PublicKey())
	r2.ExecKey, r2.ExecPub = r.ExecKey, r.ExecPub
	r2.DialSSH = func(ctx context.Context, _ string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
		return dialSSH(ctx, g.addr, cfg)
	}
	return r2, g
}

func (g *guest) waitReq(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		g.mu.Lock()
		ok := slices.Contains(g.reqs, want)
		reqs := slices.Clone(g.reqs)
		g.mu.Unlock()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %q in the guest's requests %v", want, reqs)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A terminal: the guest gets a pty of the client's size and every resize; cancelling the exec
// (the client went away) signals the command and sweeps the guest for its marker.
func TestExecOnATerminalResizesAndStopsWhenCancelled(t *testing.T) {
	r, g := guestRuntime(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resize := make(chan kri.WindowSize, 1)
	errc := make(chan error, 1)
	go func() {
		_, err := r.Exec(ctx, id("web"), kri.ExecRequest{Command: []string{"sleep", "1000"}, Stdin: strings.NewReader(""),
			TTY: &kri.TTY{Size: kri.WindowSize{Rows: 33, Cols: 101}, Resize: resize}})
		errc <- err
	}()
	g.waitReq(t, "pty-req xterm-256color 101x33")
	resize <- kri.WindowSize{Rows: 50, Cols: 132}
	g.waitReq(t, "window-change 132x50")
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("exec returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exec didn't return after its context was cancelled")
	}
	g.waitReq(t, "signal KILL")
	deadline := time.Now().Add(5 * time.Second)
	for {
		g.mu.Lock()
		ran := slices.Clone(g.ran)
		g.mu.Unlock()
		if len(ran) == 2 {
			marker := strings.Fields(strings.TrimPrefix(ran[0], "sudo -n -- env "+kri.ExecMarkerEnv+"="))[0]
			want := "sudo -n -- sh -c " + shellQuote([]string{hostexec.SweepScript}) + " sh " + marker
			if ran[1] != want {
				t.Fatalf("sweep ran %q, want %q", ran[1], want)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the guest ran %v, want the command then the sweep", ran)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
