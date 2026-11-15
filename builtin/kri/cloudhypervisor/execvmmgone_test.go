package cloudhypervisor

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"kevaso.com/core/sdk/kri"
)

// killable answers the host's systemctl as for a VMM that runs until killed is set, then as for
// one that exited (its unit failed, nothing of it left: no MainPID, no lock, no process).
func killable(h *fakeHost, killed *atomic.Bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.answer = func(cmd string) (string, error) {
		if strings.HasPrefix(cmd, "systemctl is-active") {
			if killed.Load() {
				return "failed", errors.New("exit 3")
			}
			return "active", nil
		}
		return "", nil
	}
}

// Found on the machines (TestMetal2BackoffHoldsNoClaim): a VMM killed while an Exec waited for its
// guest's SSH (a guest still booting after a restart). The wait went on for ever, since nothing
// looked whether the VMM still ran, and with it the silo's reconcile. The Exec must end once the
// VMM is gone.
func TestAnExecWaitingForTheGuestEndsWhenTheVMMExits(t *testing.T) {
	r, h := runningRuntime(t, ed25519Pub(t))
	r.ExecCheck = 50 * time.Millisecond
	var killed atomic.Bool
	killable(h, &killed)
	r.DialSSH = func(ctx context.Context, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		return nil, errors.New("connect: connection refused") // its SSH isn't up (yet, or ever)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		_, err := r.Exec(ctx, id("web"), kri.ExecRequest{Command: []string{"true"}})
		errc <- err
	}()
	time.Sleep(100 * time.Millisecond)
	killed.Store(true) // systemctl kill -s KILL --kill-whom=main
	select {
	case err := <-errc:
		if !errors.Is(err, errVMMGone) {
			t.Fatalf("exec returned %v, want that its VMM is gone", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an exec into a VM whose VMM exited still waits for its guest's SSH")
	}
}

// The same with the command already running in the guest: a session whose guest is gone has no
// end of its own (nothing answers on its TCP connection). Its VMM exiting ends it.
func TestAnExecRunningInTheGuestEndsWhenTheVMMExits(t *testing.T) {
	r, g := guestRuntime(t)
	r.ExecCheck = 50 * time.Millisecond
	h := r.Host.(*fakeHost)
	var killed atomic.Bool
	killable(h, &killed)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		_, err := r.Exec(ctx, id("web"), kri.ExecRequest{Command: []string{"sleep", "1000"}})
		errc <- err
	}()
	g.waitReq(t, "exec")
	killed.Store(true)
	select {
	case err := <-errc:
		if !errors.Is(err, errVMMGone) {
			t.Fatalf("exec returned %v, want that its VMM is gone", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an exec in a VM whose VMM exited still runs")
	}
}
