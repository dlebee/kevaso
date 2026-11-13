package container

import (
	"context"
	"errors"
	"slices"
	"testing"

	"kevaso.com/core/builtin/kri/hostexec"
)

// killedBeforeRestart is the host as kevasod saw it when it was stopped right after writing
// daemon.json: dockerd's restart never happened (its context cancelled).
type killedBeforeRestart struct{ *fake }

func (k killedBeforeRestart) Run(ctx context.Context, c hostexec.Cmd) (int, error) {
	if c.Name == "systemctl" && slices.Equal(c.Args, []string{"restart", "docker"}) {
		return -1, errors.New("signal: killed")
	}
	return k.fake.Run(ctx, c)
}

// daemon.json written, dockerd never restarted: the next Install saw the file already as it
// wanted it and restarted nothing, so dockerd ran on without Kevaso's OCI runtime (env secrets
// went into the engine's config instead) and with its own firewall handling on.
func TestADaemonConfigWrittenButNotAppliedIsAppliedOnTheNextInstall(t *testing.T) {
	ctx := context.Background()
	f := dockerHost()
	r := runtime(t, f)
	r.Host = killedBeforeRestart{f}
	if err := r.Install(ctx, nil); err == nil {
		t.Fatal("the first install should have been cut off")
	}
	r2 := runtime(t, f) // kevasod started again on the same host
	before := len(f.cmds)
	if err := r2.Install(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.cmds[before:], "systemctl restart docker") {
		t.Fatalf("dockerd never got its new configuration: %v", f.cmds[before:])
	}
	// Once applied, a later start restarts nothing (silos keep running).
	before = len(f.cmds)
	if err := runtime(t, f).Install(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(f.cmds[before:], "systemctl restart docker") {
		t.Fatal("dockerd restarted with nothing changed")
	}
}
