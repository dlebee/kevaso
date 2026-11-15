package cloudhypervisor

import (
	"context"
	"errors"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// review-batch3 (D), item G (1): a unit wedged in a state other than inactive or failed after
// its process exited (a stop job that never finishes) was "running" for ever, whatever ran: never
// stopped, reset, started again or deleted. It is decided from the processes, and the unit is
// cleaned up so the silo can move on.
func TestAUnitWedgedWithNothingRunningIsStoppedAndCleanedUp(t *testing.T) {
	const cg = "/system.slice/kevaso-silo-x.service"
	for _, state := range []string{"deactivating", "activating", "reloading", "maintenance"} {
		t.Run(state, func(t *testing.T) {
			ctx := context.Background()
			h := newFakeHost()
			r := newRuntime(t, h)
			sp := spec("web")
			if err := r.Create(ctx, sp); err != nil {
				t.Fatal(err)
			}
			if err := r.Start(ctx, sp.ID); err != nil {
				t.Fatal(err)
			}
			n := NamesFor(sp.ID)
			h.files["/sys/fs/cgroup"+cg+"/cgroup.procs"] = []byte("\n")
			h.answer = func(cmd string) (string, error) {
				switch {
				case cmd == "systemctl is-active "+n.Unit:
					return state, errors.New("exit 3")
				case strings.HasPrefix(cmd, "systemctl show") && strings.HasSuffix(cmd, n.Unit):
					return "MainPID=0\nControlGroup=" + cg, nil
				}
				return "", nil // pgrep: nothing
			}
			before := len(h.commands())
			st, err := r.Status(ctx, sp.ID)
			if err != nil || st.State == kri.Running {
				t.Fatalf("Status %s %v: its unit is %q with no process of it left: it can never be stopped, reset or started", st.State, err, state)
			}
			if i := indexOf(h.commands()[before:], "systemctl reset-failed "+n.Unit); i < 0 {
				t.Fatalf("the wedged unit wasn't cleaned up: %v", h.commands()[before:])
			}
			if err := r.Kill(ctx, sp.ID); err != nil {
				t.Fatalf("Kill: %v", err)
			}
		})
	}
}

// review-batch3 (D), item G (2): for an inactive or failed unit, a cgroup.procs that isn't there
// was read as an empty cgroup: on a host whose cgroups are elsewhere, Status said Stopped while
// the VMM ran. The VMM is also looked for itself (its API socket on its command line), and a
// look that can't be told is "running".
func TestAMissingCgroupIsNoProofTheVMMIsGone(t *testing.T) {
	for _, pgrep := range []struct {
		name string
		out  string
		err  error
	}{
		{"the VMM found by its socket", "4242\n", nil},
		{"pgrep doesn't answer", "", errors.New("pgrep: not found")},
	} {
		t.Run(pgrep.name, func(t *testing.T) {
			ctx := context.Background()
			h := newFakeHost()
			r := newRuntime(t, h)
			sp := spec("web")
			if err := r.Create(ctx, sp); err != nil {
				t.Fatal(err)
			}
			if err := r.Start(ctx, sp.ID); err != nil {
				t.Fatal(err)
			}
			n := NamesFor(sp.ID)
			h.answer = func(cmd string) (string, error) {
				switch {
				case cmd == "systemctl is-active "+n.Unit:
					return "inactive", errors.New("exit 3")
				case strings.HasPrefix(cmd, "systemctl show") && strings.HasSuffix(cmd, n.Unit):
					return "MainPID=0\nControlGroup=/system.slice/" + n.Unit, nil // no cgroup.procs at that path here
				case strings.HasPrefix(cmd, "pgrep ") && strings.Contains(cmd, n.Socket):
					return pgrep.out, pgrep.err
				}
				return "", nil
			}
			if err := r.Kill(ctx, sp.ID); err == nil {
				t.Fatal("Kill said done while the VMM may run")
			}
			st, err := r.Status(ctx, sp.ID)
			if err != nil || st.State != kri.Running {
				t.Fatalf("Status %s %v while the VMM may run: a fence counts it stopped", st.State, err)
			}
		})
	}
}
