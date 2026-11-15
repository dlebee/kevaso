package cloudhypervisor

import (
	"context"
	"errors"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// Stopped means the VMM's process is gone (review of K-094, claim 1). A SIGKILL can leave the
// unit deactivating (a stop timeout, a process in D state), or failed with a process still in its
// cgroup: the fences ask Kill and then Status, and both must say it still runs, whether or not
// its state file can be read.
func TestAVMMThatHasNotGoneIsNeverStopped(t *testing.T) {
	const cg = "/system.slice/kevaso-silo-x.service"
	cases := []struct {
		name   string
		active string // what systemctl is-active says after the kill
		show   string // what systemctl show says
		procs  string // the unit's cgroup.procs ("" absent)
	}{
		{"deactivating", "deactivating", "MainPID=4242\nControlGroup=" + cg, "4242\n"},
		{"activating", "activating", "MainPID=4242\nControlGroup=" + cg, "4242\n"},
		{"reloading", "reloading", "MainPID=4242\nControlGroup=" + cg, "4242\n"},
		{"failed with its main process", "failed", "MainPID=4242\nControlGroup=" + cg, "4242\n"},
		{"failed with a process left in its cgroup", "failed", "MainPID=0\nControlGroup=" + cg, "4243\n"},
		{"inactive with a process left in its cgroup", "inactive", "MainPID=0\nControlGroup=" + cg, "4243\n"},
		{"no answer from systemctl", "", "", ""},
	}
	for _, tc := range cases {
		for _, readable := range []bool{true, false} {
			name := tc.name
			if !readable {
				name += ", state unreadable"
			}
			t.Run(name, func(t *testing.T) {
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
				if tc.procs != "" {
					h.files["/sys/fs/cgroup"+cg+"/cgroup.procs"] = []byte(tc.procs)
				}
				h.answer = func(cmd string) (string, error) {
					switch {
					case cmd == "systemctl is-active "+n.Unit:
						if tc.active == "" {
							return "", errors.New("systemctl: no answer")
						}
						return tc.active, errors.New("exit 3")
					case strings.HasPrefix(cmd, "systemctl show") && strings.HasSuffix(cmd, n.Unit):
						if tc.show == "" {
							return "", errors.New("systemctl: no answer")
						}
						return tc.show, nil
					}
					return "", nil
				}
				if !readable {
					h.files[n.Dir+"/silo.json"] = []byte(`{"id": `)
				}
				if err := r.Kill(ctx, sp.ID); err == nil {
					t.Fatalf("Kill said done while the VMM's unit is %q and its process may run", tc.active)
				}
				st, err := r.Status(ctx, sp.ID)
				if err != nil || st.State != kri.Running {
					t.Fatalf("Status %s %v while the VMM's unit is %q and its process may run: a fence counts it stopped", st.State, err, tc.active)
				}
			})
		}
	}
}

// The other side: a unit that is inactive or failed, with no main process and an empty or gone
// cgroup, is stopped, and Kill says so.
func TestAVMMThatHasGoneIsStopped(t *testing.T) {
	for _, active := range []string{"inactive", "failed"} {
		t.Run(active, func(t *testing.T) {
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
			h.files["/sys/fs/cgroup/system.slice/x.service/cgroup.procs"] = []byte("\n")
			h.answer = func(cmd string) (string, error) {
				switch {
				case cmd == "systemctl is-active "+n.Unit:
					return active, errors.New("exit 3")
				case strings.HasPrefix(cmd, "systemctl show") && strings.HasSuffix(cmd, n.Unit):
					return "MainPID=0\nControlGroup=/system.slice/x.service", nil
				}
				return "", nil
			}
			if err := r.Kill(ctx, sp.ID); err != nil {
				t.Fatal(err)
			}
			st, err := r.Status(ctx, sp.ID)
			if err != nil || st.State == kri.Running {
				t.Fatalf("Status %s %v: its VMM is gone", st.State, err)
			}
		})
	}
}

// Reset makes the root disk afresh only once the VMM is gone: a stop that leaves the unit
// deactivating refuses the reset before lvremove.
func TestResetNeverRemovesTheDiskUnderAVMMThatHasNotGone(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	r := newRuntime(t, h)
	sp := spec("web")
	if err := r.Create(ctx, sp); err != nil {
		t.Fatal(err)
	}
	n := NamesFor(sp.ID)
	h.answer = func(cmd string) (string, error) {
		if cmd == "systemctl is-active "+n.Unit {
			return "deactivating", errors.New("exit 3")
		}
		if strings.HasPrefix(cmd, "lvs ") || strings.HasPrefix(cmd, "lvremove") || strings.HasPrefix(cmd, "lvcreate") {
			b, err := h.lv(strings.Fields(cmd)[0], strings.Fields(cmd)[1:])
			return string(b), err
		}
		return "", nil
	}
	before := len(h.commands())
	if err := r.Reset(ctx, sp); err == nil {
		t.Fatal("Reset went on while the VMM's unit is deactivating")
	}
	if i := indexOf(h.commands()[before:], "lvremove"); i >= 0 {
		t.Fatalf("the root volume was removed under a VMM that may run: %v", h.commands()[before:])
	}
}

// Review claim 3: the agent's reset gate is asked inside Reset, after the VM is stopped and gone
// and right before its root volume is made afresh; a gate that refuses leaves the volume.
func TestResetAsksItsGateRightBeforeTheDisk(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	r := newRuntime(t, h)
	sp := spec("web")
	if err := r.Create(ctx, sp); err != nil {
		t.Fatal(err)
	}
	n := NamesFor(sp.ID)
	refused := errors.New("taken back")
	var at int
	before := len(h.commands())
	err := r.ResetGated(ctx, sp, func(context.Context) error { at = len(h.commands()); return refused })
	if !errors.Is(err, refused) {
		t.Fatalf("ResetGated: %v, want the gate's error", err)
	}
	cmds := h.commands()[before:]
	if indexOf(cmds, "lvremove") >= 0 || !h.lvs[n.LV] {
		t.Fatalf("the root volume was removed although the gate refused: %v", cmds)
	}
	if stop := indexOf(cmds, "systemctl stop "+n.Unit); stop < 0 || stop >= at-before {
		t.Fatalf("the gate was asked before the VMM was stopped: %v (gate at %d)", cmds, at-before)
	}
	at = -1
	if err := r.ResetGated(ctx, sp, func(context.Context) error { at = len(h.commands()); return nil }); err != nil {
		t.Fatal(err)
	}
	if cmds := h.commands()[at:]; indexOf(cmds, "lvremove") < 0 {
		t.Fatalf("with the gate open, the reset made no fresh disk after it: %v", cmds)
	}
}
