package kvoadm

import (
	"context"
	"slices"
	"strings"
	"testing"

	"kevaso.com/core/internal/hostreset"
)

// runningHost is a reset host where kevasod (or its fence) may still run after the plan's stop
// step, which exits 0 whatever happened: runs says, for each look at what still runs (a script
// with pgrep naming kevasod.service), what it prints, given the steps run so far.
type runningHost struct {
	*fakeResetHost
	runs    func(ran []string) string
	looks   int
	later   string // from the third inspection on, if set
	inspect int
}

func (r *runningHost) Run(ctx context.Context, cmd string, in []byte) ([]byte, error) {
	if strings.Contains(cmd, "pgrep") && strings.Contains(cmd, "kevasod.service") {
		r.looks++
		return []byte(r.runs(r.ran)), nil
	}
	if cmd == hostreset.InspectScript {
		r.inspect++
		if r.later != "" && r.inspect > 2 {
			return []byte(r.later), nil
		}
	}
	return r.fakeResetHost.Run(ctx, cmd, in)
}

// destructive are the plan's steps that remove a silo's data: containers and their volumes, the
// volume group, Kevaso's files.
func destructiveRan(ran []string) []string {
	var out []string
	for _, s := range ran {
		if strings.HasPrefix(s, "step:remove") || strings.HasPrefix(s, "step:wipe") {
			out = append(out, s)
		}
	}
	return out
}

// Review claim 4: kvoadm reset took "stopped" from the stop step's exit 0 (`...; true`). kevasod or
// its fence still running (a unit left deactivating, a process systemd lost) refuses the reset
// before anything is removed, naming what runs.
func TestResetRefusesWhileKevasodStillRuns(t *testing.T) {
	rec := &hostreset.Record{State: baseState}
	pvs := []string{"/dev/loop3 " + hostreset.StorageImage}
	for _, still := range []string{"unit kevasod.service is deactivating", "unit kevaso-fence.service is active", "process 4242 /usr/local/bin/kevasod fence-watch"} {
		t.Run(still, func(t *testing.T) {
			h := newResetHost(t, rec, nil, pvs, []string{"kv-01-ab 1.00g"}, hostreset.Flags{WipeStorage: true})
			r := &runningHost{fakeResetHost: h, runs: func([]string) string { return still + "\n" }}
			out, err := reset(r, ResetOptions{Yes: true, WipeStorage: true}, "")
			if err == nil || !strings.Contains(err.Error(), still) {
				t.Fatalf("the reset went on while %s: %v\n%s", still, err, out)
			}
			if d := destructiveRan(h.ran); len(d) > 0 {
				t.Fatalf("removed %v while %s", d, still)
			}
		})
	}
}

// Review claim 4: the kill steps end in `true` too, and nothing looked after them. Right before
// the storage goes, kevasod is looked for again (and the host inspected again): one that runs
// again stops the reset before the volume group is removed.
func TestResetLooksAgainRightBeforeRemovingStorage(t *testing.T) {
	rec := &hostreset.Record{State: baseState}
	pvs := []string{"/dev/loop3 " + hostreset.StorageImage}
	storage := "step:remove volume group " + hostreset.VG + " (on the loop file only)"

	t.Run("kevasod runs again", func(t *testing.T) {
		h := newResetHost(t, rec, nil, pvs, []string{"kv-01-ab 1.00g"}, hostreset.Flags{WipeStorage: true})
		r := &runningHost{fakeResetHost: h, runs: func(ran []string) string {
			if slices.ContainsFunc(ran, func(s string) bool { return strings.HasPrefix(s, "step:delete links") }) {
				return "process 4243 /usr/local/bin/kevasod\n" // started again behind the reset's back
			}
			return ""
		}}
		out, err := reset(r, ResetOptions{Yes: true, WipeStorage: true}, "")
		if err == nil || !strings.Contains(err.Error(), "4243") {
			t.Fatalf("the reset went on while kevasod ran again: %v\n%s", err, out)
		}
		if slices.Contains(h.ran, storage) {
			t.Fatalf("the volume group was removed while kevasod ran again: %v", h.ran)
		}
	})

	t.Run("a silo is placed", func(t *testing.T) {
		h := newResetHost(t, rec, nil, pvs, []string{"kv-01-ab 1.00g"}, hostreset.Flags{WipeStorage: true})
		r := &runningHost{fakeResetHost: h, runs: func([]string) string { return "" },
			later: inspection(rec, []string{"vm kevaso-silo-cd34.service"}, pvs, []string{"kv-01-ab 1.00g", "kv-cd34 20.00g"}, baseState)}
		out, err := reset(r, ResetOptions{Yes: true, WipeStorage: true}, "")
		if err == nil || !strings.Contains(err.Error(), "kevaso-silo-cd34") {
			t.Fatalf("the reset went on with a silo it never showed: %v\n%s", err, out)
		}
		if slices.Contains(h.ran, storage) {
			t.Fatalf("the volume group was removed with a silo it never showed: %v", h.ran)
		}
	})

	t.Run("nothing changed", func(t *testing.T) {
		h := newResetHost(t, rec, nil, pvs, []string{"kv-01-ab 1.00g"}, hostreset.Flags{WipeStorage: true})
		r := &runningHost{fakeResetHost: h, runs: func([]string) string { return "" }}
		if out, err := reset(r, ResetOptions{Yes: true, WipeStorage: true}, ""); err != nil || !slices.Contains(h.ran, storage) {
			t.Fatalf("%v, ran %v\n%s", err, h.ran, out)
		}
	})
}
