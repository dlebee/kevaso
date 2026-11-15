package kvoadm

import (
	"context"
	"slices"
	"strings"
	"testing"

	"kevaso.com/core/internal/hostreset"
)

// changingHost is a reset host where a silo is placed (and its volume made) after the first
// inspection, while kvoadm waits for its yes: every later inspection shows it.
type changingHost struct {
	*fakeResetHost
	later   string
	looked  int
	scripts []string
}

func (c *changingHost) Run(ctx context.Context, cmd string, in []byte) ([]byte, error) {
	c.scripts = append(c.scripts, cmd)
	if cmd == hostreset.InspectScript {
		c.looked++
		if c.looked > 1 {
			return []byte(c.later), nil
		}
	}
	return c.fakeResetHost.Run(ctx, cmd, in)
}

// Review (check-then-act) claim 3: the reset looked, then waited at its prompt, then removed every
// volume without looking again. kevasod is stopped first (nothing new is placed), the host is
// looked at again, and a silo or volume that wasn't shown stops the reset before anything is
// removed; kevasod is started again.
func TestResetLooksAgainBeforeRemovingAnything(t *testing.T) {
	rec := &hostreset.Record{State: baseState}
	pvs := []string{"/dev/loop3 " + hostreset.StorageImage}
	h := newResetHost(t, rec, nil, pvs, nil, hostreset.Flags{})
	c := &changingHost{fakeResetHost: h, later: inspection(rec, []string{"vm kevaso-silo-ab12.service"}, pvs, []string{"kv-ab12 20.00g"}, baseState)}
	out, err := reset(c, ResetOptions{}, "yes\n")
	if err == nil || !strings.Contains(err.Error(), "kevaso-silo-ab12") {
		t.Fatalf("a silo placed while kvoadm waited didn't stop the reset: %v\n%s", err, out)
	}
	if c.looked < 2 {
		t.Fatal("never looked again before removing anything")
	}
	if steps := slices.DeleteFunc(slices.Clone(h.ran), func(s string) bool { return !strings.HasPrefix(s, "step:") }); !slices.Equal(steps, []string{"step:stop kevasod and the fence"}) {
		t.Fatalf("ran more than stopping kevasod before looking again: %v", h.ran)
	}
	if !slices.Contains(c.scripts, hostreset.StartAgainScript) {
		t.Fatal("kevasod wasn't started again after the reset stopped")
	}
	// Nothing new: the reset goes on as before.
	h = newResetHost(t, rec, nil, pvs, []string{"kv-01-ab 1.00g"}, hostreset.Flags{})
	if out, err := reset(h, ResetOptions{Yes: true}, ""); err != nil || !slices.Contains(h.ran, "step:remove volume group kevaso (on the loop file only)") {
		t.Fatalf("%v, ran %v\n%s", err, h.ran, out)
	}
}
