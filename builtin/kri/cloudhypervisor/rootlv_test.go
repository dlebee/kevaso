package cloudhypervisor

import (
	"context"
	"strings"
	"testing"
)

// Review claim B: a root logical volume that is there with no state file (silo.json lost, the
// rest of the silo's folder gone) is data whose owner can't be proven: Create never removes it,
// and says why instead of making the silo.
func TestCreateNeverRemovesARootVolumeItDidNotMake(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	r := newRuntime(t, h)
	sp := spec("db")
	n := NamesFor(sp.ID)
	h.lvs[n.LV] = true // the disk of an earlier copy of this silo, its state gone
	before := len(h.commands())
	err := r.Create(ctx, sp)
	for _, c := range h.commands()[before:] {
		if inner := hostCmd(c); strings.HasPrefix(inner, "lvremove") && strings.Contains(inner, n.LV) {
			t.Fatalf("Create removed a root volume it didn't make: %v", h.commands()[before:])
		}
	}
	if !h.lvs[n.LV] {
		t.Fatal("the root volume is gone")
	}
	if err == nil || !strings.Contains(err.Error(), n.LV) {
		t.Fatalf("Create made the silo over a disk of unknown owner, or didn't say which: %v", err)
	}
	// A half-made silo (state saved, never started, its unit not written) is still made afresh:
	// that disk is Create's own and held nothing.
	h2 := newFakeHost()
	r2 := newRuntime(t, h2)
	if err := r2.Create(ctx, sp); err != nil {
		t.Fatal(err)
	}
	_ = h2.RemoveAll("/etc/systemd/system/" + n.Unit)
	if err := r2.Create(ctx, sp); err != nil {
		t.Fatalf("redoing a half-made silo: %v", err)
	}
}
