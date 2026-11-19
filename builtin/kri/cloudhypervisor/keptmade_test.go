package cloudhypervisor

import (
	"context"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// A finished reset clears Started. Losing the unit file after that is not a half-made
// create: the disk and the state stay, and Create refuses to make the silo again.
func TestAFinishedResetKeepsItsDiskWhenTheUnitIsGone(t *testing.T) {
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
	if err := r.Reset(ctx, sp); err != nil {
		t.Fatal(err)
	}
	n := NamesFor(sp.ID)
	st, ok := r.state(sp.ID)
	if !ok || !st.Made || st.Started || st.IP == "" {
		t.Fatalf("after reset: ok %v %+v", ok, st)
	}
	ip := st.IP
	delete(h.files, "/etc/systemd/system/"+n.Unit)
	got, err := r.Status(ctx, sp.ID)
	if err != nil || got.State == kri.Absent {
		t.Fatalf("status with the unit gone: %s %v", got.State, err)
	}
	before := len(h.commands())
	err = r.Create(ctx, sp)
	if err == nil || !strings.Contains(err.Error(), "not making it again") {
		t.Fatalf("Create: %v", err)
	}
	for _, c := range h.commands()[before:] {
		if strings.Contains(c, "lvremove") || strings.Contains(c, "qemu-img") {
			t.Fatalf("Create rewrote the disk: %s", c)
		}
	}
	st, ok = r.state(sp.ID)
	if !ok || st.IP != ip || !st.Made {
		t.Fatalf("state after the refused create: ok %v %+v, want ip %s", ok, st, ip)
	}
	if _, still := h.lvs[n.LV]; !still {
		t.Fatal("the root volume is gone")
	}
}

// A create that finished (its unit was written) is not half-made. Losing the unit
// afterwards does not make the disk again.
func TestAFinishedCreateIsNotRedoneWhenItsUnitIsGone(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	r := newRuntime(t, h)
	sp := spec("web")
	if err := r.Create(ctx, sp); err != nil {
		t.Fatal(err)
	}
	n := NamesFor(sp.ID)
	delete(h.files, "/etc/systemd/system/"+n.Unit)
	before := len(h.commands())
	err := r.Create(ctx, sp)
	if err == nil || !strings.Contains(err.Error(), "not making it again") {
		t.Fatalf("Create: %v", err)
	}
	for _, c := range h.commands()[before:] {
		if strings.Contains(c, "lvremove") || strings.Contains(c, "qemu-img") {
			t.Fatalf("Create rewrote the disk: %s", c)
		}
	}
}
