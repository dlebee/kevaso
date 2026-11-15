package cloudhypervisor

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// K-112: a reset whose gate passed and that was cut before anything was removed (its lvremove
// failed) removed nothing: its mark goes, so the next Start boots the old disk as it is and wipes
// nothing on its own (the request may have been taken back since; a reset still asked for comes
// again through its gate).
func TestAResetCutBeforeItRemovedAnythingIsNotFinishedAtTheNextStart(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	r := newRuntime(t, h)
	sp := spec("db")
	if err := r.Create(ctx, sp); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, sp.ID); err != nil {
		t.Fatal(err)
	}
	n := NamesFor(sp.ID)
	fail := true
	h.answer = func(cmd string) (string, error) {
		switch {
		case strings.HasPrefix(cmd, "lvremove") && fail:
			fail = false
			return "", errors.New("Logical volume in use")
		case strings.HasPrefix(cmd, "systemctl is-active"):
			return "inactive", errors.New("exit 3")
		case strings.HasPrefix(cmd, "systemctl show"):
			return "MainPID=0\n", nil
		}
		f := strings.Fields(cmd)
		out, err := h.lv(f[0], f[1:])
		return string(out), err
	}
	gates := 0
	if err := r.ResetGated(ctx, sp, func(context.Context) error { gates++; return nil }); err == nil || gates != 1 {
		t.Fatalf("a reset whose lvremove failed: %v (gate asked %d times)", err, gates)
	}
	if b, _ := h.ReadFile(n.Dir + "/silo.json"); strings.Contains(string(b), `"remake"`) {
		t.Fatalf("a reset that removed nothing left its mark: %s", b)
	}
	before := len(h.commands())
	if err := r.Start(ctx, sp.ID); err != nil {
		t.Fatal(err)
	}
	for _, c := range h.commands()[before:] {
		if strings.HasPrefix(c, "lvremove") || strings.HasPrefix(c, "lvcreate") || strings.HasPrefix(c, "qemu-img convert") {
			t.Fatalf("the next Start made the disk afresh with no gate asked: %s", c)
		}
	}
	if !h.lvs[n.LV] {
		t.Fatal("the root volume is gone")
	}
}
