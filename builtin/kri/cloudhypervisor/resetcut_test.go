package cloudhypervisor

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// review-batch4 claim 2: a reset cut in its qemu-img convert (kevasod stopped: its reconcile's
// context ends and the convert is killed) left a partial image on a new LV while silo.json said
// Started, and the next Start booted it as it was. The reset's intent is saved before lvremove,
// and Start finishes the reset (the disk made afresh again, from the same image) before booting.
func TestAResetCutInItsConvertIsFinishedBeforeTheVMBoots(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	r := newRuntime(t, h)
	sp := spec("web")
	if err := r.Create(ctx, sp); err != nil {
		t.Fatal(err)
	}
	n := NamesFor(sp.ID)
	kill := true
	h.answer = func(cmd string) (string, error) {
		switch {
		case strings.HasPrefix(cmd, "systemctl is-active"):
			return "inactive", errors.New("exit 3")
		case strings.HasPrefix(cmd, "systemctl show"):
			return "MainPID=0\n", nil
		case strings.HasPrefix(cmd, "qemu-img convert") && kill:
			return "", errors.New("signal: killed")
		case strings.HasPrefix(cmd, "lvs ") || strings.HasPrefix(cmd, "lvremove") || strings.HasPrefix(cmd, "lvcreate"):
			b, err := h.lv(strings.Fields(cmd)[0], strings.Fields(cmd)[1:])
			return string(b), err
		}
		return "", nil
	}
	if err := r.Start(ctx, sp.ID); err != nil {
		t.Fatal(err)
	}
	err := r.Reset(ctx, sp)
	if err == nil {
		t.Fatal("a reset whose convert was killed reported success")
	}
	t.Logf("the reset: %v", err)
	kill = false
	r = newRuntime(t, h) // kevasod starts again
	before := len(h.commands())
	if err := r.Start(ctx, sp.ID); err != nil {
		t.Fatal(err)
	}
	cmds := h.commands()[before:]
	boot := indexOf(cmds, "systemctl start "+n.Unit)
	convert := indexOf(cmds, "qemu-img convert")
	if convert < 0 || boot < 0 || convert > boot {
		t.Fatalf("the VM booted the half-made disk of its cut reset (no convert before its start): %v", cmds)
	}
	if b, _ := h.ReadFile(n.Dir + "/silo.json"); strings.Contains(string(b), `"remake"`) {
		t.Fatalf("the reset's mark is still there after it was finished: %s", b)
	}
}
