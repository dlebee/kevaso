package cloudhypervisor

import (
	"context"
	"errors"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// A fence kills the VM: SIGKILL first, no power button and no wait for the guest, then the same
// teardown as a stop (the VMM unit, then its virtiofsd daemons), so nothing is left running.
func TestKillHasNoGrace(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	r := newRuntime(t, h)
	sp := spec("web")
	sp.Volumes = vmVolumes()
	if err := r.Create(ctx, sp); err != nil {
		t.Fatal(err)
	}
	n := NamesFor(sp.ID)
	share := LayoutFor(n, sp.Volumes, "").Shares[0]
	killed := false
	h.answer = func(cmd string) (string, error) {
		if strings.HasPrefix(cmd, "systemctl kill --signal=SIGKILL") {
			killed = true
		}
		if cmd == "systemctl is-active "+n.Unit && !killed {
			return "active", nil
		}
		if strings.HasPrefix(cmd, "systemctl is-active") {
			return "inactive", errors.New("exit 3")
		}
		return "", nil
	}
	before := len(h.commands())
	if err := kri.Kill(ctx, r, sp.ID); err != nil {
		t.Fatal(err)
	}
	cmds := h.commands()[before:]
	for _, c := range cmds {
		if strings.Contains(c, "power-button") {
			t.Fatalf("a kill asked the guest to power off: %v", cmds)
		}
	}
	k, vmm, fs := indexOf(cmds, "systemctl kill --signal=SIGKILL --kill-whom=all "+n.Unit), indexOf(cmds, "systemctl stop "+n.Unit), indexOf(cmds, "systemctl stop "+share.Unit)
	if k != 0 || vmm < k || fs < vmm {
		t.Fatalf("want SIGKILL, then the VMM's unit, then virtiofsd: %v", cmds)
	}
	if err := r.Kill(ctx, id("absent")); !errors.Is(err, kri.ErrNotFound) {
		t.Fatalf("absent: %v", err)
	}
}
