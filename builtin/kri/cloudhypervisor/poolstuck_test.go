package cloudhypervisor

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Found on a machine: kevasod restarted while lvcreate was making a microVM's disk
// (`lvcreate …: signal: killed`). LVM left silos_tmeta active and the pool not, and every later
// create failed with "Activation of logical volume kevaso/silos is prohibited while logical volume
// kevaso/silos_tmeta is active" until the pool was repaired by hand.

const poolProhibited = "Activation of logical volume kevaso/silos is prohibited while logical volume kevaso/silos_tmeta is active. Failed to update pool kevaso/silos."

func TestPoolCommandsAreNotInKevasosCgroup(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	r := newRuntime(t, h)
	if err := r.Create(ctx, spec("web")); err != nil {
		t.Fatal(err)
	}
	if err := r.Delete(ctx, id("web")); err != nil {
		t.Fatal(err)
	}
	h2 := newFakeHost()
	m := &loopMachine{}
	h2.answer = m.answer
	if err := (&Runtime{Host: h2}).setupStorage(ctx, StorageOptions{LoopFile: "/var/lib/kevaso-storage.img", LoopSize: "60G"}); err != nil {
		t.Fatal(err)
	}
	if err := outsideCgroup(h.commands()); err != nil {
		t.Fatal(err)
	}
	if err := outsideCgroup(h2.commands()); err != nil {
		t.Fatal(err)
	}
	if indexOf(h.commands(), "qemu-img convert") < 0 {
		t.Fatal("create didn't convert the image")
	}
	for _, c := range h.commands() {
		if !strings.HasPrefix(hostCmd(c), "qemu-img convert ") {
			continue
		}
		if !strings.Contains(c, "User="+ImgUser) || !strings.Contains(c, "Requisite=kevasod.service") || !strings.Contains(c, "PartOf=kevasod.service") || strings.Contains(c, "BindsTo=") || strings.Contains(c, "--slice=system.slice") {
			t.Errorf("qemu-img convert must be a unit bound to kevasod, shown only the image and the target: %s", c)
		}
	}
}

// outsideCgroup reports a pool-changing LVM command that is still a child of kevasod, or any
// other command that was moved out of its cgroup.
func outsideCgroup(cmds []string) error {
	n := 0
	for _, c := range cmds {
		inner := hostCmd(c)
		pool := strings.HasPrefix(inner, "lvcreate ") || strings.HasPrefix(inner, "lvremove ") || strings.HasPrefix(inner, "lvchange ")
		if !pool {
			// qemu-img convert is a transient unit bound to kevasod, not the pool's scope: a
			// restart stops it, and it is not outside the cgroup the way lvcreate is.
			if strings.HasPrefix(c, "systemd-run ") && strings.HasPrefix(inner, "qemu-img convert ") &&
				strings.Contains(c, "User="+ImgUser) && strings.Contains(c, "Requisite=kevasod.service") && strings.Contains(c, "PartOf=kevasod.service") && !strings.Contains(c, "BindsTo=") &&
				!strings.Contains(c, "--slice=system.slice") {
				continue
			}
			if strings.HasPrefix(c, "systemd-run ") {
				return errors.New("only a pool command leaves kevasod's cgroup: " + c)
			}
			continue
		}
		n++
		if !strings.HasPrefix(c, "systemd-run --quiet --collect --scope --slice=system.slice -- "+inner) {
			return errors.New("pool command is in kevasod's cgroup: " + c)
		}
	}
	if n == 0 {
		return errors.New("no pool command")
	}
	return nil
}

func TestAKilledLvcreateIsRepairedBeforeTheNextCreate(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	r := newRuntime(t, h)
	if err := r.Create(ctx, spec("keep")); err != nil {
		t.Fatal(err)
	}
	keep := NamesFor(id("keep")).LV
	if !h.lvs[keep] {
		t.Fatal("the existing silo's disk wasn't made")
	}
	var stuck, killed, off, healed bool
	h.answer = func(cmd string) (string, error) {
		switch {
		case strings.HasPrefix(cmd, "lvs -a --noheadings -o lv_name,lv_active"):
			if stuck && !healed {
				return "  silos\n  silos_tdata active\n  silos_tmeta active\n", nil
			}
			return "  silos active\n  silos_tdata active\n  silos_tmeta active\n", nil
		case strings.HasPrefix(cmd, "lvchange -an "):
			if !strings.Contains(cmd, ThinPool+"_tmeta") || !strings.Contains(cmd, ThinPool+"_tdata") {
				return "", errors.New("deactivated the wrong volumes")
			}
			off = true
			return "", nil
		case strings.HasPrefix(cmd, "lvchange -ay "):
			if !off {
				return "", errors.New(poolProhibited)
			}
			if cmd != "lvchange -ay "+VG+"/"+ThinPool {
				return "", errors.New("activated the wrong volume")
			}
			healed, stuck = true, false
			return "", nil
		case strings.HasPrefix(cmd, "lvcreate ") && !killed:
			killed, stuck = true, true
			return "", errors.New("signal: killed")
		case (strings.HasPrefix(cmd, "lvcreate ") || strings.HasPrefix(cmd, "lvremove ")) && stuck && !healed:
			return "", errors.New(poolProhibited)
		case strings.HasPrefix(cmd, "systemctl is-active"):
			return "inactive", errors.New("exit 3")
		}
		f := strings.Fields(cmd)
		if len(f) > 0 && (f[0] == "lvs" || f[0] == "lvcreate" || f[0] == "lvremove") {
			b, err := h.lv(f[0], f[1:])
			return string(b), err
		}
		return "", nil
	}
	from := len(h.commands())
	if err := r.Create(ctx, spec("web")); err == nil || !strings.Contains(err.Error(), "signal: killed") {
		t.Fatalf("killed lvcreate: %v", err)
	}
	if err := r.Create(ctx, spec("web")); err != nil {
		t.Fatal(err)
	}
	cmds := h.commands()[from:]
	an := indexOf(cmds, "lvchange -an ")
	ay := indexOf(cmds, "lvchange -ay ")
	made := lastIndex(cmds, "lvcreate -q -T "+VG+"/"+ThinPool) // the killed one is earlier
	if an < 0 || ay < an || made < ay {
		t.Fatalf("repair didn't run before the next lvcreate: %v", cmds)
	}
	for _, i := range []int{an, ay, made} {
		if !strings.HasPrefix(cmds[i], "systemd-run ") || !strings.Contains(cmds[i], " --scope ") {
			t.Errorf("repair stayed in kevasod's cgroup: %s", cmds[i])
		}
	}
	if !strings.Contains(hostCmd(cmds[an]), VG+"/"+ThinPool+"_tmeta") || !strings.Contains(hostCmd(cmds[an]), VG+"/"+ThinPool+"_tdata") {
		t.Fatalf("didn't deactivate the active sub-volumes: %s", hostCmd(cmds[an]))
	}
	if hostCmd(cmds[ay]) != "lvchange -ay "+VG+"/"+ThinPool {
		t.Fatalf("didn't activate the pool: %s", hostCmd(cmds[ay]))
	}
	if !h.lvs[keep] || !h.lvs[NamesFor(id("web")).LV] {
		t.Fatalf("disks afterwards: keep %v web %v", h.lvs[keep], h.lvs[NamesFor(id("web")).LV])
	}
	for _, c := range cmds {
		if removedPoolOr(c, keep) {
			t.Fatalf("repair removed a volume: %s", c)
		}
	}
}

func TestAStuckPoolThatCannotBeRepairedIsLeftAsItWas(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	r := newRuntime(t, h)
	if err := r.Create(ctx, spec("keep")); err != nil {
		t.Fatal(err)
	}
	keep := NamesFor(id("keep")).LV
	h.answer = func(cmd string) (string, error) {
		switch {
		case strings.HasPrefix(cmd, "lvs -a --noheadings -o lv_name,lv_active"):
			return "  silos\n  silos_tmeta active\n", nil
		case strings.HasPrefix(cmd, "lvchange -an "):
			return "", errors.New("Device or resource busy")
		case strings.HasPrefix(cmd, "lvcreate ") || strings.HasPrefix(cmd, "lvremove ") || strings.HasPrefix(cmd, "lvchange "):
			return "", errors.New(poolProhibited)
		case strings.HasPrefix(cmd, "systemctl is-active"):
			return "inactive", errors.New("exit 3")
		}
		f := strings.Fields(cmd)
		if len(f) > 0 && (f[0] == "lvs" || f[0] == "lvcreate" || f[0] == "lvremove") {
			b, err := h.lv(f[0], f[1:])
			return string(b), err
		}
		return "", nil
	}
	from := len(h.commands())
	err := r.Create(ctx, spec("web"))
	if err == nil {
		t.Fatal("create succeeded on a pool that could not be repaired")
	}
	for _, want := range []string{
		"thin pool " + VG + "/" + ThinPool + " is unusable",
		VG + "/" + ThinPool + "_tmeta is active while " + VG + "/" + ThinPool + " is not",
		"Nothing was removed",
		"lvchange -an " + VG + "/" + ThinPool + "_tmeta && lvchange -ay " + VG + "/" + ThinPool,
		"Device or resource busy",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
	if strings.Contains(err.Error(), "lvremove") {
		t.Errorf("the repair tells someone to remove a volume:\n%v", err)
	}
	cmds := h.commands()[from:]
	if indexOf(cmds, "lvcreate") >= 0 || indexOf(cmds, "lvchange -ay") >= 0 {
		t.Fatalf("it went on after the repair failed: %v", cmds)
	}
	if !h.lvs[keep] {
		t.Fatal("the existing silo's disk is gone")
	}
	for _, c := range cmds {
		if removedPoolOr(c, keep) {
			t.Fatalf("repair removed a volume: %s", c)
		}
	}
}

// removedPoolOr reports an lvremove of the thin pool, its metadata or data volume, or lv
// (a silo's existing disk).
func removedPoolOr(cmd, lv string) bool {
	inner := hostCmd(cmd)
	if !strings.HasPrefix(inner, "lvremove") {
		return false
	}
	for _, f := range strings.Fields(inner) {
		name, ok := strings.CutPrefix(f, VG+"/")
		if !ok {
			continue
		}
		if name == ThinPool || strings.HasPrefix(name, ThinPool+"_") || name == lv || strings.HasPrefix(name, lv+"-") {
			return true
		}
	}
	return false
}
