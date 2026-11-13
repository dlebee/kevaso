package cloudhypervisor

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// loopMachine is a host's LVM on a loop file, as setupStorage sees it.
type loopMachine struct {
	fileExists bool // the loop file is there
	attached   bool // a loop device holds it
	hasVG      bool // the file holds the volume group
	pool       bool // the thin pool exists
	active     bool // the group's volumes are active
}

func (m *loopMachine) answer(cmd string) (string, error) {
	switch {
	case strings.HasPrefix(cmd, "lvs"):
		if m.hasVG && m.attached && m.pool {
			return "  silos kevaso twi-a-tz--", nil
		}
		return "", errors.New("exit 5")
	case strings.HasPrefix(cmd, "vgs"):
		if m.hasVG && m.attached {
			return "  kevaso", nil
		}
		return "", errors.New("exit 5")
	case strings.HasPrefix(cmd, "test -e"):
		if m.fileExists {
			return "", nil
		}
		return "", errors.New("exit 1")
	case strings.HasPrefix(cmd, "losetup -n -O NAME -j"):
		if m.attached {
			return "/dev/loop7\n", nil
		}
		return "", nil
	case strings.HasPrefix(cmd, "losetup --find --show"):
		m.attached = true
		return "/dev/loop7\n", nil
	case strings.HasPrefix(cmd, "truncate"):
		m.fileExists = true
	case strings.HasPrefix(cmd, "vgcreate"):
		m.hasVG = true
	case strings.HasPrefix(cmd, "vgchange"):
		m.active = true
	case strings.HasPrefix(cmd, "lvcreate"):
		m.pool = true
	}
	return "", nil
}

func storageRun(t *testing.T, m *loopMachine) ([]string, error) {
	t.Helper()
	h := newFakeHost()
	h.answer = m.answer
	r := &Runtime{Host: h}
	err := r.setupStorage(t.Context(), StorageOptions{LoopFile: "/var/lib/kevaso-storage.img", LoopSize: "60G"})
	return h.cmds, err
}

func has(cmds []string, prefix string) bool {
	return slices.ContainsFunc(cmds, func(c string) bool { return strings.HasPrefix(c, prefix) })
}

func TestStorageAfterARebootReattachesTheLoopFile(t *testing.T) {
	m := &loopMachine{fileExists: true, hasVG: true, pool: true} // a boot detached it
	cmds, err := storageRun(t, m)
	if err != nil {
		t.Fatal(err)
	}
	for _, never := range []string{"truncate", "pvcreate", "vgcreate", "lvcreate"} {
		if has(cmds, never) {
			t.Errorf("after a reboot it ran %s over the existing volume group: %v", never, cmds)
		}
	}
	if !m.attached || !m.active || !has(cmds, "vgchange -q -ay kevaso") {
		t.Errorf("not attached and activated again: %+v %v", m, cmds)
	}
}

func TestStorageReusesTheLoopDeviceItIsOn(t *testing.T) {
	m := &loopMachine{fileExists: true, attached: true, hasVG: true, pool: false}
	cmds, err := storageRun(t, m)
	if err != nil {
		t.Fatal(err)
	}
	if has(cmds, "losetup --find") || has(cmds, "pvcreate") {
		t.Errorf("a second loop device or a new physical volume: %v", cmds)
	}
	if !has(cmds, "lvcreate -q --type thin-pool") {
		t.Errorf("the missing thin pool wasn't made: %v", cmds)
	}
}

func TestStorageFirstTimeMakesEverything(t *testing.T) {
	m := &loopMachine{}
	cmds, err := storageRun(t, m)
	if err != nil {
		t.Fatal(err)
	}
	order := []string{"truncate -s 60G", "losetup --find --show", "pvcreate -q /dev/loop7", "vgcreate -q kevaso /dev/loop7", "vgchange", "lvcreate", "lvchange"}
	last := -1
	for _, p := range order {
		i := slices.IndexFunc(cmds, func(c string) bool { return strings.HasPrefix(c, p) })
		if i <= last {
			t.Fatalf("%q missing or out of order: %v", p, cmds)
		}
		last = i
	}
}

func TestStorageNeverWritesOverAFileWithoutItsGroup(t *testing.T) {
	m := &loopMachine{fileExists: true} // something else is in the file
	cmds, err := storageRun(t, m)
	if err == nil || !strings.Contains(err.Error(), "won't write over it") {
		t.Fatalf("got %v", err)
	}
	if has(cmds, "pvcreate") || has(cmds, "truncate") {
		t.Errorf("it wrote over the file: %v", cmds)
	}
}
