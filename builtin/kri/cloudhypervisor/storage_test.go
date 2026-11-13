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

func TestDiskEmpty(t *testing.T) {
	if err := DiskEmpty("/dev/nvme1n1", "nvme1n1 disk\n", ""); err != nil {
		t.Fatalf("an empty disk: %v", err)
	}
	for name, c := range map[string][2]string{
		"partitions":     {"nvme0n1 disk\nnvme0n1p1 part /boot\nnvme0n1p2 part\n", ""},
		"a raid member":  {"nvme0n1 disk\nmd3 raid1 /\n", ""},
		"mounted":        {"sdb disk /srv\n", ""},
		"a partition":    {"nvme0n1p2 part\n", ""},
		"a signature":    {"sdb disk\n", "DEVICE OFFSET TYPE UUID LABEL\nsdb 0x438 ext4 1234 data\n"},
		"no such device": {"", ""},
	} {
		if err := DiskEmpty("/dev/x", c[0], c[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestStorageOnANamedDisk(t *testing.T) {
	m := &loopMachine{}
	h := newFakeHost()
	h.answer = func(cmd string) (string, error) {
		switch {
		case strings.HasPrefix(cmd, "lsblk"):
			return "nvme1n1 disk\n", nil
		case strings.HasPrefix(cmd, "wipefs"):
			return "", nil
		case strings.HasPrefix(cmd, "vgcreate"):
			m.hasVG, m.attached = true, true
			return "", nil
		}
		return m.answer(cmd)
	}
	r := &Runtime{Host: h}
	if err := r.setupStorage(t.Context(), StorageOptions{Device: "/dev/nvme1n1"}); err != nil {
		t.Fatal(err)
	}
	if !has(h.cmds, "pvcreate -q /dev/nvme1n1") || !has(h.cmds, "vgcreate -q kevaso /dev/nvme1n1") || has(h.cmds, "losetup") || has(h.cmds, "truncate") {
		t.Errorf("commands: %v", h.cmds)
	}
	// A disk with something on it: nothing written.
	h = newFakeHost()
	h.answer = func(cmd string) (string, error) {
		switch {
		case strings.HasPrefix(cmd, "lsblk"):
			return "nvme1n1 disk\n", nil
		case strings.HasPrefix(cmd, "wipefs"):
			return "nvme1n1 0x0 gpt\n", nil
		}
		return (&loopMachine{}).answer(cmd)
	}
	r = &Runtime{Host: h}
	if err := r.setupStorage(t.Context(), StorageOptions{Device: "/dev/nvme1n1"}); err == nil || !strings.Contains(err.Error(), "isn't empty") || has(h.cmds, "pvcreate") {
		t.Fatalf("a used disk: %v %v", err, h.cmds)
	}
	if err := r.setupStorage(t.Context(), StorageOptions{Device: "/dev/x", LoopFile: "/f"}); err == nil {
		t.Error("a device and a loop file both accepted")
	}
}
