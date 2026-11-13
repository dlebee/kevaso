//go:build metal

package e2e

// Machine 2's spare disk (KEVASO_METAL2_SPARE_DISK): its worker's volume group is made there
// (kvoadm host add --storage-device). This file sorts last of the two-machine tests: the reset
// test takes machine 2 out of the cluster.

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func (p *pair) spare() string {
	p.t.Helper()
	if p.m2.cfg.SpareDisk == "" {
		p.t.Skip("KEVASO_METAL2_SPARE_DISK isn't set: machine 2's storage is a loop file")
	}
	return p.m2.cfg.SpareDisk
}

// TestMetal2Disk is microVM storage on a real disk: the volume group on the spare disk and
// nothing on the OS disk; a silo's volume on it holds data through a restart of its VMM; a
// volume larger than the disk is refused with a reason, not left half made.
//
// Listens on nothing outside.
func TestMetal2Disk(t *testing.T) {
	p := metal2(t)
	disk := p.spare()
	c := p.c1
	ns := "disk2"
	c.namespace(ns)
	c.expect("the volume group is on the spare disk alone", strings.TrimSpace(p.c2.mustSh("pvs --noheadings -o pv_name -S vg_name=kevaso | tr -d ' '")), disk)
	place := ""
	if p.m1Worker {
		place = on(metalHost2)
	}
	c.apply(vmEcho(ns, "db", 8080) + place + "  volumes: [{ name: data, size: 10Gi, mountPath: /data }]\n")
	c.waitRunning(ns, 20*time.Minute, "db")
	sum := strings.TrimSpace(func() string {
		o, _ := c.in(ns, "db", "head -c 64M /dev/urandom > /data/blob && sync && sha256sum /data/blob | cut -d' ' -f1")
		return o
	}())
	if len(sum) != 64 {
		t.Fatalf("writing to the volume: %q", sum)
	}
	if out := p.c2.mustSh("lvs --noheadings -o lv_name,devices kevaso 2>/dev/null | head -3"); !strings.Contains(out, "kv-") {
		t.Errorf("no logical volume of the silo on the disk: %s", out)
	}
	c.expect("the volume's data, read back", func() string { o, _ := c.in(ns, "db", "sha256sum /data/blob | cut -d' ' -f1"); return o }(), sum)

	size := strings.TrimSpace(p.c2.mustSh("lsblk -bdn -o SIZE " + disk))
	c.apply(vmEcho(ns, "huge", 8080) + place + "  volumes: [{ name: data, size: 4000Gi, mountPath: /data }]\n")
	c.eventually("a volume larger than the disk ("+size+" bytes) is refused, saying why", 5*time.Minute, func() (bool, string) {
		s := c.silo(ns, "huge")
		d, _ := c.kvo("", "describe", "silo", "huge", "-n", ns)
		return s.Status.Phase != "Running" && (strings.Contains(d, "not enough") || strings.Contains(d, "too large") || strings.Contains(d, "space")), d
	})
	if s := c.silo(ns, "huge"); s.Status.Phase == "Running" {
		t.Errorf("a 4000Gi volume on a %s-byte disk runs (thin overcommit?)", size)
	}
}

// TestMetal2DiskReset is kvoadm reset on a host whose volume group is on a real disk: without
// --wipe-storage it keeps the volume group and names the volumes; with it, the disk is left
// with nothing on it. It takes machine 2 out of the cluster, so it runs last.
//
// Listens on nothing outside.
func TestMetal2DiskReset(t *testing.T) {
	p := metal2(t)
	disk := p.spare()
	c := p.c1
	ns := "diskreset2"
	c.namespace(ns)
	place := ""
	if p.m1Worker {
		place = on(metalHost2)
	}
	c.apply(vmEcho(ns, "db", 8080) + place + "  volumes: [{ name: data, size: 2Gi, mountPath: /data }]\n")
	c.waitRunning(ns, 20*time.Minute, "db")
	lvs := strings.TrimSpace(p.c2.mustSh("lvs --noheadings -o lv_name kevaso | tr -d ' ' | grep '^kv-' | sort"))
	reset := func(extra ...string) string {
		cfg := p.m2.cfg
		args := append([]string{"run", "./cmd/kvoadm", "reset", cfg.SSHTarget(), "--ssh-key", cfg.KeyFile, "--host-key", cfg.HostKey, "--force", "--yes"}, extra...)
		cmd := exec.CommandContext(c.ctx, "go", args...)
		var o bytes.Buffer
		cmd.Stdout, cmd.Stderr = &o, &o
		err := cmd.Run()
		t.Logf("kvoadm reset %v: %v\n%s", extra, err, o.String())
		return o.String()
	}
	_ = p.m2.d.Close()
	out := reset()
	c.expect("without --wipe-storage: the volume group is kept", out, "KEEP the volume group kevaso")
	for _, lv := range strings.Fields(lvs) {
		c.expect("…naming "+lv, out, lv)
	}
	c.expect("the disk still holds the group", strings.TrimSpace(p.c2.mustSh("pvs --noheadings -o pv_name -S vg_name=kevaso | tr -d ' '")), disk)
	out = reset("--wipe-storage")
	c.expect("--wipe-storage: the volumes are named as lost first", out, "will be lost")
	c.expect("…and it's clean", out, "is clean")
	left := p.c2.mustSh(fmt.Sprintf("lsblk -nr -o NAME %s | tail -n +2; wipefs -n %s; vgs kevaso 2>&1 | grep -v 'not found' || true", disk, disk))
	if strings.TrimSpace(left) != "" {
		t.Errorf("the disk isn't empty after --wipe-storage: %s", left)
	} else {
		t.Logf("%s is empty again", disk)
	}
	if os := p.c2.mustSh("findmnt -n -o SOURCE /"); strings.Contains(os, strings.TrimPrefix(disk, "/dev/")) {
		t.Errorf("the OS runs from the spare disk? %s", os)
	}
}
