//go:build e2e

package e2e

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/testbed"
)

// hostdirRoot is where the test plugin keeps its volumes on a host (shared between hosts by the
// test when it needs that, e.g. over NFS).
const hostdirRoot = "/srv/hostdir"

// installHostdir builds the test plugin (test/plugins/hostdir: a folder on hostdirRoot as a
// mount-reach, global storage class) and installs one side of it on a machine with kvoadm, with
// its manifest and a credential the silos must never see. It returns the credential.
func installHostdir(r *rig, machine, side, token string) {
	r.t.Helper()
	dir := r.t.TempDir()
	bin := filepath.Join(dir, "hostdir")
	if out, err := execGo(r, "build", "-o", bin, "kevaso.com/core/test/plugins/hostdir").CombinedOutput(); err != nil {
		r.t.Fatalf("build hostdir: %v\n%s", err, out)
	}
	cfg, tok := filepath.Join(dir, "config.json"), filepath.Join(dir, "token")
	_ = os.WriteFile(cfg, []byte(`{"root": "`+hostdirRoot+`"}`), 0o644)
	_ = os.WriteFile(tok, []byte(token), 0o600)
	if out, err := r.sh(machine, "install -d -m 0755 "+hostdirRoot+"/volumes"); err != nil {
		r.t.Fatalf("%s: %v %s", hostdirRoot, err, out)
	}
	ssh := r.sshArgs(machine)
	ssh = ssh[:len(ssh)-2] // not --kevasod
	out := r.must(kvoadm.Run, "", append(append([]string{"plugin", "install"}, ssh...),
		"--name", "hostdir", "--binary", bin, "--side", side, "--config", cfg, "--credential", "token="+tok,
		"--manifest", "../plugins/hostdir/kevaso-plugin.json", "--yes")...)
	r.t.Logf("kvoadm plugin install --side %s on %s:\n%s", side, machine, out)
}

// vmNames are a cloud-hypervisor silo's names on its host.
func vmNames(s *v1.Silo) cloudhypervisor.Names {
	return cloudhypervisor.NamesFor(kri.ID{Namespace: s.Namespace, Name: s.Name, UID: s.UID})
}

// TestVMVolumes is ADR 0006 on a real KVM host (the real-machine checklist's §2 and the volume
// half of its §3, with a test plugin in place of JuiceFS): a cloud-hypervisor silo with a local
// volume (a thin LV attached as a second disk, formatted once by the guest, mounted at its
// mountPath, kept across a restart, a reboot and a reset, gone with the silo) and a mount class's
// volume (the plugin's node side bind-mounts its folder, one locked-down virtiofsd shares it into
// the guest; files go both ways with the guest's owners; no credential or other host path in the
// guest; set-uid bits and device nodes refused; stopping and deleting undo it all in order).
//
//	metal  control plane + worker with KVM (cloud-hypervisor), and both sides of the hostdir plugin
func TestVMVolumes(t *testing.T) {
	r := newRig(t, 60*time.Minute, map[string]testbed.Spec{
		"metal": {Role: "metal", CPUs: 4, Memory: "6GiB", Disk: "40GiB", KVM: true, Shared: true},
	})
	metalIP := r.ip("metal")
	r.must(kvoadm.Run, "", append(append([]string{"init"}, r.sshArgs("metal")...),
		"--name", "metal-1", "--cluster", "e2e", "--api-server", "https://127.0.0.1:6443", "--internal-ip", metalIP, "--worker",
		"--runtime", "cloud-hypervisor", "--loop-storage", "25G")...)
	token := "hostdir-secret-" + randomToken(t)
	installHostdir(r, "metal", "controller", token)
	installHostdir(r, "metal", "node", token)
	units, _ := r.sh("metal", "systemctl is-active kevaso-plugin-hostdir.service kevaso-plugin-hostdir-node.service; ls -l /run/kevaso-plugins/hostdir/")
	t.Logf("plugin units:\n%s", units)
	r.eventually("the host reports the hostdir mount class", 2*time.Minute, func() (bool, string) {
		out, _ := r.kvo("", "get", "host", "metal-1", "-o", "json")
		return strings.Contains(out, `"hostdir"`), out
	})

	r.must(kvo.Run, `apiVersion: kevaso/v1
kind: Namespace
metadata: { name: notes }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: vm, namespace: notes }
spec:
  runtime: cloud-hypervisor
  vm: { image: ubuntu-24.04 }
  resources: { cpu: 1, memory: 1Gi }
  disk: { size: 5Gi }
  volumes:
    - { name: data, class: hostdir, size: 1Gi, mountPath: /home/data }
    - { name: scratch, size: 2Gi, mountPath: /scratch }
`, "apply", "-f", "-")
	r.waitRunning("notes", 30*time.Minute, "metal", "vm")
	s := r.silo("notes", "vm")
	n := vmNames(s)
	hostData := cloudhypervisorVolumesDir + "/" + s.UID + "/data"
	backing := hostdirRoot + "/volumes/" + s.UID + "/data"
	t.Logf("silo %s, on the host %s", s.UID, n.Short)
	desc, _ := r.kvo("", "describe", "silo", "vm", "-n", "notes")
	t.Logf("kvo describe silo vm:\n%s", desc)

	// ── 2a. The host side ──
	host, _ := r.sh("metal", fmt.Sprintf(`systemctl list-units --plain --no-legend 'kevaso-silo-%s-fs-*'
ps -o user=,group:16=,args= -C virtiofsd
ls -l %s/vfs/
findmnt -n -o SOURCE,FSTYPE,TARGET %s`, n.Short, n.Dir, hostData))
	t.Logf("host side:\n%s", host)
	flat := strings.Join(strings.Fields(host), " ")
	share := cloudhypervisor.LayoutFor(n, []kri.Volume{{Name: "data", MountPath: "/home/data", HostPath: hostData}}, "").Shares[0]
	if strings.Count(host, "-fs-") != 2 || strings.Count(host, "/usr/libexec/virtiofsd") != 1 ||
		!strings.Contains(flat, share.Unit+" loaded active running") || !strings.Contains(flat, share.SocketUnit+" loaded active running") {
		t.Errorf("want one virtiofsd, its unit and its socket unit: %q", host)
	}
	expect(t, "virtiofsd's user and group", flat, "root root /usr/libexec/virtiofsd")
	expect(t, "virtiofsd's flags", host, "--fd=3 --shared-dir="+hostData+" --cache=auto --sandbox=chroot --rlimit-nofile=0 --modcaps=-fsetid:-mknod:-setfcap")
	expect(t, "its socket", host, "srw-rw---- 1 root kevaso-vmm")
	expect(t, "the node side's bind mount", host, hostData)
	caps, _ := r.sh("metal", `pid=$(pgrep -x virtiofsd | head -1); for k in CapEff CapPrm CapBnd CapAmb; do printf '%s ' $k; capsh --decode=$(awk "/^$k:/{print \$2}" /proc/$pid/status) | cut -d= -f2; done; echo root=$(readlink /proc/$pid/root)`)
	t.Logf("virtiofsd's capabilities:\n%s", caps)
	// Serving, chrooted into the share: the file server's five, nothing to chroot out with, and an
	// empty bounding set.
	expect(t, "virtiofsd CapEff", caps, "CapEff cap_chown,cap_dac_override,cap_fowner,cap_setgid,cap_setuid\n")
	expect(t, "virtiofsd CapBnd", caps, "CapBnd \n")
	expect(t, "virtiofsd CapAmb", caps, "CapAmb \n")
	expect(t, "virtiofsd is chrooted into its share", caps, "root="+hostData)
	// What its unit reaches: no network, and of the host's data only the share and its socket.
	unit := share.Unit
	props, _ := r.sh("metal", "systemctl show -p User -p Group -p PrivateNetwork -p NoNewPrivileges -p RestrictSUIDSGID -p ProtectSystem -p RestrictAddressFamilies -p TemporaryFileSystem -p BindPaths "+unit)
	t.Logf("%s:\n%s", unit, props)
	for _, want := range []string{"PrivateNetwork=yes", "NoNewPrivileges=yes", "RestrictSUIDSGID=yes", "ProtectSystem=strict", "RestrictAddressFamilies=AF_UNIX", "User=root"} {
		expect(t, unit, props, want)
	}
	seen, _ := r.sh("metal", `pid=$(systemctl show -p MainPID --value `+unit+`)
nsenter -t $pid -m sh -c 'find /var/lib/kevaso /var/lib/kevaso-silos -maxdepth 4 2>&1 | sort; for d in /var/lib/kevaso-images /root /home /etc/kevaso /etc/ssh /run; do echo "$d: $(ls -A $d 2>&1 | tr "\n" " ")"; done; find /run -mindepth 1 | sed "s/^/  in \/run: /"'
echo "links: $(nsenter -t $pid -n ip -o link | awk '{print $2}' | tr '\n' ' ')"`)
	t.Logf("what virtiofsd's mount namespace holds:\n%s", seen)
	if strings.Contains(seen, "/var/lib/kevaso/etcd") || strings.Contains(seen, "/var/lib/kevaso/pki") || strings.Contains(seen, "seed.img") ||
		strings.Contains(seen, "silo.json") || !strings.Contains(seen, hostData) {
		t.Errorf("virtiofsd sees more of /var/lib than its share: %q", seen)
	}
	expect(t, "virtiofsd has no network", seen, "links: lo: \n")
	for _, d := range []string{"/var/lib/kevaso-images", "/root", "/home", "/etc/kevaso", "/etc/ssh", "/run"} {
		line := seen[strings.Index(seen, d+": "):]
		line = line[:strings.Index(line, "\n")]
		rest := strings.TrimSpace(strings.TrimPrefix(line, d+": "))
		if d == "/run" && rest == "systemd" && strings.Count(seen, "  in /run: ") == 2 &&
			strings.Contains(seen, "  in /run: /run/systemd\n") && strings.Contains(seen, "  in /run: /run/systemd/incoming\n") {
			continue // systemd's own, empty (for passing file descriptors into the unit)
		}
		if rest != "" && !strings.Contains(rest, "No such file") && !strings.Contains(rest, "Permission denied") {
			t.Errorf("virtiofsd (CAP_DAC_OVERRIDE) can read %s", line)
		}
	}

	// ── 2b. The guest side ──
	out, code := r.in("notes", "vm", "findmnt -n -o TARGET,SOURCE,FSTYPE /home/data; findmnt -n -o TARGET,SOURCE,FSTYPE /scratch; ls -l /dev/disk/by-id/ | grep virtio-kv; sed -n '/kevaso volumes: begin/,/kevaso volumes: end/p' /etc/fstab")
	t.Logf("in the guest:\n%s", out)
	if code != 0 {
		t.Fatalf("guest mounts: exit %d", code)
	}
	l := cloudhypervisor.LayoutFor(n, []kri.Volume{{Name: "data", MountPath: "/home/data", HostPath: hostData}, {Name: "scratch", MountPath: "/scratch"}}, "")
	expect(t, "/home/data is virtiofs by tag", out, "/home/data "+l.Shares[0].Tag+" virtiofs")
	expect(t, "/scratch is ext4", out, "ext4")
	expect(t, "the local disk by serial", out, "virtio-"+l.Disks[0].Serial)
	expect(t, "the fstab block", out, l.Shares[0].Tag+" /home/data virtiofs nofail 0 0")
	uuid := func() string {
		u, _ := r.in("notes", "vm", "blkid -o value -s UUID /dev/disk/by-id/virtio-"+l.Disks[0].Serial)
		return u
	}
	firstUUID := uuid()
	if out, code := r.in("notes", "vm", "echo kept > /scratch/kept && echo from-guest > /home/data/g && chown 1000:1000 /home/data/g && ls -ln /home/data/g"); code != 0 {
		t.Fatalf("writing in the guest: %d %s", code, out)
	}
	hostSees, _ := r.sh("metal", "stat -c '%u:%g %n' "+backing+"/g; cat "+backing+"/g; echo from-host > "+backing+"/h; chown 1001:1001 "+backing+"/h")
	expect(t, "the guest's file is on the host with the guest's owner", hostSees, "1000:1000 "+backing+"/g\nfrom-guest")
	if out, _ := r.in("notes", "vm", "touch /home/data/by-root; stat -c '%u:%g %a' /home/data/by-root /home/data"); !strings.HasPrefix(out, "0:0 ") {
		t.Errorf("a file the guest's root made, in the guest: %q", out)
	}
	if out, _ := r.sh("metal", "stat -c '%u:%g' "+backing+"/by-root"); strings.TrimSpace(out) != "0:0" {
		t.Errorf("a file the guest's root made, on the host: %q (want 0:0)", out)
	}
	if out, _ := r.in("notes", "vm", "su -s /bin/sh nobody -c 'ls /home/data >/dev/null && echo nobody-reads'"); out != "nobody-reads" {
		t.Errorf("another guest user can't read the volume's root: %q", out)
	}
	gs, _ := r.in("notes", "vm", "cat /home/data/h; stat -c '%u:%g' /home/data/h")
	expect(t, "the host's file is in the guest with its owner", gs, "from-host\n1001:1001")

	// No credential, no host path beyond the share.
	// The needles go in on stdin: a command line lands in the guest's journal (sudo logs it).
	var lo bytes.Buffer
	kvo.Run(r.ctx, []string{"exec", "silo", "vm", "-n", "notes", "--", "sh", "-c", `read -r tok; read -r root
grep -rlsF -e "$tok" /etc /root /home /var /tmp /run /proc/[0-9]*/environ /proc/cmdline 2>/dev/null | grep -v "^/proc/$$/" | head
grep -sF -e "$tok" -e "$root" -e /var/lib/kevaso -e /run/kevaso-plugins /proc/self/mountinfo /etc/fstab; echo done`},
		strings.NewReader(token+"\n"+hostdirRoot+"\n"), &lo, &lo)
	leak := lo.String()
	if strings.TrimSpace(leak) != "done" {
		t.Errorf("the credential or a host path is in the guest: %q", leak)
	} else {
		t.Log("no credential and no host path in the guest")
	}
	if out, _ := r.in("notes", "vm", "ls -a /home/data/..; ls -a /home/data"); strings.Contains(out, "volumes") || strings.Contains(out, s.UID) {
		t.Errorf("the guest sees above its share: %q", out)
	}
	// What the guest must not be able to do through the share.
	suid, _ := r.in("notes", "vm", "cp /bin/sh /home/data/sh && chmod u+s /home/data/sh; stat -c '%A' /home/data/sh; mknod /home/data/dev b 8 0; echo mknod=$?")
	hostSuid, _ := r.sh("metal", "stat -c '%A' "+backing+"/sh; ls -l "+backing+"/dev 2>&1")
	t.Logf("set-uid and mknod through the share: guest %q, host %q", suid, hostSuid)
	if strings.Contains(hostSuid, "s") && strings.HasPrefix(strings.TrimSpace(hostSuid), "-rws") {
		t.Errorf("a set-uid file landed on the host: %q", hostSuid)
	}
	if strings.Contains(suid, "mknod=0") || strings.HasPrefix(strings.TrimSpace(hostSuid[strings.Index(hostSuid, "\n")+1:]), "b") {
		t.Errorf("a device node through the share: %q %q", suid, hostSuid)
	}

	// ── 2c. A reboot from inside: both mounted again from fstab. ──
	boot, _ := r.in("notes", "vm", "cat /proc/sys/kernel/random/boot_id")
	_, _ = r.in("notes", "vm", "systemd-run --on-active=1 systemctl reboot")
	time.Sleep(10 * time.Second)
	if !r.eventually("after a reboot both volumes are mounted from fstab", 5*time.Minute, func() (bool, string) {
		out, code := r.in("notes", "vm", "timeout 10 cat /scratch/kept /home/data/g; findmnt -n -o FSTYPE /home/data; findmnt -n -o FSTYPE /scratch; ls -la /home/data")
		id, _ := r.in("notes", "vm", "cat /proc/sys/kernel/random/boot_id")
		return code == 0 && id != boot && strings.Contains(out, "kept\nfrom-guest\nvirtiofs\next4"), id + " " + out
	}) {
		g, _ := r.in("notes", "vm", "uptime; findmnt; systemctl status home-data.mount --no-pager; journalctl -b --no-pager | grep -i -E 'virtio|fuse|home-data' | tail -20")
		h, _ := r.sh("metal", "journalctl -u 'kevaso-silo-"+n.Short+"*' --since -10min --no-pager -o short-precise | tail -20")
		t.Logf("after the reboot, in the guest:\n%s\non the host:\n%s", g, h)
	}

	// ── A volume change: the runtime stops and starts the VM; /scratch keeps what it held. ──
	r.must(kvo.Run, `apiVersion: kevaso/v1
kind: Silo
metadata: { name: vm, namespace: notes }
spec:
  runtime: cloud-hypervisor
  vm: { image: ubuntu-24.04 }
  resources: { cpu: 1, memory: 1Gi }
  disk: { size: 5Gi }
  volumes:
    - { name: data, class: hostdir, size: 1Gi, mountPath: /home/data }
    - { name: scratch, size: 2Gi, mountPath: /scratch }
    - { name: more, size: 1Gi, mountPath: /more }
`, "apply", "-f", "-")
	r.eventually("the volume change restarts the VM", 3*time.Minute, func() (bool, string) {
		j, _ := r.sh("metal", "journalctl -u kevasod --no-pager | grep -c 'volumes changed, restarting'")
		return strings.TrimSpace(j) != "0", j
	})
	r.waitRunning("notes", 10*time.Minute, "metal", "vm")
	r.eventually("after the restart: the new volume, and the old ones with their data", 5*time.Minute, func() (bool, string) {
		out, code := r.in("notes", "vm", "cat /scratch/kept /home/data/g; findmnt -n -o FSTYPE /more")
		return code == 0 && strings.Contains(out, "kept\nfrom-guest\next4"), out
	})
	if u := uuid(); u != firstUUID || u == "" {
		t.Errorf("the local volume was formatted again: %q, was %q", u, firstUUID)
	} else {
		t.Logf("the local volume kept its file system (%s)", u)
	}

	// ── kvo reset: a fresh root disk, the volumes kept. ──
	_, _ = r.in("notes", "vm", "touch /root/on-the-old-disk")
	r.must(kvo.Run, "", "reset", "silo", "vm", "-n", "notes")
	r.eventually("the reset is applied", 5*time.Minute, func() (bool, string) {
		out, _ := r.kvo("", "describe", "silo", "vm", "-n", "notes")
		return strings.Contains(out, "reset onto"), out
	})
	r.waitRunning("notes", 15*time.Minute, "metal", "vm")
	r.eventually("after the reset: a fresh disk, the volumes and their data", 5*time.Minute, func() (bool, string) {
		out, code := r.in("notes", "vm", "ls /root/on-the-old-disk 2>/dev/null; cat /scratch/kept /home/data/g; findmnt -n -o FSTYPE /home/data")
		return code == 0 && !strings.Contains(out, "on-the-old-disk") && strings.Contains(out, "kept\nfrom-guest\nvirtiofs"), out
	})
	if u := uuid(); u != firstUUID {
		t.Errorf("the reset formatted the local volume: %q, was %q", u, firstUUID)
	}

	// ── Delete: the VMM, then virtiofsd, then the unmount; nothing left on the host. ──
	s = r.silo("notes", "vm")
	since := time.Now().Add(-2 * time.Second).UTC().Format("2006-01-02 15:04:05")
	r.must(kvo.Run, "", "delete", "silo", "vm", "-n", "notes")
	r.eventually("the silo is gone", 5*time.Minute, func() (bool, string) {
		out, _ := r.kvo("", "get", "silos", "-n", "notes", "-o", "json")
		return len(parseSilos(out)) == 0, out
	})
	r.eventually("the volume's folder is deleted by the plugin", 3*time.Minute, func() (bool, string) {
		out, _ := r.sh("metal", "ls -A "+hostdirRoot+"/volumes/")
		return strings.TrimSpace(out) == "", out
	})
	left, _ := r.sh("metal", fmt.Sprintf(`echo "lvs: $(lvs --noheadings -o lv_name kevaso | grep -c %s)"
echo "units: $(ls /etc/systemd/system | grep -c %s)"
echo "virtiofsd: $(pgrep -c virtiofsd)"
echo "mounts: $(grep -c %s /proc/self/mountinfo)"
echo "dir: $(ls -d %s 2>/dev/null | wc -l)"`, n.Short, n.Short, s.UID, n.Dir))
	t.Logf("left on the host:\n%s", left)
	for _, k := range []string{"lvs", "units", "virtiofsd", "mounts", "dir"} {
		expect(t, "nothing left: "+k, left, k+": 0")
	}
	stopOrder(t, r, "metal", "delete", since, n, share, hostData)
}

// stopOrder checks on a host, in its journal since a time, that a VM silo's share was let go in
// order: its VMM ended, then its socket unit (so nothing could start virtiofsd again), virtiofsd
// ended too (it exits by itself when the guest powers off), and only then the node side unmounted it.
func stopOrder(t *testing.T, r *rig, machine, what, since string, n cloudhypervisor.Names, share cloudhypervisor.Share, hostPath string) {
	t.Helper()
	order, _ := r.sh(machine, fmt.Sprintf(`journalctl --since '%s UTC' -o short-iso-precise --no-pager -u 'kevaso-silo-%s*' -u kevaso-plugin-hostdir-node.service | grep -E 'Stopped|Deactivated|unmounted'`, since, n.Short))
	t.Logf("%s, on %s in order:\n%s", what, machine, order)
	last := func(unit string) int {
		return max(strings.LastIndex(order, ": Stopped "+unit), strings.LastIndex(order, ": "+unit+": Deactivated"))
	}
	vmm, sock, vfs, um := last(n.Unit), last(share.SocketUnit), last(share.Unit), strings.LastIndex(order, "unmounted "+hostPath)
	if vmm < 0 || sock < 0 || vfs < 0 || um < 0 || sock < vmm || um < vmm || um < sock || um < vfs {
		t.Errorf("%s on %s: want the VMM, its socket unit and virtiofsd ended before the unmount, the socket after the VMM (at %d %d %d %d)",
			what, machine, vmm, sock, vfs, um)
	}
}

// cloudhypervisorVolumesDir is where kevasod mounts provider volumes (agent.DefaultVolumesDir).
const cloudhypervisorVolumesDir = "/var/lib/kevaso/volumes"
