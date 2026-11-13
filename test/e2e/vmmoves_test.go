//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/testbed"
)

// TestVMMoves is ADR 0006's "a root disk that moves" on two real KVM workers: a cloud-hypervisor
// silo whose root disk (disk.class) and a data volume are on a mount class moves with kvo move,
// and again by onHostLoss: Move after its host's kevasod is stopped (kevaso-fence stops the VM
// first). Never two copies (both hosts' VMM units are watched every second), its files are there,
// and the new host's exec key replaced the old one in the guest.
//
// The class is the test plugin (test/plugins/hostdir) on a folder that w1 exports to w2 over NFS
// (v4.2, hard mounts). That proves Kevaso's side of the handoff (the order of stop, unmount, mount
// and start, the fence, the new seed) on a real shared file system with real locks; it says
// nothing about JuiceFS's own behaviour (its caching, its locks across clients), which is the
// JuiceFS provider's to prove.
//
//	w1  control plane + worker with KVM (cloud-hypervisor), the hostdir plugin's both sides, the NFS server
//	w2  worker with KVM (cloud-hypervisor), the hostdir plugin's node side, the NFS client
func TestVMMoves(t *testing.T) {
	r := newRig(t, 70*time.Minute, map[string]testbed.Spec{
		"w1": {Role: "w1", CPUs: 4, Memory: "5GiB", Disk: "35GiB", KVM: true, Shared: true},
		"w2": {Role: "w2", CPUs: 4, Memory: "5GiB", Disk: "35GiB", KVM: true, Shared: true},
	})
	w1IP, w2IP := r.ip("w1"), r.ip("w2")
	t.Logf("w1 %s, w2 %s", w1IP, w2IP)
	nfs := []struct{ machine, script string }{
		{"w1", fmt.Sprintf(`set -e
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update >/dev/null && apt-get -qq install -y nfs-kernel-server >/dev/null
install -d -m 0755 %[1]s
mkdir -p /etc/exports.d && echo '%[1]s %[2]s(rw,sync,no_subtree_check,no_root_squash)' > /etc/exports.d/hostdir.exports
exportfs -ra && exportfs -v`, hostdirRoot, w2IP)},
		{"w2", fmt.Sprintf(`set -e
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update >/dev/null && apt-get -qq install -y nfs-common >/dev/null
install -d -m 0755 %[1]s
mount -t nfs4 -o vers=4.2,hard %[2]s:%[1]s %[1]s && findmnt -n %[1]s`, hostdirRoot, w1IP)},
	}
	for _, s := range nfs {
		if out, err := r.sh(s.machine, s.script); err != nil {
			t.Fatalf("NFS on %s: %v\n%s", s.machine, err, out)
		} else {
			t.Logf("NFS on %s:\n%s", s.machine, out)
		}
	}
	r.must(kvoadm.Run, "", append(append([]string{"init"}, r.sshArgs("w1")...),
		"--name", "w1", "--cluster", "e2e", "--api-server", "https://127.0.0.1:6443", "--address", w1IP, "--worker",
		"--runtime", "cloud-hypervisor", "--loop-storage", "20G")...)
	r.must(kvoadm.Run, "", append(append([]string{"host", "add"}, r.sshArgs("w2")...),
		"--name", "w2", "--install", "worker", "--address", w2IP, "--server", "https://"+w1IP+":6443", "--runtime", "cloud-hypervisor",
		"--loop-storage", "20G")...)
	token := "hostdir-secret-" + randomToken(t)
	installHostdir(r, "w1", "controller", token)
	installHostdir(r, "w1", "node", token)
	installHostdir(r, "w2", "node", token)
	for _, h := range []string{"w1", "w2"} {
		r.eventually(h+" reports the hostdir mount class", 2*time.Minute, func() (bool, string) {
			out, _ := r.kvo("", "get", "host", h, "-o", "json")
			return strings.Contains(out, `"hostdir"`), out
		})
	}
	uids, _ := r.sh("w1", "id kevaso-vmm; id kevaso-vfs")
	uids2, _ := r.sh("w2", "id kevaso-vmm; id kevaso-vfs")
	t.Logf("users: w1 %q, w2 %q", uids, uids2)

	r.must(kvo.Run, `apiVersion: kevaso/v1
kind: Namespace
metadata: { name: mv }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: vm, namespace: mv }
spec:
  runtime: cloud-hypervisor
  image: ubuntu-24.04
  resources: { cpu: 1, memory: 1Gi }
  disk: { class: hostdir, size: 6Gi }
  availability: { onHostLoss: Move }
  volumes:
    - { name: data, class: hostdir, size: 1Gi, mountPath: /data }
`, "apply", "-f", "-")
	r.waitRunning("mv", 30*time.Minute, "w1", "vm")
	s := r.silo("mv", "vm")
	n := vmNames(s)
	if s.Status.Movable != "Anywhere" {
		t.Errorf("movable: %q, want Anywhere", s.Status.Movable)
	}
	img := hostdirRoot + "/volumes/" + s.UID + "/disk.root/root.raw"
	data := cloudhypervisorVolumesDir + "/" + s.UID + "/data"
	share := cloudhypervisor.LayoutFor(n, []kri.Volume{{Name: "data", MountPath: "/data", HostPath: data}}, "").Shares[0]
	host := map[string]string{"w1": "w1", "w2": "w2"}
	other := map[string]string{"w1": "w2", "w2": "w1"}
	ls, _ := r.sh(host[s.Status.Host], "ls -ls "+img+"; du -h --apparent-size "+img+"; findmnt -n -o TARGET,SOURCE "+cloudhypervisorVolumesDir+"/"+s.UID+"/disk.root")
	t.Logf("the root disk on %s:\n%s", s.Status.Host, ls)
	expect(t, "root.raw is the VMM's alone", ls, "-rw------- 1 kevaso-vmm kevaso-vmm")

	// What's in the VM, to find again after each move.
	if out, code := r.in("mv", "vm", "echo on-the-root-disk > /root/marker && echo on-the-data-volume > /data/marker && sync && cat /etc/hostname"); code != 0 {
		t.Fatalf("writing the markers: %d %s", code, out)
	}
	// vmmActive says whether the silo's VMM unit runs on a host.
	vmmActive := func(h string) bool {
		out, _ := r.sh(h, "systemctl is-active "+n.Unit)
		return strings.TrimSpace(out) == "active"
	}
	// watch follows the VMM on both hosts until it runs on to (and the guest answers), and fails
	// if it ever runs on both.
	watch := func(what, from, to string, within time.Duration) {
		t.Helper()
		start := time.Now()
		stopped := time.Time{}
		for time.Since(start) < within {
			f, g := vmmActive(from), vmmActive(to)
			if f && g {
				t.Errorf("%s: two copies run (on %s and %s)", what, from, to)
				return
			}
			if !f && stopped.IsZero() {
				stopped = time.Now()
				t.Logf("%s: stopped on %s after %s", what, from, stopped.Sub(start).Round(time.Second))
			}
			if g {
				t.Logf("%s: VMM up on %s after %s (%s after the stop)", what, to, time.Since(start).Round(time.Second), time.Since(stopped).Round(time.Second))
				return
			}
			time.Sleep(time.Second)
		}
		t.Fatalf("%s: never ran on %s\n%s\n%s", what, to, r.journal(to, 40), r.journal(from, 20))
	}
	// leftOn says what of the silo a host still runs or has mounted ("0 0": nothing).
	leftOn := func(h string) string {
		out, _ := r.sh(h, fmt.Sprintf("pgrep -c virtiofsd; grep -c %s /proc/self/mountinfo; true", s.UID))
		return strings.Join(strings.Fields(out), " ")
	}
	// check: the silo runs on on with its files and only on's exec key; the old host has let go
	// (handedOff: it unmounted; after a host loss its agent is down and can't, see below).
	check := func(what, on string, handedOff bool) {
		t.Helper()
		r.waitRunning("mv", 15*time.Minute, on, "vm")
		if got := r.silo("mv", "vm").Status.Host; got != on {
			t.Fatalf("%s: on %s, want %s", what, got, on)
		}
		r.eventually(what+": the files are there", 3*time.Minute, func() (bool, string) {
			out, code := r.in("mv", "vm", "cat /root/marker /data/marker; findmnt -n -o FSTYPE /data")
			return code == 0 && out == "on-the-root-disk\non-the-data-volume\nvirtiofs", out
		})
		keys, _ := r.in("mv", "vm", "cat /home/kevaso/.ssh/authorized_keys | wc -l; cat /var/lib/cloud/data/instance-id")
		t.Logf("%s: in the guest, authorized keys and instance-id: %q", what, keys)
		if strings.Fields(keys)[0] != "1" {
			t.Errorf("%s: want only the new host's exec key: %q", what, keys)
		}
		old := other[on]
		if vmmActive(old) {
			t.Errorf("%s: the VMM still runs on %s", what, old)
		}
		left := leftOn(old)
		if !handedOff {
			t.Logf("%s: on %s (its agent down): virtiofsd and mounts %q", what, old, left)
			if !strings.HasPrefix(left, "0 ") {
				t.Errorf("%s: virtiofsd still runs on %s", what, old)
			}
		} else if left != "0 0" {
			t.Errorf("%s: %s still has virtiofsd or the volumes mounted: %q", what, old, left)
		}
	}

	// 1. kvo move, twice (so the silo ends on w2: losing w1 would lose the control plane).
	from := s.Status.Host
	for i := 0; i < 2; i++ {
		to := other[from]
		since := time.Now().Add(-time.Second).UTC().Format("2006-01-02 15:04:05")
		out := r.must(kvo.Run, "", "move", "silo", "vm", "-n", "mv", "--to", to)
		t.Logf("kvo move silo vm --to %s: %s", to, strings.TrimSpace(out))
		watch(fmt.Sprintf("kvo move %d (%s → %s)", i+1, from, to), from, to, 10*time.Minute)
		check(fmt.Sprintf("kvo move %d", i+1), to, true)
		mounted, _ := r.sh(to, fmt.Sprintf(`journalctl --since '%s UTC' -o short-iso-precise --no-pager -u kevaso-plugin-hostdir-node.service | grep mounted | head -2`, since))
		t.Logf("on %s (new):\n%s", to, mounted)
		stopOrder(t, r, from, fmt.Sprintf("move %d", i+1), since, n, share, data)
		if i == 0 && to == "w2" {
			break
		}
		from = to
	}
	s = r.silo("mv", "vm")
	if s.Status.Host != "w2" {
		t.Fatalf("on %s, want w2", s.Status.Host)
	}

	// Checklist §3.3: a second VMM on the image from w1 while the VM runs on w2.
	// Read-only, so that if nothing stops it, it can't harm the running VM's disk in its 10s.
	probe, _ := r.sh("w1", fmt.Sprintf(`timeout 10 /opt/kevaso/cloud-hypervisor/cloud-hypervisor --firmware /opt/kevaso/cloud-hypervisor/CLOUDHV_EFI.fd --cpus boot=1 --memory size=256M --disk path=%s,image_type=raw,readonly=on --console off --serial off 2>&1 | grep -v sparse | tail -4; echo "exit ${PIPESTATUS:-?}"`, img))
	t.Logf("a second VMM on the image from w1 (checklist §3.3):\n%s", probe)

	// 2. onHostLoss: Move: w2's kevasod stopped (and kept down); kevaso-fence stops the VM, then
	// the control plane moves it to w1.
	if _, err := r.sh("w2", "systemctl stop kevasod"); err != nil {
		t.Fatal(err)
	}
	stoppedAt := time.Now()
	watch("kevasod stopped on w2 → fence → onHostLoss: Move", "w2", "w1", 8*time.Minute)
	t.Logf("moved %s after w2's kevasod stopped", time.Since(stoppedAt).Round(time.Second))
	fence, _ := r.sh("w2", "journalctl -u kevaso-fence --no-pager | grep fence: | tail -5")
	t.Logf("kevaso-fence on w2:\n%s", fence)
	expect(t, "the fence stopped it on w2", fence, "fence: stopped mv/vm (onHostLoss Move)")
	check("onHostLoss: Move", "w1", false)
	desc, _ := r.kvo("", "describe", "silo", "vm", "-n", "mv")
	t.Logf("kvo describe silo vm:\n%s", desc)
	if _, err := r.sh("w2", "systemctl start kevasod"); err != nil {
		t.Fatal(err)
	}
	// Back, w2's agent lets go of what it had mounted for the silo, and starts nothing.
	r.eventually("w2, back, unmounts the moved silo's volumes", 3*time.Minute, func() (bool, string) {
		l := leftOn("w2")
		return l == "0 0", l
	})
	if vmmActive("w2") {
		t.Error("w2 started the VM again when its kevasod came back")
	}

	// Delete: stopped, unmounted, and the volumes' folders gone from the share.
	r.must(kvo.Run, "", "delete", "silo", "vm", "-n", "mv")
	r.eventually("the volumes' folders are deleted", 5*time.Minute, func() (bool, string) {
		out, _ := r.sh("w1", "ls -A "+hostdirRoot+"/volumes/")
		return strings.TrimSpace(out) == "", out
	})
	for _, h := range []string{"w1", "w2"} {
		left, _ := r.sh(h, fmt.Sprintf("echo vmm=$(systemctl is-active %s) virtiofsd=$(pgrep -c virtiofsd) mounts=$(grep -c %s /proc/self/mountinfo)", n.Unit, s.UID))
		t.Logf("left on %s: %s", h, left)
		if !strings.Contains(left, "virtiofsd=0 mounts=0") || strings.Contains(left, "vmm=active") {
			t.Errorf("left on %s: %s", h, left)
		}
	}
}
