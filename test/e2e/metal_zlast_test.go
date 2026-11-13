//go:build metal

package e2e

// These run last in a whole run (files are taken in name order): podman changes the worker's
// runtimes, and the reboot takes the machine down.

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/sdk/kri"
)

// enableWorker sets the worker's runtimes with kvoadm host enable-worker (the same storage and
// egress CA as setup).
func (c *mt) enableWorker(runtimes ...string) {
	c.t.Helper()
	args := []string{"host", "enable-worker", c.cfg.SSHTarget(), "--ssh-port", strconv.Itoa(c.cfg.Port), "--ssh-key", c.cfg.KeyFile,
		"--host-key", c.cfg.HostKey, "--loop-storage", metalLoop, "--egress-extra-ca", "/etc/kevaso/test-internet-ca.pem"}
	for _, r := range runtimes {
		args = append(args, "--runtime", r)
	}
	var o bytes.Buffer
	if code := kvoadm.Run(c.ctx, args, strings.NewReader(""), &o, &o); code != 0 {
		c.t.Fatalf("kvoadm host enable-worker %v: exit %d\n%s", runtimes, code, o.String())
	}
	c.eventually("the API is back after the worker's restart", 3*time.Minute, func() (bool, string) {
		out, code := c.kvo("", "get", "hosts")
		return code == 0, out
	})
}

// runtimeReady waits for a runtime of the host to be Ready, failing on Failed.
func (c *mt) runtimeReady(rt string, within time.Duration) {
	c.t.Helper()
	c.eventually("runtime "+rt+" Ready", within, func() (bool, string) {
		var h v1.Host
		out, code := c.kvo("", "get", "host", metalHost, "-o", "json")
		if code != 0 || jsonUnmarshal(out, &h) != nil {
			return false, out
		}
		st := h.Status.Runtimes[rt]
		if st.State == "Failed" {
			c.t.Fatalf("runtime %s failed: %s", rt, st.Message)
		}
		return st.State == "Ready", fmt.Sprintf("%+v", st)
	})
}

// TestMetalPodman is podman as the container engine (design §0.2): added to the worker with
// kvoadm host enable-worker next to cloud-hypervisor and docker (which keep their silos), its
// silo runs, opens a port on the external IP, gets an endpoint secret with plain curl… from
// python; then podman is taken off again.
//
// Listens on the external IP while it runs: 18130.
func TestMetalPodman(t *testing.T) {
	c := metal(t)
	ns := "pod"
	c.namespace(ns, "grant/podapp", "secret/pod-pw")
	c.apply(boxEcho(ns, "keep", 8080))
	c.waitRunning(ns, 10*time.Minute, "keep")
	keepUID := c.silo(ns, "keep").UID
	startedAt := func() string {
		return strings.TrimSpace(c.mustSh(`docker ps -q --filter label=kevaso.com/uid=` + keepUID + ` | xargs -r docker inspect -f '{{.Name}} {{.State.StartedAt}}' | sort`))
	}
	before := startedAt()

	c.enableWorker("cloud-hypervisor", "docker", "podman")
	t.Cleanup(func() { c.enableWorker("cloud-hypervisor", "docker") })
	c.runtimeReady("podman", 15*time.Minute)
	if after := startedAt(); after != before {
		t.Errorf("adding podman restarted a docker silo: %q → %q", before, after)
	}

	pw := randomValue(t, "pod-")
	c.must(pw, "create", "secret", "pod-pw", "-n", ns, "--from-file", "-")
	c.apply(`apiVersion: kevaso/v1
kind: Grant
metadata: { name: podapp, namespace: ` + ns + ` }
spec:
  secrets: [{ name: pod-pw }]
---
` + strings.Replace(boxEcho(ns, "web", 18130), "runtime: docker", "runtime: podman", 1) + `  grants: [podapp]
  ports: [{ name: web, port: 18130 }]
  service:
    ports: [{ port: web, hostPort: [external] }]
`)
	c.waitRunning(ns, 10*time.Minute, "web")
	c.eventually("a podman silo answers this Mac on the external IP", time.Minute, func() (bool, string) {
		ok, got := c.open(18130)
		return ok && strings.Contains(got, "web 18130"), got
	})
	got, _ := c.in(ns, "web", `python3 -c "import urllib.request as u; print(u.urlopen(u.Request('http://169.254.42.1/v1/secrets/pod-pw', headers={'Kevaso-Local': '1'}), timeout=10).read().decode())"`)
	c.expect("its local endpoint answers", got, pw)
	uid := c.silo(ns, "web").UID
	c.expect("it is podman's", c.mustSh("podman ps -a --filter label=kevaso.com/uid="+uid+" --format '{{.Labels}}' | head -1"), "kevaso.com/uid:"+uid)
	c.must("", "delete", "silo", "web", "-n", ns)
	c.eventually("deleted: podman has nothing of it", 3*time.Minute, func() (bool, string) {
		out, _ := c.sh("podman ps -aq --filter label=kevaso.com/uid=" + uid)
		return strings.TrimSpace(out) == "", out
	})
}

// TestMetalReboot reboots the machine itself (sudo systemctl reboot over SSH) and checks what
// comes back: the same pinned host key, a new boot, kevasod and the fence running (both enabled),
// the runtimes Ready (the volume group's loop file attached again), and the silos running again
// as their restart rules say (every silo is meant to run: Wait and Recreate alike), the
// microVM's volume with its data.
//
// Listens on nothing outside but what the silos it makes would.
func TestMetalReboot(t *testing.T) {
	c := metal(t)
	ns := "boot"
	c.namespace(ns)
	c.apply(boxEcho(ns, "stay", 8080) + "---\n" + boxEcho(ns, "moves", 8080) + "  availability: { onHostLoss: Recreate }\n---\n" +
		vmEcho(ns, "vm", 8080) + "  volumes: [{ name: data, size: 1Gi, mountPath: /data }]\n")
	c.waitRunning(ns, 20*time.Minute, "stay", "moves", "vm")
	marker := randomValue(t, "boot-")
	if out, code := c.in(ns, "vm", "echo "+marker+" > /data/marker && sync"); code != 0 {
		t.Fatalf("write: %d %s", code, out)
	}
	bootID := strings.TrimSpace(c.mustSh("cat /proc/sys/kernel/random/boot_id"))

	_, _ = c.sh("nohup sh -c 'sleep 2; systemctl reboot' >/dev/null 2>&1 &")
	_ = c.d.Close()
	time.Sleep(20 * time.Second)
	c.eventually("the machine is back over SSH, with the pinned host key", 15*time.Minute, func() (bool, string) {
		out, err := c.sh("cat /proc/sys/kernel/random/boot_id")
		if err != nil {
			_ = c.d.Close()
			return false, err.Error()
		}
		return strings.TrimSpace(out) != bootID, "same boot " + out
	})
	t.Logf("rebooted: a new boot, and the host key still matched the pin (%s)", c.cfg.HostKey)

	for _, u := range []string{"kevasod", "kevaso-fence"} {
		c.eventually(u+" runs after the boot", 3*time.Minute, func() (bool, string) {
			out, _ := c.sh("systemctl is-enabled " + u + "; systemctl is-active " + u)
			return strings.Contains(out, "enabled") && strings.HasSuffix(strings.TrimSpace(out), "active") && !strings.Contains(out, "inactive"), out
		})
	}
	c.eventually("the API answers", 5*time.Minute, func() (bool, string) {
		out, code := c.kvo("", "get", "hosts")
		return code == 0 && strings.Contains(out, "Ready"), out
	})
	c.runtimeReady("cloud-hypervisor", 10*time.Minute)
	c.runtimeReady("docker", 10*time.Minute)
	c.waitRunning(ns, 15*time.Minute, "stay", "moves", "vm")
	vm := c.silo(ns, "vm")
	unit := cloudhypervisor.NamesFor(kri.ID{Namespace: vm.Namespace, Name: vm.Name, UID: vm.UID}).Unit
	c.expect("the microVM's unit is up", c.mustSh("systemctl is-active "+unit), "active")
	c.eventually("the microVM's volume still has its data", 5*time.Minute, func() (bool, string) {
		out, code := c.in(ns, "vm", "cat /data/marker")
		return code == 0 && out == marker, out
	})
	c.expect("the volume group's loop file is attached again", c.mustSh("losetup -n -O BACK-FILE -l | tr -d ' '"), "/var/lib/kevaso-storage.img")
	// The stand-in internet is a transient unit: the boot ended it. Start it again (same CA).
	if out, err := c.sh("systemctl reset-failed kvt-inet 2>/dev/null; systemd-run --unit=kvt-inet python3 /var/lib/kvt-inet/server.py"); err != nil {
		t.Logf("the stand-in internet after the boot: %v %s", err, out)
	}
}
