//go:build metal

package e2e

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/internal/cli/kvoadm"
)

// MetalForeignDocker is the KEVASO_METAL_PREINSTALL script TestMetalKvoadmResetLeavesForeign
// needs: Docker installed by a person before Kevaso, with a container and a volume of its own.
const MetalForeignDocker = `set -e
DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker.io >/dev/null
systemctl enable --now docker >/dev/null 2>&1
docker volume create kvt-foreign-vol >/dev/null
docker run -d -q --name kvt-foreign --restart unless-stopped -v kvt-foreign-vol:/data docker.io/library/busybox:1.36 sleep infinity >/dev/null`

// TestMetalKvoadmResetLeavesForeign is K-113 and K-114 (81f17a4, 16fcd62, e31b964) on one machine
// installed with this build, Docker installed before Kevaso (KEVASO_METAL_PREINSTALL=
// MetalForeignDocker) and podman after it:
//   - a silo whose main process is a binary named kevasod doesn't make kvoadm reset refuse;
//   - a step made to fail (an immutable file under /var/lib/kevaso) keeps the install record, and
//     a second look shows the same plan;
//   - the reset done: Docker, its foreign container (running) and volume stay, Kevaso's
//     containers are gone, podman works, and the install record is gone.
//
// It ends the cluster (the suite's own reset follows). Run it alone.
func TestMetalKvoadmResetLeavesForeign(t *testing.T) {
	if !strings.Contains(os.Getenv("KEVASO_METAL_PREINSTALL"), "kvt-foreign") {
		t.Skip("needs KEVASO_METAL_PREINSTALL=MetalForeignDocker's script")
	}
	c := metal(t)
	ns := "resetforeign"
	c.namespace(ns)
	c.apply(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: named, namespace: ` + ns + ` }
spec:
  runtime: docker
  container: { image: docker.io/library/python:3.12-slim, command: ["sh", "-c", "cp /bin/sleep /tmp/kevasod && exec /tmp/kevasod infinity"] }
  resources: { cpu: 1, memory: 256Mi }
`)
	c.waitRunning(ns, 15*time.Minute, "named")
	if n, _ := strconv.Atoi(strings.TrimSpace(c.mustSh("pgrep -xc kevasod || true"))); n < 2 {
		t.Fatalf("%d processes named kevasod: want kevasod itself and the silo's", n)
	}
	c.mustSh("DEBIAN_FRONTEND=noninteractive apt-get install -y -q podman >/dev/null")
	t.Logf("the install record: %s", c.mustSh("ls -l /var/lib/kevaso-install/ 2>&1; wc -l < /var/lib/kevaso-install/installed 2>&1"))

	cfg := c.cfg
	ssh := []string{cfg.SSHTarget(), "--ssh-port", strconv.Itoa(cfg.Port), "--ssh-key", cfg.KeyFile, "--host-key", cfg.HostKey}
	reset := func(extra ...string) (string, int) {
		var o bytes.Buffer
		code := kvoadm.Run(c.ctx, append(append([]string{"reset"}, ssh...), extra...), strings.NewReader(""), &o, &o)
		return metalRedact(o.String()), code
	}
	planOf := func(out string) string {
		var keep []string
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(strings.TrimSpace(l), "- ") {
				keep = append(keep, strings.TrimSpace(l))
			}
		}
		return strings.Join(keep, "\n")
	}
	first, code := reset("--force", "--dry-run")
	t.Logf("kvoadm reset --dry-run (exit %d):\n%s", code, first)
	for _, w := range []string{"Docker stays (it was there before)", "podman"} {
		if !strings.Contains(first, w) {
			t.Errorf("the plan doesn't name %s", w)
		}
	}

	// A step made to fail: a file under /var/lib/kevaso no one can remove (immutable). (A busy
	// mount doesn't: the reset stops every kvt-* unit and unmounts what is under its paths.)
	c.mustSh("touch /var/lib/kevaso/kvt-stuck && chattr +i /var/lib/kevaso/kvt-stuck")
	t.Cleanup(func() {
		_, _ = c.sh("chattr -i /var/lib/kevaso/kvt-stuck 2>/dev/null; rm -f /var/lib/kevaso/kvt-stuck; true")
	})
	cut, code := reset("--force", "--yes")
	t.Logf("kvoadm reset with a step made to fail (exit %d):\n%s", code, cut)
	if strings.Contains(cut, "still running") || strings.Contains(cut, "still runs") {
		t.Errorf("refused for a silo's process named kevasod")
	}
	if code == 0 {
		t.Errorf("the reset passed with an immutable file under /var/lib/kevaso: the failing step wasn't made")
	}
	c.expect("the install record is kept", c.mustSh("test -e /var/lib/kevaso-install/installed && echo kept || echo gone"), "kept")
	again, _ := reset("--force", "--dry-run")
	t.Logf("a second look:\n%s", again)
	pkgs := func(plan string) string {
		var l []string
		for _, s := range strings.Split(plan, "\n") {
			if strings.Contains(s, "purge") || strings.Contains(s, "left installed") {
				l = append(l, s)
			}
		}
		return strings.Join(l, "\n")
	}
	if a, b := pkgs(planOf(first)), pkgs(planOf(again)); a != b {
		t.Errorf("the packages in the plan changed after the cut reset:\nbefore:\n%s\nafter:\n%s", a, b)
	}

	c.mustSh("chattr -i /var/lib/kevaso/kvt-stuck && rm -f /var/lib/kevaso/kvt-stuck")
	done, code := reset("--force", "--yes")
	t.Logf("kvoadm reset (exit %d):\n%s", code, done)
	if code != 0 {
		t.Errorf("kvoadm reset: exit %d", code)
	}
	c.expect("Docker stays", c.mustSh("dpkg-query -W -f '${Status}' docker.io 2>/dev/null | grep -c 'install ok installed' || true"), "1")
	c.expect("its foreign container runs", c.mustSh("docker inspect -f '{{.State.Running}}' kvt-foreign 2>&1"), "true")
	c.expect("its foreign volume stays", c.mustSh("docker volume ls -q | grep -c '^kvt-foreign-vol$' || true"), "1")
	c.expect("no container of Kevaso's", c.mustSh("docker ps -aq --filter label=kevaso.com/uid | wc -l; true"), "0")
	c.expect("nothing named kv-", c.mustSh("docker ps -a --format '{{.Names}}' | grep -c '^kv-' || true"), "0")
	c.expect("podman works", c.mustSh("podman --version >/dev/null 2>&1 && echo yes || echo no"), "yes")
	c.expect("the install record is gone", c.mustSh("test -e /var/lib/kevaso-install && echo there || echo gone"), "gone")
	t.Logf("other packages after: %s", c.mustSh("for p in qemu-utils genisoimage nftables lvm2; do echo \"$p $(dpkg-query -W -f '${Status}' $p 2>/dev/null)\"; done"))
}
