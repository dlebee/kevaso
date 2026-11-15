//go:build metal

package e2e

import (
	"strings"
	"testing"
	"time"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/sdk/kri"
)

// TestMetalRestartDuringRootDiskCreate is metal.md's B4: kevasod restarted while a microVM's root
// disk is being made (a watcher restarts it the moment lvcreate or the image convert for that LV
// runs). The microVM still comes up, a second microVM is made after it, and the pool is never
// removed or found half-active ("prohibited while … _tmeta is active").
//
// Listens on nothing outside.
func TestMetalRestartDuringRootDiskCreate(t *testing.T) {
	c := metal(t)
	ns := "b4"
	c.namespace(ns)
	since := strings.TrimSpace(c.mustSh("date -u '+%Y-%m-%d %H:%M:%S'"))
	t.Cleanup(func() { _, _ = c.sh("systemctl stop kvt-b4 2>/dev/null; rm -f /run/kvt-b4; true") })
	// The watcher can't know the LV's name before the silo exists: any root-disk lvcreate or
	// convert onto a kv- LV while nothing else is being made.
	c.mustSh(`systemd-run --unit=kvt-b4 sh -c 'for i in $(seq 1 6000); do if pgrep -f "[l]vcreate .*-n kv-|[q]emu-img convert .*/dev/kevaso/kv-" >/dev/null; then echo "$(pgrep -af "[l]vcreate .*-n kv-|[q]emu-img convert .*/dev/kevaso/kv-" | head -1)" > /run/kvt-b4; systemctl restart kevasod; exit; fi; sleep 0.02; done' >/dev/null`)
	c.apply(vmEcho(ns, "first", 8080))
	c.eventually("kevasod restarted during the root disk's making", 10*time.Minute, func() (bool, string) {
		out, _ := c.sh("cat /run/kvt-b4 2>/dev/null")
		return strings.TrimSpace(out) != "", "not yet"
	})
	t.Logf("restarted during: %s", strings.TrimSpace(c.mustSh("cat /run/kvt-b4")))
	c.eventually("the API back", 3*time.Minute, func() (bool, string) { o, code := c.kvo("", "get", "hosts"); return code == 0, o })
	c.waitRunning(ns, 15*time.Minute, "first")
	c.apply(vmEcho(ns, "second", 8080))
	c.waitRunning(ns, 15*time.Minute, "second")
	for _, n := range []string{"first", "second"} {
		got, code := c.in(ns, n, "echo booted")
		if code != 0 || strings.TrimSpace(got) != "booted" {
			t.Errorf("%s: %d %s", n, code, got)
		}
	}
	n := cloudhypervisor.NamesFor(kri.ID{Namespace: ns, Name: "first", UID: c.silo(ns, "first").UID})
	j := c.mustSh("journalctl -u kevasod --no-pager --since '" + since + "' | grep -E 'lvremove|prohibited|repair|tmeta|half-made' | tail -10; true")
	t.Logf("the journal (pool):\n%s", j)
	if strings.Contains(j, "prohibited while") {
		t.Error("the pool was found half-active and not repaired")
	}
	if strings.Contains(j, "lvremove -q -y kevaso/silos") || strings.Contains(j, "lvremove -q -y "+cloudhypervisor.VG+"/"+cloudhypervisor.ThinPool+" ") {
		t.Error("the pool was removed")
	}
	t.Logf("first's LV %s: %s", n.LV, strings.TrimSpace(c.mustSh("lvs --noheadings -o lv_name,lv_attr kevaso | tr -s ' '")))
}
