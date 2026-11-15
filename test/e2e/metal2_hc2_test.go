//go:build metal

package e2e

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/sdk/kri"
)

// host-code-2's claims on the machines, beside the long soak (a kept cluster, own namespaces,
// nothing reset or rebooted).

// claimTime is the time in a silo's start claim ("starting on HOST at TIME"), "" when none.
func claimTime(s *v1.Silo) string {
	c := meta.FindCondition(s.Status.Conditions, "StartClaim")
	if c == nil || c.Status != meta.ConditionTrue {
		return ""
	}
	_, at, _ := strings.Cut(c.Message, " at ")
	return at
}

// TestMetal2StartClaimFreshThroughSlowInit is claim 2 (77fa95f): through a slow init step, a
// microVM's and a docker silo's start claims are renewed at least every 10s, and stop changing
// once the silo runs.
//
// Listens on nothing outside.
func TestMetal2StartClaimFreshThroughSlowInit(t *testing.T) {
	p := metal2(t)
	c := p.c1
	ns := "claimfresh2"
	c.namespace(ns)
	slow := "  init: { steps: [{ name: slow, run: \"sleep 60\" }] }\n"
	for _, name := range []string{"vm", "box"} {
		t.Run(name, func(t *testing.T) {
			c := c.with(t)
			if name == "vm" { // one at a time: each is watched from its start
				c.apply(vmEcho(ns, "vm", 8080) + slow)
			} else {
				c.apply(boxEcho(ns, "box", 8080) + slow)
			}
			var times []string
			changedAt := time.Time{}
			longest := time.Duration(0)
			deadline := time.Now().Add(20 * time.Minute)
			for {
				s := c.silo(ns, name)
				if at := claimTime(s); at != "" && (len(times) == 0 || times[len(times)-1] != at) {
					if !changedAt.IsZero() {
						longest = max(longest, time.Since(changedAt))
					}
					times, changedAt = append(times, at), time.Now()
				}
				if s.Status.Phase == "Running" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("never ran: %s", s.Status.Phase)
				}
				time.Sleep(5 * time.Second)
			}
			if len(times) < 4 {
				t.Errorf("the claim changed %d times through a 60s init step: not kept fresh", len(times))
			}
			if longest > 16*time.Second { // renewed every 10s, read every 5s
				t.Errorf("%s between two renewals of the claim", longest.Round(time.Second))
			} else {
				t.Logf("claim renewed %d times, at most %s apart", len(times), longest.Round(time.Second))
			}
			last := claimTime(c.silo(ns, name))
			time.Sleep(25 * time.Second)
			if now := claimTime(c.silo(ns, name)); now != last && now != "" {
				t.Errorf("the claim still changes once it runs: %q → %q", last, now)
			}
		})
	}
}

// TestMetal2VMResetTakenBackDuringStop is claim 3 (19bf8a3): a microVM's kvo reset, taken back
// while its guest powers off: its root disk is the same logical volume (same creation time) and a
// file written before is there.
//
// Listens on nothing outside.
func TestMetal2VMResetTakenBackDuringStop(t *testing.T) {
	p := metal2(t)
	c := p.c1
	ns := "vmresetback2"
	c.namespace(ns)
	c.apply(vmEcho(ns, "vm", 8080))
	c.waitRunning(ns, 20*time.Minute, "vm")
	if out, code := c.in(ns, "vm", "echo kept > /root/marker && sync"); code != 0 {
		t.Fatalf("write: %d %s", code, out)
	}
	s := c.silo(ns, "vm")
	host := map[string]*mt{metalHost: p.c1, metalHost2: p.c2}[s.Status.Host]
	n := cloudhypervisor.NamesFor(kri.ID{Namespace: ns, Name: "vm", UID: s.UID})
	lvTime := func() string { return strings.TrimSpace(host.mustSh("lvs --noheadings -o lv_time kevaso/" + n.LV)) }
	before := lvTime()
	old := s.Spec.Reset
	c.must("", "reset", "silo", "vm", "-n", ns)
	// Taken back at once: the guest powers off (up to 30s) with its unit still active.
	for {
		var cur v1.Silo
		if err := json.Unmarshal([]byte(c.must("", "get", "silo", "vm", "-n", ns, "-o", "json")), &cur); err != nil {
			t.Fatal(err)
		}
		cur.Spec.Reset = old
		b, _ := json.Marshal(cur)
		if _, code := c.kvo(string(b), "apply", "-f", "-"); code == 0 {
			break
		}
	}
	t.Logf("the reset taken back while the guest powers off (unit %s)", strings.TrimSpace(host.mustSh("systemctl is-active "+n.Unit+" || true")))
	c.waitRunning(ns, 10*time.Minute, "vm")
	if now := lvTime(); now != before {
		t.Errorf("the root disk was made again: created %s, now %s", before, now)
	}
	got, _ := c.in(ns, "vm", "cat /root/marker 2>&1")
	c.expect("its file is there", got, "kept")
}

// TestMetal2StuckStopIsNotStopped is claim 1 (2a1adf0): a microVM whose unit sits in
// deactivating (its VMM frozen, the stop's timeout long) isn't counted stopped: its status never
// says so, and nothing starts another copy, until the process is gone.
//
// Listens on nothing outside.
func TestMetal2StuckStopIsNotStopped(t *testing.T) {
	p := metal2(t)
	c := p.c1
	ns := "stuckstop2"
	c.namespace(ns)
	c.apply(vmEcho(ns, "vm", 8080))
	c.waitRunning(ns, 20*time.Minute, "vm")
	s := c.silo(ns, "vm")
	host := map[string]*mt{metalHost: p.c1, metalHost2: p.c2}[s.Status.Host]
	n := cloudhypervisor.NamesFor(kri.ID{Namespace: ns, Name: "vm", UID: s.UID})
	t.Cleanup(func() {
		_, _ = host.sh("kill -CONT $(systemctl show -p MainPID --value " + n.Unit + ") 2>/dev/null; rm -rf /run/systemd/system/" + n.Unit + ".d/kvt-slowstop.conf; systemctl daemon-reload; true")
	})
	host.mustSh("mkdir -p /run/systemd/system/" + n.Unit + ".d && printf '[Service]\\nTimeoutStopSec=120\\n' > /run/systemd/system/" + n.Unit + ".d/kvt-slowstop.conf && systemctl daemon-reload && " +
		"kill -STOP $(systemctl show -p MainPID --value " + n.Unit + ") && systemctl stop --no-block " + n.Unit)
	c.eventually("its unit sits in deactivating", 30*time.Second, func() (bool, string) {
		st := strings.TrimSpace(host.mustSh("systemctl is-active " + n.Unit + " || true"))
		return st == "deactivating", st
	})
	for end := time.Now().Add(60 * time.Second); time.Now().Before(end); time.Sleep(2 * time.Second) {
		cur := c.silo(ns, "vm")
		if r := meta.FindCondition(cur.Status.Conditions, "Ready"); r != nil && strings.Contains(r.Message, "Stopped") {
			t.Fatalf("counted stopped while its process is still there: %s", r.Message)
		}
		if out := strings.TrimSpace(host.mustSh("pgrep -fc -- '[c]loud-hypervisor.*" + n.Socket + "' || true")); out != "1" {
			t.Fatalf("%s VMMs of it while the stop is stuck", out)
		}
	}
	t.Log("a minute in deactivating: never counted stopped, no second copy")
	host.mustSh("kill -CONT $(systemctl show -p MainPID --value " + n.Unit + ") 2>/dev/null; true")
	c.waitRunning(ns, 10*time.Minute, "vm")
}

// TestMetal2UnreadableWatermarkClearsItself is claim 5 (e92a474) on machine 2 (a worker): kevasod
// started with its watermark unreadable holds (WatermarkUnreadable: running silos run on, a new
// one doesn't start); the file put back as it was, the hold ends by itself, without a restart,
// and the new silo starts.
//
// Listens on nothing outside.
func TestMetal2UnreadableWatermarkClearsItself(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "watermark2"
	c.namespace(ns)
	const wm = "/var/lib/kevaso/control-plane-watermark.json"
	t.Cleanup(func() {
		_, _ = p.c2.sh("[ -d " + wm + " ] && rmdir " + wm + "; [ -e " + wm + ".kvt ] && mv " + wm + ".kvt " + wm + "; true")
	})
	p.c2.mustSh("systemctl stop kevasod && mv " + wm + " " + wm + ".kvt && mkdir " + wm + " && systemctl start kevasod")
	pid := strings.TrimSpace(p.c2.mustSh("systemctl show -p MainPID --value kevasod"))
	c.eventually("machine 2 holds: its watermark is unreadable", 3*time.Minute, func() (bool, string) {
		h := c.hostNamed(metalHost2)
		b := meta.FindCondition(h.Status.Conditions, "ControlPlaneBehind")
		return b != nil && b.Status == meta.ConditionTrue && b.Reason == "WatermarkUnreadable", fmt.Sprint(b)
	})
	c.apply(boxEcho(ns, "new", 8080) + on(metalHost2))
	time.Sleep(20 * time.Second)
	if s := c.silo(ns, "new"); s.Status.Phase == "Running" {
		t.Fatal("a new silo started on a held worker")
	}
	p.c2.mustSh("rmdir " + wm + " && mv " + wm + ".kvt " + wm)
	c.eventually("the hold ends by itself", 2*time.Minute, func() (bool, string) {
		h := c.hostNamed(metalHost2)
		b := meta.FindCondition(h.Status.Conditions, "ControlPlaneBehind")
		return b != nil && b.Status == meta.ConditionFalse, fmt.Sprint(b)
	})
	c.waitRunning(ns, 5*time.Minute, "new")
	if now := strings.TrimSpace(p.c2.mustSh("systemctl show -p MainPID --value kevasod")); now != pid {
		t.Errorf("kevasod restarted (%s → %s): the hold was to end by itself", pid, now)
	}
}
