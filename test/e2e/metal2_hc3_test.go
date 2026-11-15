//go:build metal

package e2e

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/sdk/kri"
)

// host-code-3's checks on the machines (8e9bbfa, ed24c87, cde8926), beside the long soak.

// keptLists says whether a host's KeptSilos names something of a namespace.
func keptLists(c *mt, host, ns string) bool {
	h := c.hostNamed(host)
	k := meta.FindCondition(h.Status.Conditions, "KeptSilos")
	return k != nil && k.Status == meta.ConditionTrue && strings.Contains(k.Message, ns+"/")
}

// TestMetal2DeleteDuringInit is item A on machine 2: a docker silo deleted while its init step
// (sleep 300) runs: within seconds nothing of it is left (no init, no pause, no state) and
// nothing is kept.
//
// Listens on nothing outside.
func TestMetal2DeleteDuringInit(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "delinit2"
	c.namespace(ns)
	c.apply(boxEcho(ns, "slow", 8080) + on(metalHost2) + "  init: { steps: [{ name: slow, run: \"sleep 300\" }] }\n")
	uid := c.silo(ns, "slow").UID
	short := cloudhypervisor.NamesFor(kri.ID{Namespace: ns, Name: "slow", UID: uid}).Short
	c.eventually("its init step runs", 10*time.Minute, func() (bool, string) {
		out, _ := p.c2.sh("docker ps --format '{{.Names}}' | grep -c '^kv-" + short + "-init$' || true")
		return strings.TrimSpace(out) == "1", out
	})
	since := strings.TrimSpace(p.c2.mustSh("date -u '+%Y-%m-%d %H:%M:%S'"))
	c.must("", "delete", "silo", "slow", "-n", ns)
	at := time.Now()
	c.eventually("nothing of it left on machine 2 (init, pause, state)", 30*time.Second, func() (bool, string) {
		out := strings.TrimSpace(p.c2.mustSh("docker ps -aq --filter name=kv-" + short + " | wc -l; ls /var/lib/kevaso-containers | grep -c " + short + " || true"))
		return strings.Join(strings.Fields(out), " ") == "0 0", out
	})
	t.Logf("gone %s after the delete", time.Since(at).Round(time.Second))
	c.expect("the journal says it removed it", p.c2.mustSh("journalctl -u kevasod --no-pager --since '"+since+"' | grep -c 'removing "+ns+"/slow' || true"), "1")
	time.Sleep(15 * time.Second)
	if keptLists(c, metalHost2, ns) {
		t.Error("KeptSilos names it")
	}
}

// TestMetal2DeleteThenRestart is item B: a microVM deleted, and machine 2's kevasod restarted
// within a second: the seen delete survives the restart (/var/lib/kevaso/seen-deletes.json), the
// new run removes the copy, the file is empty afterwards, nothing is kept or left running.
//
// Listens on nothing outside.
func TestMetal2DeleteThenRestart(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "delrestart2"
	c.namespace(ns)
	c.apply(vmEcho(ns, "vm", 8080) + on(metalHost2))
	c.waitRunning(ns, 20*time.Minute, "vm")
	s := c.silo(ns, "vm")
	n := cloudhypervisor.NamesFor(kri.ID{Namespace: ns, Name: "vm", UID: s.UID})
	since := strings.TrimSpace(p.c2.mustSh("date -u '+%Y-%m-%d %H:%M:%S'"))
	c.must("", "delete", "silo", "vm", "-n", ns)
	p.c2.mustSh("systemctl restart kevasod")
	t.Log("deleted, and machine 2's kevasod restarted at once")
	c.eventually("the copy removed after the restart", 5*time.Minute, func() (bool, string) {
		out := strings.TrimSpace(p.c2.mustSh("systemctl is-active " + n.Unit + " || true; lvs --noheadings -o lv_name kevaso | tr -d ' ' | grep -c '^" + n.LV + "' || true"))
		return strings.Fields(out)[0] != "active" && strings.Fields(out)[len(strings.Fields(out))-1] == "0", out
	})
	j := p.c2.mustSh("journalctl -u kevasod --no-pager --since '" + since + "' | grep -E 'seen deletes|removing " + ns + "/vm' | head -5")
	t.Logf("journal:\n%s", j)
	if !strings.Contains(j, "removing "+ns+"/vm") {
		t.Error("the journal doesn't say it removed it")
	}
	c.expect("the seen-deletes file is empty afterwards", strings.TrimSpace(p.c2.mustSh("cat /var/lib/kevaso/seen-deletes.json 2>/dev/null || echo '[]'")), "[]")
	if keptLists(c, metalHost2, ns) {
		t.Error("KeptSilos names it")
	}
}

// TestMetal2KevasodStopsQuickly is item C: systemctl stop kevasod finishes in under 35s on each
// machine, running its silos (and the soak's); over 5s, the journal names what it waited for.
// Each is started again at once.
//
// Listens on nothing outside.
func TestMetal2KevasodStopsQuickly(t *testing.T) {
	p := metal2(t)
	for _, h := range []*mt{p.c2, p.c1} {
		since := strings.TrimSpace(h.mustSh("date -u '+%Y-%m-%d %H:%M:%S'"))
		out := strings.TrimSpace(h.mustSh("s=$(date +%s.%N); systemctl stop kevasod; e=$(date +%s.%N); systemctl start kevasod; awk -v e=$e -v s=$s 'BEGIN{print e-s}'"))
		secs, _ := strconv.ParseFloat(out, 64)
		t.Logf("%s: systemctl stop kevasod took %.1fs", h.cfg.ExternalIP, secs)
		if secs > 35 {
			t.Errorf("%s: kevasod took %.1fs to stop", h.cfg.ExternalIP, secs)
		}
		if secs > 5 {
			t.Logf("what it waited for:\n%s", h.mustSh("journalctl -u kevasod --no-pager --since '"+since+"' | grep -iE 'waiting|waited|still' | tail -5"))
		}
		p.c1.eventually("the API back", 3*time.Minute, func() (bool, string) { o, code := p.c1.kvo("", "get", "hosts"); return code == 0, o })
	}
}

// TestMetal2BackoffHoldsNoClaim is item F: a microVM's VMM killed by systemd right after each
// start, twice (systemctl kill --kill-whom=main: no PID read and killed later): while it waits
// out its restart backoff (Ready says it starts again in …), its start claim isn't renewed. Each
// restart is timed; the kernel's log is read for an OOM kill.
//
// Listens on nothing outside.
func TestMetal2BackoffHoldsNoClaim(t *testing.T) {
	p := metal2(t)
	c := p.c1
	ns := "backoff2"
	c.namespace(ns)
	c.apply(vmEcho(ns, "vm", 8080))
	c.waitRunning(ns, 20*time.Minute, "vm")
	s := c.silo(ns, "vm")
	host := map[string]*mt{metalHost: p.c1, metalHost2: p.c2}[s.Status.Host]
	n := cloudhypervisor.NamesFor(kri.ID{Namespace: ns, Name: "vm", UID: s.UID})
	since := strings.TrimSpace(host.mustSh("date -u '+%Y-%m-%d %H:%M:%S'"))
	enter := func() string {
		return strings.TrimSpace(host.mustSh("systemctl show -p ActiveEnterTimestampMonotonic --value " + n.Unit))
	}
	kill := func() string {
		at := enter()
		host.mustSh("systemctl kill -s KILL --kill-whom=main " + n.Unit)
		return at
	}
	was := kill()
	killed := time.Now()
	c.eventually("started again once (a new start of its unit)", 10*time.Minute, func() (bool, string) {
		now := enter()
		active := strings.TrimSpace(host.mustSh("systemctl is-active " + n.Unit + " || true"))
		return now != was && now != "0" && active == "active", now + " " + active
	})
	t.Logf("the first restart took %s", time.Since(killed).Round(time.Second))
	kill()
	c.eventually("waiting out its backoff", 3*time.Minute, func() (bool, string) {
		r := meta.FindCondition(c.silo(ns, "vm").Status.Conditions, "Ready")
		return r != nil && strings.Contains(r.Message, "starting it again in"), fmt.Sprint(r)
	})
	held := claimTime(c.silo(ns, "vm"))
	for end := time.Now().Add(20 * time.Second); time.Now().Before(end); time.Sleep(3 * time.Second) {
		cur := c.silo(ns, "vm")
		r := meta.FindCondition(cur.Status.Conditions, "Ready")
		if r == nil || !strings.Contains(r.Message, "starting it again in") {
			break // the backoff is over
		}
		if now := claimTime(cur); now != held {
			t.Fatalf("its start claim renewed during the backoff: %q → %q", held, now)
		}
	}
	t.Logf("during the backoff the claim stayed %q", held)
	c.waitRunning(ns, 10*time.Minute, "vm")
	t.Logf("the kernel's log since: %s", host.mustSh("journalctl -k --no-pager --since '"+since+"' | grep -iE 'oom|killed process' | tail -3; true"))
	t.Logf("the agent's log for it:\n%s", host.mustSh("journalctl -u kevasod --no-pager --since '"+since+"' | grep "+ns+"/vm | grep -v 'retry in 1' | tail -12"))
}

// TestMetal2VMMLock is host-code-4's claim 3 (f251e18): a microVM started after the upgrade runs
// its VMM under a lock it holds itself (flock --no-fork): its unit's MainPID is cloud-hypervisor
// with this silo's socket, the lock is held while it runs, by the VMM, and a second taker waits
// and gives up (75).
//
// Listens on nothing outside.
func TestMetal2VMMLock(t *testing.T) {
	p := metal2(t)
	c := p.c1
	ns := "vmmlock2"
	c.namespace(ns)
	c.apply(vmEcho(ns, "vm", 8080))
	c.waitRunning(ns, 20*time.Minute, "vm")
	s := c.silo(ns, "vm")
	host := map[string]*mt{metalHost: p.c1, metalHost2: p.c2}[s.Status.Host]
	n := cloudhypervisor.NamesFor(kri.ID{Namespace: ns, Name: "vm", UID: s.UID})
	lock := n.Dir + "/vmm.lock"
	pid := strings.TrimSpace(host.mustSh("systemctl show -p MainPID --value " + n.Unit))
	cmd := host.mustSh("tr '\\0' ' ' < /proc/" + pid + "/cmdline")
	if !strings.Contains(cmd, "cloud-hypervisor") || !strings.Contains(cmd, n.Socket) || strings.HasPrefix(strings.TrimSpace(cmd), "/usr/bin/flock") {
		t.Errorf("its MainPID %s is %q, want cloud-hypervisor with its socket", pid, cmd)
	}
	c.expect("the lock is held while it runs", host.mustSh("flock -n -E 75 "+lock+" true; echo $?"), "75")
	c.expect("held by the VMM itself", host.mustSh("ls -l /proc/"+pid+"/fd | grep -c vmm.lock || true"), "1")
	start := time.Now()
	c.expect("a second taker waits and gives up", host.mustSh("sudo -u "+cloudhypervisor.VMMUser+" flock --no-fork -w 5 -E 75 "+lock+" true; echo $?"), "75")
	t.Logf("it gave up after %s", time.Since(start).Round(time.Second))
}

// TestMetal2ResetCutDuringConvert is host-code-4's claim 2a (b477cb6): kvo reset of a microVM,
// kevasod killed (SIGKILL) while qemu-img converts the image onto its new root disk: the mark is
// saved, kevasod comes back (Restart), the convert runs again before the unit starts, the guest
// boots, and the mark is gone.
//
// Listens on nothing outside.
func TestMetal2ResetCutDuringConvert(t *testing.T) {
	p := metal2(t)
	c := p.c1
	ns := "resetcut2"
	c.namespace(ns)
	c.apply(vmEcho(ns, "vm", 8080))
	c.waitRunning(ns, 20*time.Minute, "vm")
	s := c.silo(ns, "vm")
	host := map[string]*mt{metalHost: p.c1, metalHost2: p.c2}[s.Status.Host]
	n := cloudhypervisor.NamesFor(kri.ID{Namespace: ns, Name: "vm", UID: s.UID})
	since := strings.TrimSpace(host.mustSh("date -u '+%Y-%m-%d %H:%M:%S'"))
	// On the host: wait for the convert, then kill kevasod at once (one command, no round trip).
	host.mustSh("systemd-run --unit=kvt-resetcut sh -c 'for i in $(seq 1 3000); do if pgrep -f \"[q]emu-img convert.*" + n.LV + "\" >/dev/null; then cp /var/lib/kevaso-silos/" + n.Short + "/silo.json /run/kvt-resetcut.json; systemctl kill -s KILL kevasod; echo killed > /run/kvt-resetcut; exit; fi; sleep 0.05; done' >/dev/null")
	t.Cleanup(func() {
		_, _ = host.sh("systemctl stop kvt-resetcut 2>/dev/null; rm -f /run/kvt-resetcut /run/kvt-resetcut.json; true")
	})
	c.must("", "reset", "silo", "vm", "-n", ns)
	c.eventually("kevasod killed during the convert", 5*time.Minute, func() (bool, string) {
		out, _ := host.sh("cat /run/kvt-resetcut 2>/dev/null")
		return strings.TrimSpace(out) == "killed", out
	})
	c.expect("the mark was saved before", host.mustSh("grep -c '\"remake\"' /run/kvt-resetcut.json || true"), "1")
	c.eventually("the API back", 3*time.Minute, func() (bool, string) { out, code := c.kvo("", "get", "hosts"); return code == 0, out })
	c.waitRunning(ns, 15*time.Minute, "vm")
	got, code := c.in(ns, "vm", "echo booted")
	if code != 0 || got != "booted" {
		t.Errorf("the guest doesn't answer after the remake: %d %q", code, got)
	}
	if out := strings.TrimSpace(host.mustSh("grep -c '\"remake\"' /var/lib/kevaso-silos/" + n.Short + "/silo.json || true")); out != "0" {
		t.Errorf("the mark is still there: %s", out)
	}
	j := host.mustSh("journalctl --no-pager --since '" + since + "' | grep -E 'qemu-img|Started .*" + n.Unit + "|remake' | tail -8")
	t.Logf("journal:\n%s", j)
}

// TestMetal2VolumeDroppedFromSpec is host-code's second batch: a microVM with a local volume, the
// volume taken out of its spec: it restarts, the guest no longer mounts it, its status lists it
// no more, and its host says it let it go. What becomes of the volume's logical volume is recorded.
//
// Listens on nothing outside.
func TestMetal2VolumeDroppedFromSpec(t *testing.T) {
	p := metal2(t)
	c := p.c1
	ns := "dropvol2"
	c.namespace(ns)
	c.apply(vmEcho(ns, "vm", 8080) + "  volumes: [{ name: data, size: 1Gi, mountPath: /data }]\n")
	c.waitRunning(ns, 20*time.Minute, "vm")
	if out, code := c.in(ns, "vm", "echo kept > /data/marker && sync"); code != 0 {
		t.Fatalf("write: %d %s", code, out)
	}
	s := c.silo(ns, "vm")
	host := map[string]*mt{metalHost: p.c1, metalHost2: p.c2}[s.Status.Host]
	n := cloudhypervisor.NamesFor(kri.ID{Namespace: ns, Name: "vm", UID: s.UID})
	started := strings.TrimSpace(host.mustSh("systemctl show -p ActiveEnterTimestamp --value " + n.Unit))
	lvs := func() string {
		return strings.TrimSpace(host.mustSh("lvs --noheadings -o lv_name kevaso | tr -d ' ' | grep '^" + n.LV + "' | sort | tr '\\n' ' '"))
	}
	before := lvs()
	since := strings.TrimSpace(host.mustSh("date -u '+%Y-%m-%d %H:%M:%S'"))
	c.apply(vmEcho(ns, "vm", 8080)) // the same silo, its volume gone from the spec
	c.eventually("it restarts", 5*time.Minute, func() (bool, string) {
		now := strings.TrimSpace(host.mustSh("systemctl show -p ActiveEnterTimestamp --value " + n.Unit))
		return now != started && now != "", now
	})
	c.waitRunning(ns, 10*time.Minute, "vm")
	got, _ := c.in(ns, "vm", "mountpoint -q /data && echo mounted || echo not-mounted")
	c.expect("the guest no longer mounts it", got, "not-mounted")
	for _, v := range c.silo(ns, "vm").Status.Volumes {
		if v.Name == "data" {
			t.Errorf("its status still lists the volume: %+v", v)
		}
	}
	t.Logf("its LVs before: %q; after: %q", before, lvs())
	t.Logf("its host's journal:\n%s", host.mustSh("journalctl -u kevasod --no-pager --since '"+since+"' | grep -E '"+ns+"/vm' | grep -iE 'volume|let go|releas|restart' | tail -6"))
}
