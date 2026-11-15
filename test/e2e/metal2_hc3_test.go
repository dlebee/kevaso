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

// TestMetal2BackoffHoldsNoClaim is item F: a microVM whose VMM is killed right after each start,
// twice: while it waits out its restart backoff (Ready says it starts again in …), its start
// claim isn't renewed.
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
	mainPID := func() string { return strings.TrimSpace(host.mustSh("systemctl show -p MainPID --value " + n.Unit)) }
	// Never kill 0 (that would be this shell's own group).
	kill := func(pid string) { host.mustSh("[ '" + pid + "' -gt 0 ] 2>/dev/null && kill -KILL " + pid + "; true") }
	first := mainPID()
	kill(first)
	c.eventually("started again once (another VMM)", 5*time.Minute, func() (bool, string) {
		pid := mainPID()
		return pid != "0" && pid != first, pid
	})
	kill(mainPID())
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
}
