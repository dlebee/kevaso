//go:build metal

package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	"kevaso.com/core/internal/agent"
)

// TestMetal2HeldServesLastState is network-3's N3-4 (K-097, K-122): machine 1's store copied
// aside (kevasod stopped a moment), a grant G deleted, machine 2's last state saved without it;
// then the older store put back (the same history, older): machine 2 holds. While held, machine
// 2 serves what it last trusted: egress to G's name stays refused, the silo's DNS answers as
// before, and kevasod restarted held loads the same rules within seconds. The newer store back,
// the hold ends.
//
// Listens on nothing outside. It stops machine 1's control plane four times, a few seconds each.
func TestMetal2HeldServesLastState(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "held2"
	c.namespace(ns, "grant/g")
	c.apply(`apiVersion: kevaso/v1
kind: Grant
metadata: { name: g, namespace: ` + ns + ` }
spec:
  egress: [{ to: example.com }]
---
` + vmEcho(ns, "vm", 8080) + on(metalHost2) + "  grants: [g]\n")
	c.waitRunning(ns, 20*time.Minute, "vm")
	egress := func() string {
		out, _ := c.in(ns, "vm", "curl -sk -o /dev/null -w '%{http_code}' -m 10 --resolve example.com:443:203.0.113.9 https://example.com/ 2>/dev/null; true")
		return strings.TrimSpace(out)
	}
	dns := func() string {
		out, _ := c.in(ns, "vm", "getent hosts vm."+ns+".kevaso vm."+ns+" 2>&1 | sort; true")
		return strings.TrimSpace(out)
	}
	if got := egress(); got == "000" || got == "" {
		t.Fatalf("egress to example.com with G: %q, want an answer", got)
	}
	dnsBefore := dns()
	t.Logf("with G: egress answers; DNS %q", dnsBefore)

	const store = "/var/lib/kevaso/store.db"
	copyStore := func(to string) {
		p.c1.mustSh("systemctl stop kevasod && mkdir -p " + to + " && cp -a " + store + " " + store + "-wal " + store + "-shm " + to + "/ 2>/dev/null; systemctl start kevasod")
		c.eventually("the API back", 3*time.Minute, func() (bool, string) { o, code := c.kvo("", "get", "hosts"); return code == 0, o })
	}
	putStore := func(from string) {
		p.c1.mustSh("systemctl stop kevasod && rm -f " + store + "-wal " + store + "-shm && cp -a " + from + "/store.db* /var/lib/kevaso/ && systemctl start kevasod")
		c.eventually("the API back", 3*time.Minute, func() (bool, string) { o, code := c.kvo("", "get", "hosts"); return code == 0, o })
	}
	t.Cleanup(func() { _, _ = p.c1.sh("rm -rf /var/lib/kevaso-kvt-old /var/lib/kevaso-kvt-new") })
	copyStore("/var/lib/kevaso-kvt-old")
	saved := strings.TrimSpace(p.c2.mustSh("stat -c %Y /var/lib/kevaso/last-state.json"))
	c.must("", "delete", "grant", "g", "-n", ns)
	c.eventually("machine 2 saves its last state without G", 3*time.Minute, func() (bool, string) {
		now := strings.TrimSpace(p.c2.mustSh("stat -c %Y /var/lib/kevaso/last-state.json"))
		return now != saved && strings.TrimSpace(p.c2.mustSh("grep -c '\"name\": *\"g\"' /var/lib/kevaso/last-state.json || true")) == "0", now
	})
	c.eventually("egress to G's name refused without G", 2*time.Minute, func() (bool, string) { g := egress(); return g == "000", g })

	copyStore("/var/lib/kevaso-kvt-new")
	t.Cleanup(func() { // the newer store back whatever happens, so the cluster isn't left held
		if strings.TrimSpace(p.c1.mustSh("test -d /var/lib/kevaso-kvt-new && echo y || true")) == "y" {
			_, _ = p.c1.sh("systemctl stop kevasod && rm -f " + store + "-wal " + store + "-shm && cp -a /var/lib/kevaso-kvt-new/store.db* /var/lib/kevaso/ ; systemctl start kevasod")
		}
	})
	putStore("/var/lib/kevaso-kvt-old")
	c.eventually("machine 2 holds (the older store of its history)", 3*time.Minute, func() (bool, string) {
		b := meta.FindCondition(c.hostNamed(metalHost2).Status.Conditions, agent.ConditionControlPlaneBehind)
		j := p.c2.mustSh("journalctl -u kevasod --no-pager --since '-3min' | grep -c HOLD || true")
		return b != nil && b.Status == meta.ConditionTrue || strings.TrimSpace(j) != "0", fmt.Sprint(b) + " HOLD lines " + strings.TrimSpace(j)
	})
	t.Logf("held: %s", p.c2.mustSh("journalctl -u kevasod --no-pager --since '-3min' | grep HOLD | tail -2"))
	c.holds("held: egress to G's name stays refused", 30*time.Second, func() (bool, string) { g := egress(); return g == "000", g })
	c.expect("held: the silo's DNS answers as before", dns(), dnsBefore)
	rules := func() string { return strings.TrimSpace(p.c2.mustSh("nft -s list table inet kevaso | md5sum")) }
	before := rules()
	p.c2.mustSh("systemctl restart kevasod")
	restarted := time.Now()
	c.eventually("restarted held: the same rules", time.Minute, func() (bool, string) { r := rules(); return r == before, r })
	t.Logf("the rules back %s after the restart", time.Since(restarted).Round(time.Second))
	c.expect("restarted held: egress still refused", egress(), "000")

	putStore("/var/lib/kevaso-kvt-new")
	c.eventually("the hold ends with the newer store", 5*time.Minute, func() (bool, string) {
		b := meta.FindCondition(c.hostNamed(metalHost2).Status.Conditions, agent.ConditionControlPlaneBehind)
		return b == nil || b.Status != meta.ConditionTrue, fmt.Sprint(b)
	})
}
