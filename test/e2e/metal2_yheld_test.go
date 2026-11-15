//go:build metal

package e2e

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/cli/kvoadm"
)

// TestMetal2HeldServesLastState is network-3's N3-4 (K-097, K-122): machine 1's store copied
// aside (kevasod stopped a moment), a grant G deleted, machine 2's last state saved without it;
// then the older store put back (the same history, older): machine 2 holds. A held worker has no
// agent connection (no kvo exec), so the guest logs, every 5s, its egress to G's name and its own
// name's DNS answer. While held: egress to G's name stays refused, the DNS answers as before, and
// kevasod restarted held loads the same rules within seconds. kvoadm host trust-control-plane
// ends the hold (putting a store copy back can't: the control plane wrote past any copy).
//
// Listens on nothing outside. It stops machine 1's control plane three times, a few seconds each.
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
` + vmEcho(ns, "vm", 8080) + on(metalHost2) + "  grants: [g]\n  ports: [{ name: http, port: 8080 }]\n  service:\n    ports: [{ port: http }]\n")
	c.waitRunning(ns, 20*time.Minute, "vm")
	logger := `systemd-run -q --unit kvtlog sh -c 'while true; do echo "$(date +%s) $(curl -sk -o /dev/null -w %{http_code} -m 4 --resolve example.com:443:203.0.113.9 https://example.com/ 2>/dev/null) $(getent hosts vm.` + ns + `.kevaso | cut -d" " -f1)" >> /root/egress.log; sleep 5; done'`
	if out, code := c.in(ns, "vm", logger); code != 0 {
		t.Fatalf("the guest's logger: %d %s", code, out)
	}
	readLog := func() [][]string {
		out, _ := c.in(ns, "vm", "cat /root/egress.log")
		var rows [][]string
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			if f := strings.Fields(l); len(f) >= 2 {
				rows = append(rows, f)
			}
		}
		return rows
	}
	now := func() int64 {
		var n int64
		fmt.Sscan(strings.TrimSpace(p.c2.mustSh("date +%s")), &n)
		return n
	}
	c.eventually("with G: the guest's egress to example.com answers", 2*time.Minute, func() (bool, string) {
		r := readLog()
		return len(r) > 0 && r[len(r)-1][1] != "000", fmt.Sprint(r[max(0, len(r)-2):])
	})
	rows := readLog()
	dnsBefore := ""
	if last := rows[len(rows)-1]; len(last) > 2 {
		dnsBefore = last[2]
	}
	t.Logf("with G: egress answers; vm.%s.kevaso is %q", ns, dnsBefore)
	if dnsBefore == "" {
		t.Errorf("the silo's own name doesn't resolve in it")
	}

	const store = "/var/lib/kevaso/store.db"
	t.Cleanup(func() { _, _ = p.c1.sh("rm -rf /var/lib/kevaso-kvt-old") })
	p.c1.mustSh("systemctl stop kevasod && mkdir -p /var/lib/kevaso-kvt-old && cp -a " + store + " " + store + "-wal " + store + "-shm /var/lib/kevaso-kvt-old/ 2>/dev/null; systemctl start kevasod")
	c.eventually("the API back", 3*time.Minute, func() (bool, string) { o, code := c.kvo("", "get", "hosts"); return code == 0, o })
	saved := strings.TrimSpace(p.c2.mustSh("stat -c %Y /var/lib/kevaso/last-state.json"))
	c.must("", "delete", "grant", "g", "-n", ns)
	c.eventually("machine 2 saves its last state without G", 3*time.Minute, func() (bool, string) {
		now := strings.TrimSpace(p.c2.mustSh("stat -c %Y /var/lib/kevaso/last-state.json"))
		return now != saved && strings.TrimSpace(p.c2.mustSh("grep -c '\"name\": *\"g\"' /var/lib/kevaso/last-state.json || true")) == "0", now
	})
	c.eventually("without G: the guest's egress refused", 2*time.Minute, func() (bool, string) {
		r := readLog()
		return r[len(r)-1][1] == "000", fmt.Sprint(r[len(r)-1])
	})

	trust := func() {
		cfg := p.m2.cfg
		var o bytes.Buffer
		code := kvoadm.Run(c.ctx, []string{"host", "trust-control-plane", cfg.SSHTarget(), "--ssh-port", strconv.Itoa(cfg.Port), "--ssh-key", cfg.KeyFile, "--host-key", cfg.HostKey, "--yes"}, strings.NewReader(""), &o, &o)
		t.Logf("kvoadm host trust-control-plane %s: exit %d\n%s", metalHost2, code, metalRedact(o.String()))
	}
	held := false
	t.Cleanup(func() { // never leave the cluster held
		if held {
			trust()
		}
	})
	p.c1.mustSh("systemctl stop kevasod && rm -f " + store + "-wal " + store + "-shm && cp -a /var/lib/kevaso-kvt-old/store.db* /var/lib/kevaso/ && systemctl start kevasod")
	held = true
	c.eventually("the API back", 3*time.Minute, func() (bool, string) { o, code := c.kvo("", "get", "hosts"); return code == 0, o })
	c.eventually("machine 2 holds (the older store of its history)", 3*time.Minute, func() (bool, string) {
		b := meta.FindCondition(c.hostNamed(metalHost2).Status.Conditions, agent.ConditionControlPlaneBehind)
		return b != nil && b.Status == meta.ConditionTrue, fmt.Sprint(b)
	})
	heldFrom := now()
	t.Logf("held: %s", p.c2.mustSh("journalctl -u kevasod --no-pager --since '-3min' | grep HOLD | tail -1 | cut -c1-300"))
	time.Sleep(30 * time.Second)
	rules := func() string { return strings.TrimSpace(p.c2.mustSh("nft -s list table inet kevaso | md5sum")) }
	before := rules()
	p.c2.mustSh("systemctl restart kevasod")
	restarted := time.Now()
	c.eventually("restarted held: the same rules", time.Minute, func() (bool, string) { r := rules(); return r == before, r })
	t.Logf("the rules back %s after the restart", time.Since(restarted).Round(time.Second))
	time.Sleep(30 * time.Second)
	heldTo := now()

	trust()
	c.eventually("trust-control-plane ends the hold", 5*time.Minute, func() (bool, string) {
		b := meta.FindCondition(c.hostNamed(metalHost2).Status.Conditions, agent.ConditionControlPlaneBehind)
		return b == nil || b.Status != meta.ConditionTrue, fmt.Sprint(b)
	})
	held = false
	n := 0
	for _, r := range readLog() {
		var ts int64
		fmt.Sscan(r[0], &ts)
		if ts < heldFrom || ts > heldTo {
			continue
		}
		n++
		if r[1] != "000" {
			t.Errorf("held, at %s: egress to G's name answered %s (G was deleted before the hold)", r[0], r[1])
		}
		if dns := map[bool]string{true: r[2], false: ""}[len(r) > 2]; dns != dnsBefore {
			t.Errorf("held, at %s: vm.%s.kevaso is %q, was %q", r[0], ns, dns, dnsBefore)
		}
	}
	t.Logf("held for %ds: %d of the guest's tries, each refused, its name as before", heldTo-heldFrom, n)
	if n < 10 {
		t.Errorf("only %d of the guest's tries fell in the hold", n)
	}
}
