//go:build metal

package e2e

import (
	"strings"
	"testing"
	"time"
)

// TestMetal2InjectCutOff is network-3's N3-3 (K-076, a35d179) on machine 2 (a worker): a microVM
// with an injected key; machine 2's traffic to machine 1's API dropped (nft, output to the
// port the tests dial, and to 6443, the port the control plane advertises) for 2m30s.
// The key is still injected all through (past the one-minute refetch), and the journal
// says "injecting what it gave" once. The hour's end isn't waited for.
//
// Listens on nothing outside.
func TestMetal2InjectCutOff(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "cutinject2"
	c.namespace(ns, "secret/api-key")
	key := randomValue(t, "sk-cut-")
	// kvoadm host add takes --egress-extra-ca but doesn't put it in the worker's unit (reported):
	// a drop-in gives machine 2's kevasod the stand-in's CA, as host add was asked to. Before any
	// silo is made there: a restart mid-create would cut its disk's lvcreate (reported apart).
	if !strings.Contains(p.c2.mustSh("systemctl cat kevasod"), "--egress-extra-ca") {
		exec := strings.TrimSpace(p.c2.mustSh("systemctl show -p ExecStart --value kevasod | sed -n 's/.*argv\\[\\]=\\([^;]*\\) ;.*/\\1/p'"))
		if exec == "" {
			t.Fatal("machine 2's kevasod command line: not found")
		}
		d := "/run/systemd/system/kevasod.service.d"
		t.Cleanup(func() {
			_, _ = p.c2.sh("rm -f " + d + "/kvt-ca.conf; systemctl daemon-reload; systemctl restart kevasod; true")
		})
		p.c2.mustSh("mkdir -p " + d + " && printf '[Service]\\nExecStart=\\nExecStart=%s --egress-extra-ca /etc/kevaso/test-internet-ca.pem\\n' '" + exec + "' > " + d + "/kvt-ca.conf && systemctl daemon-reload && systemctl restart kevasod")
		c.eventually("machine 2 back with the CA", 3*time.Minute, func() (bool, string) { return c.hostReady(metalHost2) })
	}
	c.must(key, "create", "secret", "api-key", "-n", ns, "--from-file", "token=-", "--allow", "inject", "--write-only")
	c.apply(`apiVersion: kevaso/v1
kind: Grant
metadata: { name: api, namespace: ` + ns + ` }
spec:
  egress: [{ to: "` + metalInetAddr + `/32", ports: ["443"] }]
  secrets:
    - { name: api-key, key: token, deliver: inject, to: { host: ` + metalInetName + ` } }
---
` + vmEcho(ns, "vm", 8080) + on(metalHost2) + "  grants: [api]\n")
	c.waitRunning(ns, 20*time.Minute, "vm")
	call := func() string {
		out, _ := c.in(ns, "vm", `ca=; [ -f /etc/ssl/certs/kevaso-ca-bundle.crt ] && ca="--cacert /etc/ssl/certs/kevaso-ca-bundle.crt"; `+
			"curl -sS --max-time 20 $ca --resolve "+metalInetName+":443:203.0.113.9 https://"+metalInetName+"/v1/models 2>&1")
		return out
	}
	want := `"auth": "` + metalHash("Bearer "+key) + `"`
	c.expect("injected before the cut", call(), want)
	// While cut, kvo exec can't reach the guest (machine 2's agent is cut off too): the guest asks
	// by itself every 10s and logs what came back.
	logger := `systemd-run -q --unit kvtcut sh -c 'ca=; [ -f /etc/ssl/certs/kevaso-ca-bundle.crt ] && ca="--cacert /etc/ssl/certs/kevaso-ca-bundle.crt"; while true; do echo "$(date +%s) $(curl -sS --max-time 8 $ca --resolve ` + metalInetName + `:443:203.0.113.9 https://` + metalInetName + `/v1/models 2>&1 | tr -d "\n")" >> /root/cut.log; sleep 10; done'`
	if out, code := c.in(ns, "vm", logger); code != 0 {
		t.Fatalf("the guest's logger: %d %s", code, out)
	}
	since := strings.TrimSpace(p.c2.mustSh("date -u '+%Y-%m-%d %H:%M:%S'"))
	from := strings.TrimSpace(p.c2.mustSh("date +%s"))
	t.Cleanup(func() { _, _ = p.c2.sh("nft delete table inet kvtest 2>/dev/null; true") })
	drop := "nft add table inet kvtest; nft add chain inet kvtest o '{ type filter hook output priority 0; }'"
	for _, port := range metalAPIDropPorts(p.apiPort) {
		drop += "; nft add rule inet kvtest o ip daddr " + p.c1.cfg.ExternalIP + " tcp dport " + port + " drop"
	}
	p.c2.mustSh(drop)
	time.Sleep(150 * time.Second)
	to := strings.TrimSpace(p.c2.mustSh("date +%s"))
	p.c2.mustSh("nft delete table inet kvtest")
	c.eventually("machine 2 back (kvo exec reaches its guest)", 3*time.Minute, func() (bool, string) {
		out, code := c.in(ns, "vm", "echo up")
		return code == 0 && strings.TrimSpace(out) == "up", out
	})
	log, _ := c.in(ns, "vm", "cat /root/cut.log; systemctl status kvtcut --no-pager 2>&1 | head -5")
	t.Logf("the guest's log (cut from %s to %s, machine 2's clock):\n%s", from, to, log)
	n, bad := 0, 0
	for _, l := range strings.Split(strings.TrimSpace(log), "\n") {
		f := strings.SplitN(l, " ", 2)
		if len(f) < 2 || f[0] < from || f[0] > to {
			continue
		}
		n++
		if !strings.Contains(f[1], want) {
			bad++
			t.Errorf("at %s, into the cut: not injected: %s", f[0], f[1])
		}
	}
	t.Logf("during the 2m30s cut: %d of the guest's calls, %d not injected", n, bad)
	if n < 10 {
		t.Errorf("only %d calls fell in the cut", n)
	}
	lines := strings.TrimSpace(p.c2.mustSh("journalctl -u kevasod --no-pager --since '" + since + "' | grep 'injecting what it gave' || true"))
	t.Logf("machine 2's journal:\n%s", lines)
	if c := strings.Count(lines, "injecting what it gave"); c != 1 {
		t.Errorf("%d 'injecting what it gave' lines, want 1", c)
	}
}
