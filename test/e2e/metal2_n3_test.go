//go:build metal

package e2e

import (
	"strings"
	"testing"
	"time"
)

// TestMetal2EgressByNameRefusesPrivate is network-3's N3-1 and N3-2 (K-057, a5190c2; K-124) on
// machine 2: a microVM whose grant opens, by name, 127-0-0-1.sslip.io, 169-254-169-254.sslip.io,
// the machine's own address as a name, and the silo bridge's gate port by name. Each connection
// (sent to a public stand-in address, so it leaves the silo and the gate judges it by its SNI) is
// refused. Loopback, link-local and the bridge's own range say "which a grant never opens" (K-124);
// the machine's own public address says "which a name never leads to" (K-057). A grant that names
// 169.254.169.254 is refused at admission.
//
// Listens on nothing outside.
func TestMetal2EgressByNameRefusesPrivate(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "egressname2"
	c.namespace(ns)
	hostName := strings.ReplaceAll(p.c2.cfg.ExternalIP, ".", "-") + ".sslip.io"
	bridge := strings.TrimSpace(p.c2.mustSh("ip -4 -o addr show kvbr0 | awk '{print $4}' | cut -d/ -f1 | grep -v '^169.254' | head -1"))
	gateName := strings.ReplaceAll(bridge, ".", "-") + ".sslip.io"
	names := []string{"127-0-0-1.sslip.io", "169-254-169-254.sslip.io", hostName}
	grant := func(extra string) string {
		return `apiVersion: kevaso/v1
kind: Grant
metadata: { name: out, namespace: ` + ns + ` }
spec:
  egress:
    - { to: 127-0-0-1.sslip.io }
    - { to: 169-254-169-254.sslip.io }
    - { to: ` + hostName + ` }
    - { to: ` + gateName + `, ports: ["15001"] }
` + extra
	}
	c.apply(grant("") + "---\n" + vmEcho(ns, "vm", 8080) + on(metalHost2) + "  grants: [out]\n")
	c.waitRunning(ns, 20*time.Minute, "vm")
	since := strings.TrimSpace(p.c2.mustSh("date -u '+%Y-%m-%d %H:%M:%S'"))
	try := func(name, port string) string {
		out, _ := c.in(ns, "vm", "curl -sv -k -m 8 --resolve "+name+":"+port+":203.0.113.9 https://"+name+":"+port+"/ 2>&1 | grep -E '^\\* |^< HTTP|curl:' | tail -4")
		return out
	}
	for _, n := range names {
		t.Logf("N3-1 %s:\n%s", n, try(n, "443"))
	}
	t.Logf("N3-2 getent %s: %s", gateName, func() string { o, _ := c.in(ns, "vm", "getent hosts "+gateName+" || echo none"); return o }())
	t.Logf("N3-2 %s:15001:\n%s", gateName, try(gateName, "15001"))
	plain, _ := c.in(ns, "vm", "curl -sv -k -m 5 https://"+gateName+":15001/ 2>&1 | tail -3")
	t.Logf("N3-2 plain curl https://%s:15001/:\n%s", gateName, plain)
	time.Sleep(2 * time.Second)
	j := p.c2.mustSh("journalctl -u kevasod --no-pager --since '" + since + "' | grep 'gate: BLOCKED' | grep " + ns + " | tail -12; true")
	t.Logf("machine 2's journal:\n%s", j)
	for _, n := range append(names, gateName) {
		phrase := "which a grant never opens" // loopback, link-local, the bridge (K-124)
		if n == hostName {
			phrase = "which a name never leads to" // the machine's own public address (K-057)
		}
		found := false
		for _, l := range strings.Split(j, "\n") {
			if strings.Contains(l, n) && strings.Contains(l, phrase) {
				found = true
			}
		}
		if !found {
			t.Errorf("no 'gate: BLOCKED … %s … %s' line", n, phrase)
		}
	}

	// Naming the link-local metadata address is refused; the name stays closed.
	out, exitCode := c.kvo(grant(`    - { to: 169.254.169.254/32, ports: ["443"] }`), "apply", "-f", "-")
	if exitCode == 0 || !strings.Contains(out, "169.254.0.0/16") {
		t.Fatalf("a grant naming link-local was admitted: exit %d\n%s", exitCode, out)
	}
}
