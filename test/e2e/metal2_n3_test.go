//go:build metal

package e2e

import (
	"strings"
	"testing"
	"time"
)

// TestMetal2EgressByNameRefusesPrivate is network-3's N3-1 and N3-2 (K-057, a5190c2) on machine 2:
// a microVM whose grant opens, by name, 127-0-0-1.sslip.io, 169-254-169-254.sslip.io, the
// machine's own address as a name, and the silo bridge's gate port by name. Each connection (sent
// to a public stand-in address, so it leaves the silo and the gate judges it by its SNI) is
// refused, and the journal says "which a name never leads to" for each. Then the grant also names
// 169.254.169.254/32 for 443: that name is let through, and a SYN to 169.254.169.254 leaves the
// machine (tcpdump).
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
		found := false
		for _, l := range strings.Split(j, "\n") {
			if strings.Contains(l, n) && strings.Contains(l, "which a name never leads to") {
				found = true
			}
		}
		if !found {
			t.Errorf("no 'gate: BLOCKED … %s … which a name never leads to' line", n)
		}
	}

	// The grant names 169.254.169.254/32 for 443: that name is let through.
	c.apply(grant(`    - { to: 169.254.169.254/32, ports: ["443"] }`))
	time.Sleep(15 * time.Second) // the grant reaches the gate
	p.c2.mustSh("rm -f /run/kvt-n3.pcap; systemd-run -q --unit kvt-n3dump timeout 25 tcpdump -ni any -c 5 -w /run/kvt-n3.pcap host 169.254.169.254 and tcp port 443")
	t.Cleanup(func() { _, _ = p.c2.sh("systemctl stop kvt-n3dump 2>/dev/null; rm -f /run/kvt-n3.pcap; true") })
	time.Sleep(2 * time.Second)
	t.Logf("N3-1 with the /32 named:\n%s", try("169-254-169-254.sslip.io", "443"))
	c.eventually("tcpdump ended", 40*time.Second, func() (bool, string) {
		out := strings.TrimSpace(p.c2.mustSh("systemctl is-active kvt-n3dump || true"))
		return out != "active", out
	})
	syns := strings.TrimSpace(p.c2.mustSh("tcpdump -nr /run/kvt-n3.pcap 2>/dev/null | grep -c 'Flags \\[S\\]' || true"))
	t.Logf("SYNs to 169.254.169.254:443 seen on machine 2: %s", syns)
	if syns == "0" {
		t.Errorf("with 169.254.169.254/32 named, no SYN to it left machine 2")
	}
}
