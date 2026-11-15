//go:build metal

package e2e

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/builtin/kri/container"
	"kevaso.com/core/sdk/kri"
)

// TestMetalBridgeBinding is the network lane's K-002 checks (network.md K2-1 to K2-6) on a real
// kernel and nft: bridge prerouting is default-deny, and each port passes only its own silo's
// address (and MAC where the runtime fixed one), bound from the runtime's state while the silo is
// still in its init steps; a silo can't speak as another, nothing goes out over IPv6, the host
// still reaches its silos, and a restart keeps the chain closed.
//
// Listens on nothing outside.
func TestMetalBridgeBinding(t *testing.T) {
	c := metal(t)
	ns := "bind"
	c.namespace(ns)
	initWait := "  init: { steps: [{ name: wait, run: \"sleep 600\" }] }\n"
	c.apply(vmEcho(ns, "a", 8080) + initWait + "---\n" + boxEcho(ns, "b", 8080) + initWait)

	type bound struct{ ip, mac, tap string }
	var a, b bound
	c.eventually("both silos' state is on the host", 15*time.Minute, func() (bool, string) {
		read := func(path string) (bound, bool) {
			out, err := c.sh("cat " + path + " 2>/dev/null")
			var s struct {
				ID  kri.ID `json:"id"`
				IP  string `json:"ip"`
				MAC string `json:"mac"`
			}
			if err != nil || json.Unmarshal([]byte(out), &s) != nil || s.IP == "" {
				return bound{}, false
			}
			return bound{ip: s.IP, mac: s.MAC, tap: cloudhypervisor.NamesFor(s.ID).Tap}, true
		}
		sa, sb := c.silo(ns, "a"), c.silo(ns, "b")
		var ok1, ok2 bool
		a, ok1 = read(cloudhypervisor.NamesFor(kri.ID{Namespace: ns, Name: "a", UID: sa.UID}).Dir + "/silo.json")
		b, ok2 = read(container.NamesFor(kri.ID{Namespace: ns, Name: "b", UID: sb.UID}).Dir + "/state.json")
		return ok1 && ok2, fmt.Sprint(a, b)
	})
	t.Logf("a: %+v, b: %+v", a, b)

	// K2-1: nft takes the text, and the bound shapes are there.
	c.expect("K2-1: nft -c takes the baseline file", c.mustSh("nft -c -f /etc/kevaso-silos.nft; echo rc=$?"), "rc=0")
	var chain string
	c.eventually("K2-2: both ports bound while the silos are still in init", 30*time.Second, func() (bool, string) {
		chain = c.mustSh("nft list chain bridge kevaso prerouting 2>&1")
		return strings.Contains(chain, "policy drop") && strings.Contains(chain, "ip saddr "+a.ip+" accept") && strings.Contains(chain, "ip saddr "+b.ip+" accept"), chain
	})
	if a.mac != "" {
		c.expect("K2-1: the microVM's port also checks its MAC", chain, "ether saddr "+a.mac+" ip saddr "+a.ip+" accept")
		arp := false // nft lists the two arp terms in its own order
		for _, l := range strings.Split(chain, "\n") {
			arp = arp || strings.Contains(l, a.tap) && strings.Contains(l, "arp saddr ip "+a.ip) && strings.Contains(l, "arp saddr ether "+a.mac)
		}
		if !arp {
			t.Errorf("K2-1: no ARP rule binding the microVM's address and MAC:\n%s", chain)
		}
	}
	if ip := c.silo(ns, "a").Status.SiloIP; ip != "" {
		t.Errorf("K2-2: a has a silo IP in the API already (%s): not the init case", ip)
	}
	if j := c.mustSh("journalctl -u kevasod --no-pager --since '-20min' | grep -i -E 'nft.*(error|syntax)|could not process' | tail -3 || true"); strings.TrimSpace(j) != "" {
		t.Errorf("K2-1: the real nft refused a ruleset: %s", j)
	}

	// K2-3: b speaking as a is dropped.
	pause := container.NamesFor(kri.ID{Namespace: ns, Name: "b", UID: c.silo(ns, "b").UID}).Pause
	var pid string
	c.eventually("b's pause container runs", 2*time.Minute, func() (bool, string) {
		out, _ := c.sh("docker inspect -f '{{.State.Running}} {{.State.Pid}}' " + pause + " 2>&1")
		f := strings.Fields(out)
		if len(f) == 2 && f[0] == "true" && f[1] != "0" {
			pid = f[1]
			return true, ""
		}
		return false, out
	})
	ns3 := "nsenter -t " + pid + " -n "
	c.mustSh(ns3 + "ip addr add " + a.ip + "/32 dev eth0")
	t.Cleanup(func() { _, _ = c.sh(ns3 + "ip addr del " + a.ip + "/32 dev eth0") })
	spoof, _ := c.sh(ns3 + "curl -s -m 3 --interface " + a.ip + " -o /dev/null -w '%{http_code}' http://169.254.42.1/ 2>&1; echo rc=$?")
	if !strings.Contains(spoof, "rc=28") && !strings.Contains(spoof, "rc=7") {
		t.Errorf("K2-3: b reached the endpoint as a: %q", spoof)
	} else {
		t.Logf("K2-3: b as a gets nothing: %s", strings.TrimSpace(spoof))
	}
	_, _ = c.sh(ns3 + "arping -c 2 -w 3 -s " + a.ip + " -I eth0 " + strings.Join(strings.Split(a.ip, ".")[:3], ".") + ".1 2>&1")
	if neigh := c.mustSh("ip neigh show dev kvbr0 | grep -F '" + a.ip + " ' || true"); b.mac != "" && strings.Contains(neigh, b.mac) {
		t.Errorf("K2-3: the host maps a's address to b's MAC: %s", neigh)
	}

	// K2-4: nothing over IPv6 from a port.
	_, _ = c.sh(ns3 + "ping -6 -c 3 -w 3 -I eth0 ff02::1 2>&1")
	if n6 := strings.TrimSpace(c.mustSh("ip -6 neigh show dev kvbr0")); n6 != "" {
		t.Errorf("K2-4: IPv6 neighbours on the bridge: %s", n6)
	}

	// K2-5: the host still reaches its silos.
	c.eventually("K2-5: the host pings the microVM", 3*time.Minute, func() (bool, string) {
		out, err := c.sh("ping -c1 -W2 " + a.ip)
		return err == nil, out
	})

	// K2-6: a restart keeps the chain closed.
	c.mustSh("systemctl restart kevasod")
	for i := 0; i < 20; i++ {
		ch, _ := c.sh("nft list chain bridge kevaso prerouting 2>&1")
		if strings.Contains(ch, "type filter hook prerouting") && !strings.Contains(ch, "policy drop") {
			t.Fatalf("K2-6: the chain opened during a restart:\n%s", ch)
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Log("K2-6: policy drop throughout the restart")
	c.eventually("the API is back", 3*time.Minute, func() (bool, string) { out, code := c.kvo("", "get", "hosts"); return code == 0, out })
}
