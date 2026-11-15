//go:build metal

package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/builtin/kri/container"
	"kevaso.com/core/sdk/kri"
)

// host-code-6's bare-metal checks that need no reset, beside the long soak (a kept cluster, own
// namespaces). Every copy the agent keeps on purpose (an unreadable state) is removed by hand at
// the end, the way the runtime's Delete removes it.

// boxOn2 is a docker silo on machine 2 and its names there, once it runs.
func boxOn2(c *mt, ns, name string, pin bool) container.Names {
	c.t.Helper()
	if pin {
		c.apply(boxEcho(ns, name, 8080) + on(metalHost2))
	} else { // movable: placed anywhere, then moved to machine 2
		c.apply(boxEcho(ns, name, 8080) + "  availability: { onHostLoss: Recreate }\n") // a container moves only as a fresh copy
		c.waitRunning(ns, 15*time.Minute, name)
		if c.silo(ns, name).Status.Host != metalHost2 {
			c.must("", "move", "silo", name, "-n", ns, "--to", metalHost2, "--recreate")
		}
		c.eventually("on machine 2", 10*time.Minute, func() (bool, string) {
			s := c.silo(ns, name)
			return s.Status.Host == metalHost2 && s.Status.Phase == "Running", s.Status.Host + " " + s.Status.Phase
		})
	}
	c.waitRunning(ns, 15*time.Minute, name)
	return container.NamesFor(kri.ID{Namespace: ns, Name: name, UID: c.silo(ns, name).UID})
}

// dropBox removes a kept container copy by hand: its containers and its state folder.
func dropBox(h *mt, n container.Names) {
	_, _ = h.sh("for c in $(docker ps -aq --filter name=^" + n.Main + "); do docker rm -f $c >/dev/null; done; rm -rf " + n.Dir + "; true")
}

// TestMetal2UnreadableStateMove is K-105 (003c04a) on a container: its state.json made unreadable
// while it runs on machine 2, then kvo move to machine 1. Machine 2 stops it by name before it
// releases the handoff (the journal says its runtime doesn't list it, then released here; the
// container is gone from docker ps by then), and the silo runs on machine 1.
//
// Listens on nothing outside.
func TestMetal2UnreadableStateMove(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "unreadmove2"
	c.namespace(ns)
	n := boxOn2(c, ns, "box", false)
	t.Cleanup(func() { dropBox(p.c2, n) })
	since := strings.TrimSpace(p.c2.mustSh("date -u '+%Y-%m-%d %H:%M:%S'"))
	p.c2.mustSh("echo '{\"id\": ' > " + n.Dir + "/state.json")
	c.must("", "move", "silo", "box", "-n", ns, "--to", metalHost, "--recreate")
	runsAtRelease := false
	c.eventually("released here (machine 2's journal)", 5*time.Minute, func() (bool, string) {
		runs := strings.TrimSpace(p.c2.mustSh("docker ps --format '{{.Names}}' | grep -c '^"+n.Main+"$' || true")) != "0"
		rel := strings.TrimSpace(p.c2.mustSh("journalctl -u kevasod --no-pager --since '"+since+"' | grep -c '"+ns+"/box moved to .*released here' || true")) != "0"
		runsAtRelease = rel && runs // its container read just before the journal
		return rel, fmt.Sprintf("released %v, its container runs %v", rel, runs)
	})
	if runsAtRelease {
		t.Errorf("released while its container still runs on machine 2")
	}
	j := p.c2.mustSh("journalctl -u kevasod --no-pager --since '" + since + "' | grep '" + ns + "/box' | grep -v 'retry in 1' | tail -8")
	t.Logf("machine 2's journal:\n%s", j)
	if !strings.Contains(j, "its runtime doesn't list it") {
		t.Errorf("no 'its runtime doesn't list it … stopping it' before the release")
	}
	if i, k := strings.Index(j, "its runtime doesn't list it"), strings.Index(j, "released here"); i < 0 || k < 0 || i > k {
		t.Errorf("not stopped before released (lines %d, %d)", i, k)
	}
	c.waitRunning(ns, 10*time.Minute, "box")
	if h := c.silo(ns, "box").Status.Host; h != metalHost {
		t.Errorf("runs on %s, want %s", h, metalHost)
	}
	t.Logf("machine 2 after: state dir %s", p.c2.mustSh("ls "+n.Dir+" 2>&1 | tr '\\n' ' '"))
}

// TestMetal2UnreadableStateDelete is K-105's delete: a container's state.json unreadable, kvo
// delete. Its container stops, its state folder stays, and KeptSilos on machine 2 names it and the
// unreadable file.
//
// Listens on nothing outside.
func TestMetal2UnreadableStateDelete(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "unreaddel2"
	c.namespace(ns)
	n := boxOn2(c, ns, "box", true)
	t.Cleanup(func() { dropBox(p.c2, n) })
	p.c2.mustSh("echo '{\"id\": ' > " + n.Dir + "/state.json")
	c.must("", "delete", "silo", "box", "-n", ns)
	c.eventually("its container stops", 2*time.Minute, func() (bool, string) {
		out := p.c2.mustSh("docker ps --format '{{.Names}}' | grep -c '^" + n.Main + "$' || true")
		return strings.TrimSpace(out) == "0", out
	})
	c.expect("its state folder stays", p.c2.mustSh("test -d "+n.Dir+" && echo there || echo gone"), "there")
	c.eventually("KeptSilos names the unreadable file", 2*time.Minute, func() (bool, string) {
		k := meta.FindCondition(c.hostNamed(metalHost2).Status.Conditions, "KeptSilos")
		return k != nil && k.Status == meta.ConditionTrue && strings.Contains(k.Message, n.Dir+"/state.json"), fmt.Sprint(k)
	})
	t.Logf("KeptSilos: %s", meta.FindCondition(c.hostNamed(metalHost2).Status.Conditions, "KeptSilos").Message)
	dropBox(p.c2, n)
	c.eventually("KeptSilos goes once it is removed by hand", 3*time.Minute, func() (bool, string) {
		k := meta.FindCondition(c.hostNamed(metalHost2).Status.Conditions, "KeptSilos")
		return k == nil || k.Status != meta.ConditionTrue || !strings.Contains(k.Message, n.Short), fmt.Sprint(k)
	})
}

// TestMetal2UnreadableVMStateHoldsAddresses is K-105 on a microVM (003c04a, d699888): its
// silo.json made unreadable while it runs on machine 2. A new silo placed there isn't given an
// address (CreateFailed naming the file); kvo delete kills its VMM; KeptSilos names the file.
// Removed by hand, the new silo starts.
//
// Listens on nothing outside.
func TestMetal2UnreadableVMStateHoldsAddresses(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "unreadvm2"
	c.namespace(ns)
	c.apply(vmEcho(ns, "vm", 8080) + on(metalHost2))
	c.waitRunning(ns, 20*time.Minute, "vm")
	n := cloudhypervisor.NamesFor(kri.ID{Namespace: ns, Name: "vm", UID: c.silo(ns, "vm").UID})
	drop := func() {
		_, _ = p.c2.sh("systemctl stop " + n.Unit + " 2>/dev/null; rm -f /etc/systemd/system/" + n.Unit + "; systemctl daemon-reload; systemctl reset-failed " + n.Unit + " 2>/dev/null; " +
			"ip link del " + n.Tap + " 2>/dev/null; for lv in $(lvs --noheadings -o lv_name kevaso | grep " + n.LV + "); do lvremove -q -y kevaso/$lv; done; rm -rf " + n.Dir + "; true")
	}
	t.Cleanup(drop)
	file := n.Dir + "/silo.json"
	p.c2.mustSh("cp " + file + " /run/kvt-unreadvm.json && echo '{\"id\": ' > " + file)
	t.Cleanup(func() { _, _ = p.c2.sh("rm -f /run/kvt-unreadvm.json") })
	c.apply(boxEcho(ns, "new", 8080) + on(metalHost2))
	c.eventually("the new silo gets no address: CreateFailed naming the file", 3*time.Minute, func() (bool, string) {
		r := meta.FindCondition(c.silo(ns, "new").Status.Conditions, "Ready")
		return r != nil && strings.Contains(r.Message, file), fmt.Sprint(r)
	})
	t.Logf("the new silo's Ready: %s", meta.FindCondition(c.silo(ns, "new").Status.Conditions, "Ready").Message)
	c.must("", "delete", "silo", "vm", "-n", ns)
	c.eventually("its VMM is killed", 2*time.Minute, func() (bool, string) {
		out := strings.TrimSpace(p.c2.mustSh("systemctl is-active " + n.Unit + " || true"))
		return out != "active" && out != "deactivating", out
	})
	c.eventually("KeptSilos names the file", 2*time.Minute, func() (bool, string) {
		k := meta.FindCondition(c.hostNamed(metalHost2).Status.Conditions, "KeptSilos")
		return k != nil && strings.Contains(k.Message, file), fmt.Sprint(k)
	})
	c.expect("its root disk is kept", p.c2.mustSh("lvs --noheadings -o lv_name kevaso | tr -d ' ' | grep -c '^"+n.LV+"$' || true"), "1")
	drop()
	c.eventually("the new silo starts once the file is gone (its create retried)", 10*time.Minute, func() (bool, string) {
		s := c.silo(ns, "new")
		return s.Status.Phase == "Running", s.Status.Phase
	})
}

// TestMetal2StartBackoffNoClaim is K-115 (3881c27, 25a29c7). A silo whose init step exits 3: after
// InitFailed, no new start claim. A docker silo whose command doesn't exist (its main process
// exits 127 at once): over 90s its container is started a few times at most (the agent's own
// backoff, 5s doubling), not in a loop, and its start claim changes only at those tries.
//
// Listens on nothing outside.
func TestMetal2StartBackoffNoClaim(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "startback2"
	c.namespace(ns)
	c.apply(boxEcho(ns, "initbad", 8080) + on(metalHost2) + "  init: { steps: [{ name: fail, run: \"exit 3\" }] }\n")
	c.eventually("InitFailed", 5*time.Minute, func() (bool, string) {
		f := meta.FindCondition(c.silo(ns, "initbad").Status.Conditions, "InitFailed")
		return f != nil && f.Status == meta.ConditionTrue, fmt.Sprint(f)
	})
	held := claimTime(c.silo(ns, "initbad"))
	c.holds("no new start claim after InitFailed", 60*time.Second, func() (bool, string) {
		now := claimTime(c.silo(ns, "initbad"))
		return now == held || now == "", now
	})

	since := strings.TrimSpace(p.c2.mustSh("date -u '+%Y-%m-%d %H:%M:%S'"))
	c.apply(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: bad, namespace: ` + ns + ` }
spec:
  runtime: docker
  container: { image: docker.io/library/python:3.12-slim, command: ["/kvt-no-such-binary"] }
  resources: { cpu: 1, memory: 256Mi }
` + on(metalHost2))
	n := container.NamesFor(kri.ID{Namespace: ns, Name: "bad", UID: c.silo(ns, "bad").UID})
	claims := map[string]bool{}
	for end := time.Now().Add(90 * time.Second); time.Now().Before(end); time.Sleep(2 * time.Second) {
		if at := claimTime(c.silo(ns, "bad")); at != "" {
			claims[at] = true
		}
	}
	starts := strings.TrimSpace(p.c2.mustSh("id=$(docker inspect -f '{{.Id}}' " + n.Main + " 2>/dev/null); [ -n \"$id\" ] && journalctl --no-pager --since '" + since + "' | grep -c \"Started docker-$id\" || echo 0"))
	r := meta.FindCondition(c.silo(ns, "bad").Status.Conditions, "Ready")
	j := p.c2.mustSh("journalctl -u kevasod --no-pager --since '" + since + "' | grep '" + ns + "/bad' | grep -v 'retry in 1' | tail -6; true")
	t.Logf("in 90s: its container started %s times; %d start claims; Ready %v; the agent's log:\n%s", starts, len(claims), r, j)
	var k int
	fmt.Sscan(starts, &k)
	if k > 6 { // 5s, 10s, 20s, 40s: a handful of tries in 90s
		t.Errorf("its container started %d times in 90s: no backoff", k)
	}
	if len(claims) > 6 {
		t.Errorf("%d start claims in 90s: claimed between tries", len(claims))
	}
}
