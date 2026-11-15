//go:build metal

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/sdk/kri"
)

// Tests that run on a kept cluster (the long soak's: KEVASO_METAL_REUSE), each in a namespace of
// its own, cleaning up after itself, never touching the soak's namespace and never resetting or
// rebooting a machine.

// anyOf counts the containers of a silo on a machine, every one of them (main, init, pause).
func anyOf(c *mt, uid string) int {
	out, _ := c.sh("docker ps -q --filter label=kevaso.com/uid=" + uid)
	return len(strings.Fields(out))
}

// neverBoth asks both machines every half second, from themselves, whether something of the
// silo runs on each; it returns a stop func that says when both did, if ever, and how often it
// asked.
func (p *pair) neverBoth(count func(*mt) int) (stop func() (both string, checks int64)) {
	done := make(chan struct{})
	var bothAt atomic.Value
	var checks atomic.Int64
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			r1, r2 := make(chan int, 1), make(chan int, 1)
			go func() { r1 <- count(p.c1) }()
			go func() { r2 <- count(p.c2) }()
			if a, b := <-r1, <-r2; a > 0 && b > 0 && bothAt.Load() == nil {
				bothAt.Store(fmt.Sprintf("%s (machine 1: %d, machine 2: %d)", time.Now().Format(time.TimeOnly), a, b))
			}
			checks.Add(1)
			time.Sleep(500 * time.Millisecond)
		}
	}()
	return func() (string, int64) {
		close(done)
		s, _ := bothAt.Load().(string)
		return s, checks.Load()
	}
}

// TestMetal2InitStepUnderACut is K-088 on the machines: an opted-in docker silo (onControlPlaneLoss:
// Stop, after 30s, onHostLoss: Recreate) on machine 2 whose init step runs (sleep 300) when the
// cut comes. Within after plus the fence's reaction nothing of it runs on machine 2 (its init
// container included); the control plane restarts it on machine 1 after that; and at no moment
// does anything of it run on both. Contact back: on one host, no InitFailed.
//
// Listens on nothing outside.
func TestMetal2InitStepUnderACut(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "initcut2"
	c.namespace(ns)
	t.Cleanup(p.uncut)
	c.apply(boxEcho(ns, "slow", 8080) + "  availability: { onControlPlaneLoss: Stop, after: 30s, onHostLoss: Recreate }\n" +
		"  init: { when: everyBoot, steps: [{ name: slow, run: \"sleep 300\" }] }\n")
	c.eventually("placed", 5*time.Minute, func() (bool, string) { s := c.silo(ns, "slow"); return s.Status.Host != "", s.Status.Host })
	if c.silo(ns, "slow").Status.Host != metalHost2 {
		c.must("", "move", "silo", "slow", "-n", ns, "--to", metalHost2, "--recreate")
	}
	uid := c.silo(ns, "slow").UID
	short := cloudhypervisor.NamesFor(kri.ID{Namespace: ns, Name: "slow", UID: uid}).Short
	c.eventually("its init step runs on machine 2", 10*time.Minute, func() (bool, string) {
		out, _ := p.c2.sh("docker ps --format '{{.Names}}' | grep -c '^kv-" + short + "-init$' || true")
		return strings.TrimSpace(out) == "1", out
	})
	stop := p.neverBoth(func(h *mt) int { return anyOf(h, uid) })
	p.cut()
	cutAt := time.Now()
	t.Log("machine 2 cut off while the init step runs")
	c.eventually("nothing of it runs on machine 2 (init and pause included)", 30*time.Second+6*time.Second+30*time.Second, func() (bool, string) {
		n := anyOf(p.c2, uid)
		return n == 0, strconv.Itoa(n) + " containers"
	})
	if d := time.Since(cutAt); d > 30*time.Second+6*time.Second+10*time.Second { // a heartbeat's slack
		t.Errorf("machine 2 stopped it %s into the cut, past after + 6s", d.Round(time.Second))
	}
	c.eventually("the control plane starts it on machine 1", 5*time.Minute, func() (bool, string) {
		s := c.silo(ns, "slow")
		return s.Status.Host == metalHost, s.Status.Host + " " + s.Status.Phase
	})
	p.uncut()
	c.eventually(metalHost2+" is Ready again", 5*time.Minute, func() (bool, string) { return c.hostReady(metalHost2) })
	time.Sleep(time.Minute)
	if at, n := stop(); at != "" {
		t.Errorf("something of the silo ran on both machines at %s (%d checks)", at, n)
	} else {
		t.Logf("never on both machines: %d checks", n)
	}
	if anyOf(p.c2, uid) != 0 {
		t.Error("machine 2 runs something of it after the cut, though it's machine 1's")
	}
	desc := c.must("", "describe", "silo", "slow", "-n", ns)
	if strings.Contains(desc, "InitFailed") {
		t.Errorf("InitFailed after the cut:\n%s", desc)
	}
}

// TestMetal2RootDiskKeptOverAConfirmedMove is the review's root-disk claim A (K-004): a microVM
// (no opt-in) moved off machine 2 while that one is cut off (kvo move --confirm-fenced), machine 2
// back in contact: its root disk stays there (the unit stopped), the Host lists the silo as kept
// ("no handoff from this host"), and a move back starts that same disk (a file written before is
// there).
//
// Listens on nothing outside.
func TestMetal2RootDiskKeptOverAConfirmedMove(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "rootkept2"
	c.namespace(ns)
	t.Cleanup(p.uncut)
	c.apply(vmEcho(ns, "vm", 8080) + "  availability: { onHostLoss: Recreate }\n") // --recreate needs it
	c.waitRunning(ns, 20*time.Minute, "vm")
	if c.silo(ns, "vm").Status.Host != metalHost2 {
		t.Skip("placed on machine 1, and a microVM's local root can't move to machine 2: run again")
	}
	if out, code := c.in(ns, "vm", "echo before > /root/marker && sync"); code != 0 {
		t.Fatalf("write: %d %s", code, out)
	}
	s := c.silo(ns, "vm")
	n := cloudhypervisor.NamesFor(kri.ID{Namespace: ns, Name: "vm", UID: s.UID})
	p.cut()
	c.eventually(metalHost2+" lost", 3*time.Minute, func() (bool, string) {
		h := c.hostNamed(metalHost2)
		return !hostIs(*h, "Ready"), fmt.Sprint(h.Status.Conditions)
	})
	// Confirming the fence is the operator's word: make it true first, on the host.
	p.c2.mustSh("systemctl stop " + n.Unit)
	c.must("", "move", "silo", "vm", "-n", ns, "--to", metalHost, "--confirm-fenced", "--recreate")
	// The cut lifted at once: kept short (the long soak's opted-in silo stops after 2m of one).
	p.uncut()
	c.eventually("it runs on machine 1", 15*time.Minute, func() (bool, string) {
		s := c.silo(ns, "vm")
		return s.Status.Host == metalHost && s.Status.Phase == "Running", s.Status.Host + " " + s.Status.Phase
	})
	c.eventually(metalHost2+" is Ready again", 5*time.Minute, func() (bool, string) { return c.hostReady(metalHost2) })
	time.Sleep(time.Minute)
	c.expect("machine 2 keeps its root disk", p.c2.mustSh("lvs --noheadings -o lv_name kevaso | tr -d ' '"), n.LV)
	if a := strings.TrimSpace(p.c2.mustSh("systemctl is-active " + n.Unit + " || true")); a == "active" {
		t.Error("machine 2 runs its old copy")
	}
	c.eventually("machine 2 lists it as kept, with no handoff", 3*time.Minute, func() (bool, string) {
		h := c.hostNamed(metalHost2)
		for _, cd := range h.Status.Conditions {
			if strings.Contains(cd.Message, ns+"/vm") && strings.Contains(cd.Message, "no handoff from this host") {
				return true, cd.Message
			}
		}
		return false, fmt.Sprint(h.Status.Conditions)
	})
	// A move back to machine 2 starts that same disk (Create never removes a root volume it
	// didn't make: the kept one is used).
	c.must("", "move", "silo", "vm", "-n", ns, "--to", metalHost2, "--recreate")
	c.eventually("it runs on machine 2 again", 15*time.Minute, func() (bool, string) {
		s := c.silo(ns, "vm")
		return s.Status.Host == metalHost2 && s.Status.Phase == "Running", s.Status.Host + " " + s.Status.Phase
	})
	got, _ := c.in(ns, "vm", "cat /root/marker 2>&1")
	c.expect("the same disk: the file written before is there", got, "before")
}

// TestMetal2ResetTakenBackDuringThePull is the review's reset gate (K-004): a container silo,
// kvo reset, then the reset taken back (spec.reset to what it was) while the image is pulled
// again: the silo's files are all there afterwards (nothing was wiped for a reset that didn't
// happen).
//
// Listens on nothing outside.
func TestMetal2ResetTakenBackDuringThePull(t *testing.T) {
	p := metal2(t)
	c := p.c1
	ns := "resetback2"
	c.namespace(ns)
	const image = "docker.io/library/rust:1.82" // large: its pull takes a while
	c.apply(fmt.Sprintf(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: big, namespace: %s }
spec:
  runtime: docker
  container: { image: %s, command: [sleep, infinity] }
  resources: { cpu: 1, memory: 256Mi }
`, ns, image))
	c.waitRunning(ns, 20*time.Minute, "big")
	if out, code := c.in(ns, "big", "echo kept > /root/marker && sync"); code != 0 {
		t.Fatalf("write: %d %s", code, out)
	}
	s := c.silo(ns, "big")
	host := map[string]*mt{metalHost: p.c1, metalHost2: p.c2}[s.Status.Host]
	host.mustSh("docker image rm -f " + image + " >/dev/null 2>&1 || true") // so the reset pulls it again
	old := s.Spec.Reset
	c.must("", "reset", "silo", "big", "-n", ns)
	c.eventually("the image is being pulled again", 2*time.Minute, func() (bool, string) {
		// Any engine command with the image (a pull, or a run that pulls), while the image isn't there.
		out, _ := host.sh("pgrep -fa 'docker .*" + image + "' | grep -v pgrep | head -1; docker image inspect " + image + " >/dev/null 2>&1 && echo present || echo absent")
		return strings.Contains(out, image) && strings.Contains(out, "absent"), out
	})
	for {
		var cur v1.Silo
		if err := json.Unmarshal([]byte(c.must("", "get", "silo", "big", "-n", ns, "-o", "json")), &cur); err != nil {
			t.Fatal(err)
		}
		cur.Spec.Reset = old
		b, _ := json.Marshal(cur)
		if _, code := c.kvo(string(b), "apply", "-f", "-"); code == 0 {
			break
		}
	}
	t.Log("the reset taken back during the pull")
	c.waitRunning(ns, 10*time.Minute, "big")
	time.Sleep(30 * time.Second)
	got, _ := c.in(ns, "big", "cat /root/marker 2>&1")
	c.expect("its files are all there", got, "kept")
}

// TestMetal2DrainDuringAMove is K-070 on the machines: a container moving (as a fresh copy: the
// only way a container moves since control-6) from machine 2 to machine 1, machine 2 cut off just
// after kvo move (so it still holds it), then kvoadm host drain metal-1. Drain either leaves the
// move (status.movingFrom stays metal-2) or re-places the silo (onHostLoss: Recreate), and at no
// moment does it run on both machines.
//
// Listens on nothing outside.
func TestMetal2DrainDuringAMove(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "drainmove2"
	c.namespace(ns)
	t.Cleanup(p.uncut)
	t.Cleanup(func() {
		var o bytes.Buffer
		_ = kvoadm.Run(c.ctx, []string{"host", "uncordon", metalHost, "--context", "metal2"}, strings.NewReader(""), &o, &o)
	})
	c.apply(boxEcho(ns, "web", 8080) + "  availability: { onHostLoss: Recreate }\n") // a container moves only as a fresh copy
	c.waitRunning(ns, 10*time.Minute, "web")
	if c.silo(ns, "web").Status.Host != metalHost2 {
		c.must("", "move", "silo", "web", "-n", ns, "--to", metalHost2, "--recreate")
		c.eventually("web on "+metalHost2, 5*time.Minute, func() (bool, string) {
			s := c.silo(ns, "web")
			return s.Status.Host == metalHost2 && s.Status.Phase == "Running" && s.Status.MovingFrom == "", s.Status.Host
		})
	}
	uid := c.silo(ns, "web").UID
	stop := p.neverBoth(func(h *mt) int { return anyOf(h, uid) })
	c.must("", "move", "silo", "web", "-n", ns, "--to", metalHost, "--recreate")
	p.cut() // machine 2 holds it: it can't hand it off now
	t.Log("moving web from machine 2 to machine 1, machine 2 cut off")
	var o bytes.Buffer
	code := kvoadm.Run(c.ctx, []string{"host", "drain", metalHost, "--context", "metal2"}, strings.NewReader(""), &o, &o)
	t.Logf("kvoadm host drain %s: exit %d\n%s", metalHost, code, o.String())
	left := strings.Contains(o.String(), "a move from "+metalHost2+" is under way")
	time.Sleep(30 * time.Second) // what the drain set going plays out, machine 2 still cut off
	s := c.silo(ns, "web")
	t.Logf("after the drain: host %q, movingFrom %q, phase %s; on machine 1 %d, on machine 2 %d", s.Status.Host, s.Status.MovingFrom, s.Status.Phase, anyOf(p.c1, uid), anyOf(p.c2, uid))
	switch {
	case left && s.Status.MovingFrom != metalHost2:
		t.Errorf("drain said it leaves the move, but movingFrom is %q", s.Status.MovingFrom)
	case !left && !strings.Contains(o.String(), ns+"/web: recreated elsewhere"):
		t.Errorf("drain neither left the move nor re-placed it")
	}
	if both, checks := stop(); both != "" {
		t.Errorf("it ran on both machines at %s (%d checks)", both, checks)
	} else {
		t.Logf("never on both machines (%d checks)", checks)
	}
}

// TestMetal2IngressRecordDeleted is ingress-3's IB-1 on a real nginx class (K-089, K-090): a
// class of the test's own (ib), its controller on machine 1, Ingresses a, b and new served, one
// held at its last good version (broken). A request loop on machine 1 asks every served host
// five times a second throughout. The applied record deleted from the controller and kevasod
// restarted: nginx's config is unchanged, no answer changed, the class says it's held and why.
// Then the broken Ingress fixed: the class applies, the record is back (0600), still all 200.
//
// Listens on nothing outside (the class's ports are internal).
func TestMetal2IngressRecordDeleted(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "ib2"
	c.namespace(ns, "ingress/a", "ingress/b", "ingress/new", "ingress/broken")
	t.Cleanup(func() {
		for _, a := range [][]string{{"delete", "ingressclass", "ib"}, {"delete", "silo", "ingress-ib", "-n", "kevaso-system"}} {
			_, _ = c.kvo("", a...)
		}
		_, _ = p.c1.sh("systemctl stop kvt-ib-loop 2>/dev/null; true")
	})
	ing := func(name, host, extra string) string {
		return `---
apiVersion: kevaso/v1
kind: Ingress
metadata: { name: ` + name + `, namespace: ` + ns + extra + ` }
spec:
  ingressClass: ib
  hosts: [` + host + `]
  tls: { none: true }
  rules: [{ path: /, service: { name: app, port: http } }]
`
	}
	c.apply(`apiVersion: kevaso/v1
kind: Namespace
metadata: { name: kevaso-system }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: ingress-ib, namespace: kevaso-system }
spec:
  runtime: docker
  container: { image: docker.io/library/nginx:1.27 }
` + on(metalHost) + `  ports: [{ name: http, port: 80 }]
  service:
    ports: [{ port: http }]
---
apiVersion: kevaso/v1
kind: IngressClass
metadata: { name: ib }
spec:
  controller: { driver: nginx, silo: ingress-ib, namespace: kevaso-system }
---
` + boxEcho(ns, "app", 8080) + `  ports: [{ name: http, port: 8080 }]
  service:
    ports: [{ port: http }]
` + ing("a", "a.ib.test", "") + ing("b", "b.ib.test", "") + ing("broken", "broken.ib.test", ""))
	c.waitRunning("kevaso-system", 10*time.Minute, "ingress-ib")
	c.waitRunning(ns, 10*time.Minute, "app")
	c.apply(ing("new", "new.ib.test", ""))
	ip := c.silo("kevaso-system", "ingress-ib").Status.SiloIP
	ctl := "docker ps -q --filter label=kevaso.com/name=ingress-ib | head -1"
	hosts := []string{"a.ib.test", "b.ib.test", "broken.ib.test", "new.ib.test"}
	c.eventually("every served host answers 200", 3*time.Minute, func() (bool, string) {
		for _, h := range hosts {
			if out, _ := p.c1.sh("curl -s -o /dev/null -w '%{http_code}' -H 'Host: " + h + "' http://" + ip + "/"); out != "200" {
				return false, h + " " + out
			}
		}
		return true, ""
	})
	// broken is served at a good version first, then edited broken: held at that last good one.
	c.apply(ing("broken", "broken.ib.test", ", annotations: { nginx/proxy-body-size: \"lots; return 500\" }"))
	c.eventually("the class holds broken at its last good version", 2*time.Minute, func() (bool, string) {
		out, _ := c.kvo("", "get", "ingressclass", "ib", "-o", "yaml")
		return strings.Contains(out, "ib2/broken"), out
	})
	// The loop: every answer that isn't 200, with its time.
	loop := `mkdir -p /var/lib/kvt-ib; : > /var/lib/kvt-ib/answers.log
systemd-run --unit=kvt-ib-loop sh -c 'while :; do for h in ` + strings.Join(hosts, " ") + `; do c=$(curl -s -m 2 -o /dev/null -w "%{http_code}" -H "Host: $h" http://` + ip + `/); [ "$c" = 200 ] || echo "$(date +%T.%N) $h $c" >> /var/lib/kvt-ib/answers.log; done; sleep 0.2; done' >/dev/null`
	p.c1.mustSh(loop)
	changed := func() string { return strings.TrimSpace(p.c1.mustSh("cat /var/lib/kvt-ib/answers.log")) }

	// IB-1: the record deleted with routes served, kevasod restarted.
	p.c1.mustSh("docker exec $(" + ctl + ") rm -f /etc/nginx/nginx.conf.kevaso /etc/nginx/nginx.conf.kevaso.next")
	before := p.c1.mustSh("docker exec $(" + ctl + ") nginx -T 2>/dev/null | md5sum")
	p.c1.mustSh("systemctl restart kevasod")
	c.eventually("the API back", 3*time.Minute, func() (bool, string) { out, code := c.kvo("", "get", "hosts"); return code == 0, out })
	time.Sleep(30 * time.Second)
	if after := p.c1.mustSh("docker exec $(" + ctl + ") nginx -T 2>/dev/null | md5sum"); after != before {
		t.Error("IB-1: nginx's config changed with the record gone")
	}
	if ch := changed(); ch != "" {
		t.Errorf("IB-1: answers changed:\n%s", ch)
	} else {
		t.Log("IB-1: no answer changed")
	}
	held, _ := c.kvo("", "get", "ingressclass", "ib", "-o", "json") // JSON: YAML writes the apostrophe twice
	if !strings.Contains(held, "can't tell") {
		t.Errorf("IB-1: the class doesn't say it can't tell what the proxy serves:\n%s", held)
	}
	// The broken Ingress fixed: the class applies, the record is back.
	c.apply(ing("broken", "broken.ib.test", ""))
	c.eventually("the record is back, 0600", 2*time.Minute, func() (bool, string) {
		out, _ := p.c1.sh("docker exec $(" + ctl + ") stat -c %a /etc/nginx/nginx.conf.kevaso")
		return strings.TrimSpace(out) == "600", out
	})
	time.Sleep(10 * time.Second)
	if ch := changed(); ch != "" {
		t.Errorf("answers changed by the end:\n%s", ch)
	}
}
