//go:build metal

package e2e

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/worker"
	"kevaso.com/core/sdk/kri"
)

// TestMetal2Worker is the owner's setup in miniature: machine 1 the system node only (until a
// later test makes it a worker too), machine 2 a worker that joined over the external IPs, the
// mesh between them; a microVM and a container on the worker answer this Mac on its external
// IP (and not on the system node's), kvo exec reaches them through the agent's tunnel, and their
// secrets (the local endpoint, a file) come from the system node on the other machine.
//
// Listens on machine 2's external IP while it runs: 18200, 18201.
func TestMetal2Worker(t *testing.T) {
	p := metal2(t)
	c := p.c1
	ns := "worker2"
	c.namespace(ns, "grant/app", "secret/pw")
	pw := randomValue(t, "pw-")
	c.must(pw, "create", "secret", "pw", "-n", ns, "--from-file", "-")
	c.apply("apiVersion: kevaso/v1\nkind: Grant\nmetadata: { name: app, namespace: " + ns + " }\nspec:\n  secrets:\n    - { name: pw }\n    - { name: pw, deliver: file, path: /run/secrets/pw }\n")
	for _, name := range []string{metalHost, metalHost2} {
		var h = c.hostNamed(name)
		t.Logf("%s: control plane %v, worker %v, external %s, mesh %s", name, h.Spec.Components.ControlPlane != nil, h.Spec.Components.Worker != nil,
			h.Spec.ExternalIP, h.Status.Network.MeshIP)
		if h.Status.Network.MeshIP == "" {
			t.Errorf("%s has no mesh IP", name)
		}
	}
	if h := c.hostNamed(metalHost); !p.m1Worker && h.Spec.Components.Worker != nil {
		t.Errorf("%s is a worker: want the system node only", metalHost)
	}
	place := ""
	if p.m1Worker {
		place = on(metalHost2)
	}
	c.apply(vmEcho(ns, "vm", 18200) + place + `  ports: [{ name: web, port: 18200 }]
  service:
    ports: [{ port: web, hostPort: [external] }]
  grants: [app]
---
` + boxEcho(ns, "box", 18201) + place + `  ports: [{ name: web, port: 18201 }]
  service:
    ports: [{ port: web, hostPort: [external] }]
  grants: [app]
`)
	c.waitRunning(ns, 20*time.Minute, "vm", "box")
	for _, s := range []struct {
		silo string
		port int
	}{{"vm", 18200}, {"box", 18201}} {
		if h := c.silo(ns, s.silo).Status.Host; h != metalHost2 {
			t.Errorf("%s runs on %s, want %s", s.silo, h, metalHost2)
		}
		c.eventually(fmt.Sprintf("%s answers on %s's external IP", s.silo, metalHost2), 2*time.Minute, func() (bool, string) {
			ok, got := openOn(p.m2, s.port)
			return ok && strings.Contains(got, fmt.Sprintf("%s %d", s.silo, s.port)), got
		})
		if ok, got := openOn(p.m1, s.port); ok {
			t.Errorf("%s answers on the system node's IP too: %s", s.silo, got)
		}
		c.expect(s.silo+": kvo exec through the tunnel", func() string { o, _ := c.in(ns, s.silo, "echo through-the-tunnel"); return o }(), "through-the-tunnel")
		// Secrets on the worker: its agent asks the system node on the other machine.
		got, _ := c.in(ns, s.silo, `python3 -c "import urllib.request as u; print(u.urlopen(u.Request('http://169.254.42.1/v1/secrets/pw', headers={'Kevaso-Local': '1'}), timeout=10).read().decode())"`)
		c.expect(s.silo+": the local endpoint, answered across machines", got, pw)
		c.expect(s.silo+": a file the worker wrote", func() string { o, _ := c.in(ns, s.silo, "cat /run/secrets/pw"); return o }(), pw)
	}
}

// TestMetal2Mesh is the mesh between two hosts at different sites: a microVM on machine 1 reaches
// a container on machine 2 by its service name (the silo IP over WireGuard) on a port whose
// allowFrom names it; a silo allowFrom doesn't name can't connect; a port on [external] answers
// on its own host's IP only.
//
// Listens on machine 2's external IP while it runs: 18210.
func TestMetal2Mesh(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "mesh2"
	c.namespace(ns)
	c.apply(boxEcho(ns, "api", 8080, 18210) + on(metalHost2) + `  ports: [{ name: http, port: 8080 }, { name: pub, port: 18210 }]
  service:
    ports: [{ port: http, allowFrom: [caller] }, { port: pub, hostPort: [external] }]
---
` + vmEcho(ns, "caller", 8080) + on(metalHost) + "---\n" + boxEcho(ns, "stranger", 8080) + on(metalHost))
	c.waitRunning(ns, 20*time.Minute, "api", "caller", "stranger")
	apiIP := c.silo(ns, "api").Status.SiloIP
	got, _ := c.in(ns, "caller", "getent ahostsv4 api | awk 'NR==1 {print $1}'")
	if strings.TrimSpace(got) != apiIP {
		t.Errorf("from machine 1, api = %q, want its silo IP %s", got, apiIP)
	}
	c.eventually("a microVM on machine 1 reaches a container on machine 2 by name", 2*time.Minute, func() (bool, string) {
		out, _ := c.in(ns, "caller", "curl -sS --max-time 5 http://api:8080/")
		return strings.Contains(out, "api 8080"), out
	})
	py := `python3 -c "import urllib.request as u; print(u.urlopen('http://api:8080/', timeout=5).read().decode())" 2>&1`
	c.holds("a silo allowFrom doesn't name can't connect", 10*time.Second, func() (bool, string) {
		out, _ := c.in(ns, "stranger", py)
		return !strings.Contains(out, "api 8080"), out
	})
	c.eventually("[external] answers on its host's IP", time.Minute, func() (bool, string) { return openOn(p.m2, 18210) })
	if ok, got := openOn(p.m1, 18210); ok {
		t.Errorf("[external] also answers on the other host's IP: %s", got)
	}
}

// TestMetal2Moves is moves between the two workers (design §0.3): a container silo moves to the
// other host (a handoff: never two copies; its root made afresh from its image), and leaves
// nothing on the source; a
// microVM with a local volume is refused, saying why; onHostLoss: Move with a local volume is
// refused at admission.
//
// Listens on nothing outside.
func TestMetal2Moves(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "moves2"
	c.namespace(ns)
	c.apply(boxEcho(ns, "web", 8080) + "  availability: { onHostLoss: Recreate }\n---\n" + vmEcho(ns, "db", 8080) + on(metalHost2) + "  volumes: [{ name: data, size: 1Gi, mountPath: /data }]\n")
	c.waitRunning(ns, 20*time.Minute, "web", "db")
	from := c.silo(ns, "web").Status.Host
	to := map[string]string{metalHost: metalHost2, metalHost2: metalHost}[from]
	src := map[string]*mt{metalHost: p.c1, metalHost2: p.c2}[from]
	marker := randomValue(t, "move-")
	if out, code := c.in(ns, "web", "echo "+marker+" > /root/marker && sync"); code != 0 {
		t.Fatalf("write: %d %s", code, out)
	}
	uid := c.silo(ns, "web").UID
	c.must("", "move", "silo", "web", "-n", ns, "--to", to, "--recreate")
	c.eventually("web runs on "+to, 10*time.Minute, func() (bool, string) {
		s := c.silo(ns, "web")
		return s.Status.Host == to && s.Status.Phase == "Running" && s.Status.MovingFrom == "", fmt.Sprint(s.Status.Host, s.Status.Phase, s.Status.MovingFrom)
	})
	// A container's own root is made afresh from its image on the new host: data travels with a
	// move only on a storage class that moves (none on these machines without a plugin).
	if got, _ := c.in(ns, "web", "cat /root/marker 2>&1"); got == marker {
		t.Logf("its root came along (unexpected but harmless): %s", got)
	}
	c.eventually("nothing of it is left on "+from, 3*time.Minute, func() (bool, string) {
		out, _ := src.sh("docker ps -aq --filter label=kevaso.com/uid=" + uid + "; docker volume ls -q --filter label=kevaso.com/uid=" + uid)
		return strings.TrimSpace(out) == "", out
	})
	out, code := c.kvo("", "move", "silo", "db", "-n", ns, "--to", metalHost)
	if code == 0 || !strings.Contains(out, "not movable") {
		t.Errorf("a microVM with a local volume moved, or wasn't told why not: %q", out)
	} else {
		t.Logf("a microVM with a local volume: %s", strings.TrimSpace(out))
	}
	out, code = c.kvo(boxEcho(ns, "mover", 8080)+"  availability: { onHostLoss: Move }\n  volumes: [{ name: data, size: 1Gi, mountPath: /data }]\n", "apply", "-f", "-")
	if code == 0 || !strings.Contains(out, "Move needs every disk and volume on a movable storage class") {
		t.Errorf("onHostLoss: Move with a local volume: %q", out)
	}
}

// cut drops all traffic between machine 2 and machine 1 on machine 2 (an nftables table of the
// test's; the reset removes any it leaves). SSH from this Mac is another address: untouched.
func (p *pair) cut() {
	p.t.Helper()
	ip := p.m1.cfg.ExternalIP
	p.c2.mustSh(`nft -f - <<'NFT'
table inet kvt-cut {
  chain in { type filter hook input priority -10; ip saddr ` + ip + ` drop; }
  chain out { type filter hook output priority -10; ip daddr ` + ip + ` drop; }
}
NFT`)
}

func (p *pair) uncut() { _, _ = p.c2.sh("nft delete table inet kvt-cut 2>/dev/null; true") }

// running says whether a silo has a running container on a machine (by its UID).
func running(c *mt, uid string) bool {
	out, _ := c.sh("docker ps -q --filter label=kevaso.com/uid=" + uid + " --filter label=kevaso.com/name")
	return strings.TrimSpace(out) != ""
}

// TestMetal2Fence is a worker cut off from its control plane (§0.7; a firewall rule on machine 2,
// never port 22): it changes nothing, except that the silos that asked for it (onControlPlaneLoss:
// Stop) stop past their after. Only such a silo with onHostLoss: Recreate is started elsewhere by
// the control plane, after its after plus the margin, counted on the control plane's own clock;
// the Stop silo that waits stays assigned to machine 2, and nothing else moves by itself (a
// Recreate silo that didn't opt in included). kvo move --confirm-fenced moves a silo off the lost
// host. With the cut lifted, machine 2 starts the waiting Stop silo again, removes its copies of
// what moved, and every other silo is the same copy, never restarted.
//
// Listens on nothing outside.
func TestMetal2Fence(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "fence2"
	c.namespace(ns)
	t.Cleanup(p.uncut)
	c.apply(boxEcho(ns, "stay", 8080) + on(metalHost2) + "---\n" +
		boxEcho(ns, "recreate", 8080) + on(metalHost2) + "  availability: { onHostLoss: Recreate }\n---\n" +
		boxEcho(ns, "stops", 8080) + on(metalHost2) + "  availability: { onControlPlaneLoss: Stop, after: 30s }\n---\n" +
		boxEcho(ns, "restarts", 8080) + "  availability: { onControlPlaneLoss: Stop, after: 30s, onHostLoss: Recreate }\n---\n" +
		boxEcho(ns, "rescue", 8080) + "  availability: { onHostLoss: Recreate }\n") // a container moves only as a fresh copy; Recreate alone never restarts it elsewhere by itself
	c.waitRunning(ns, 10*time.Minute, "stay", "recreate", "stops", "restarts", "rescue")
	for _, n := range []string{"restarts", "rescue"} {
		if s := c.silo(ns, n); s.Status.Host != metalHost2 {
			c.must("", "move", "silo", n, "-n", ns, "--to", metalHost2, "--recreate")
		}
	}
	names := []string{"stay", "recreate", "stops", "restarts", "rescue"}
	c.eventually("all five on "+metalHost2, 5*time.Minute, func() (bool, string) {
		for _, n := range names {
			s := c.silo(ns, n)
			if s.Status.Host != metalHost2 || s.Status.Phase != "Running" {
				return false, n + " " + s.Status.Host + " " + s.Status.Phase
			}
		}
		return true, ""
	})
	uids := map[string]string{}
	for _, n := range names {
		uids[n] = c.silo(ns, n).UID
	}
	startedAt := func(n string) string {
		return strings.TrimSpace(p.c2.mustSh("docker ps -q --filter label=kevaso.com/uid=" + uids[n] + " | xargs -r docker inspect -f '{{.State.StartedAt}}'"))
	}
	before := map[string]string{}
	for _, n := range []string{"stay", "recreate"} {
		before[n] = startedAt(n)
	}
	rec := p.c2.mustSh("cat " + fence.Dir + "/" + fence.RecordFile)
	if !strings.Contains(rec, `"stopAfter":`) {
		t.Errorf("machine 2 runs a Stop silo and its fence record doesn't stop it: %s", rec)
	}

	p.cut()
	cutAt := time.Now()
	t.Log("machine 2 cut off from the system node")
	c.eventually("both Stop silos stop on machine 2", fence.WorstStopped(30*time.Second)+30*time.Second, func() (bool, string) {
		return !running(p.c2, uids["stops"]) && !running(p.c2, uids["restarts"]), "still running"
	})
	// The agent counts from the last heartbeat it sent: up to one period before the cut.
	if d := time.Since(cutAt); d < 30*time.Second-worker.DefaultHeartbeat {
		t.Errorf("the Stop silos stopped %s into the cut, before their after (30s, less a heartbeat)", d.Round(time.Second))
	}
	confirmMove(t, c, ns, "restarts", metalHost)
	c.eventually("--confirm-fenced: the Stop + Recreate silo runs on machine 1", 5*time.Minute, func() (bool, string) {
		s := c.silo(ns, "restarts")
		return s.Status.Host == metalHost && s.Status.Phase == "Running", s.Status.Host + " " + s.Status.Phase
	})
	// Well past the host lease: nothing else stops, and nothing else starts elsewhere.
	for end := time.Now().Add(90 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Second) {
		for _, n := range []string{"stay", "recreate", "rescue"} {
			if !running(p.c2, uids[n]) {
				t.Fatalf("the cut stopped %s on machine 2 (it didn't ask to stop)", n)
			}
		}
		for _, n := range []string{"recreate", "stops"} {
			if s := c.silo(ns, n); s.Status.Host != metalHost2 {
				t.Fatalf("the control plane moved %s to %q by itself (it didn't opt in, or waits)", n, s.Status.Host)
			}
		}
	}
	t.Log("well into the cut: the rest keeps running on machine 2, and nothing else started elsewhere")
	if out, code := c.kvo("", "move", "silo", "rescue", "-n", ns, "--to", metalHost, "--recreate"); code == 0 {
		t.Errorf("a move off a lost host without --confirm-fenced went ahead: %s", out)
	}
	// Machine 2 still runs rescue. Confirming the fence is the operator's word that it doesn't:
	// make it true first, as an operator would on a host they can reach.
	p.c2.mustSh("docker ps -q --filter label=kevaso.com/uid=" + uids["rescue"] + " | xargs -r docker stop -t 2 >/dev/null; true")
	c.must("", "move", "silo", "rescue", "-n", ns, "--to", metalHost, "--confirm-fenced", "--recreate")
	c.eventually("--confirm-fenced: rescue runs on machine 1", 5*time.Minute, func() (bool, string) {
		s := c.silo(ns, "rescue")
		return s.Status.Host == metalHost && s.Status.Phase == "Running", s.Status.Host + " " + s.Status.Phase
	})

	p.uncut()
	t.Log("the cut lifted")
	c.eventually(metalHost2+" is Ready again", 5*time.Minute, func() (bool, string) {
		return c.hostReady(metalHost2)
	})
	c.eventually("machine 2 starts the waiting Stop silo again and keeps no copy of what moved", 5*time.Minute, func() (bool, string) {
		return running(p.c2, uids["stops"]) && !running(p.c2, uids["rescue"]) && !running(p.c2, uids["restarts"]), "not yet"
	})
	for n, v := range before {
		if got := startedAt(n); got != v {
			t.Errorf("%s restarted: %q → %q", n, v, got)
		}
	}
	c.waitRunning(ns, 3*time.Minute, names...)
}

// TestMetal2HostLoss is a worker lost and back (§0.7): machine 2 rebooted while it holds silos.
// While it's down the control plane starts none of them elsewhere, onHostLoss: Recreate or not;
// back up, they all run on it again (a container, a Recreate one, and a microVM with its volume's
// data).
//
// Needs the control plane's half of §0.7 (a lost host's silos wait).
//
// Listens on nothing outside.
func TestMetal2HostLoss(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "loss2"
	c.namespace(ns)
	c.apply(boxEcho(ns, "stay", 8080) + on(metalHost2) + "---\n" +
		vmEcho(ns, "vm", 8080) + on(metalHost2) + "  volumes: [{ name: data, size: 1Gi, mountPath: /data }]\n---\n" +
		boxEcho(ns, "moves", 8080) + "  availability: { onHostLoss: Recreate }\n")
	c.waitRunning(ns, 20*time.Minute, "stay", "vm", "moves")
	if s := c.silo(ns, "moves"); s.Status.Host != metalHost2 {
		c.must("", "move", "silo", "moves", "-n", ns, "--to", metalHost2, "--recreate")
		c.eventually("moves on "+metalHost2, 5*time.Minute, func() (bool, string) {
			s := c.silo(ns, "moves")
			return s.Status.Host == metalHost2 && s.Status.Phase == "Running", s.Status.Host
		})
	}
	marker := randomValue(t, "loss-")
	if out, code := c.in(ns, "vm", "echo "+marker+" > /data/marker && sync"); code != 0 {
		t.Fatalf("write: %d %s", code, out)
	}
	movesUID := c.silo(ns, "moves").UID
	vm := c.silo(ns, "vm")
	unit := cloudhypervisor.NamesFor(kri.ID{Namespace: vm.Namespace, Name: vm.Name, UID: vm.UID}).Unit
	boot := strings.TrimSpace(p.c2.mustSh("cat /proc/sys/kernel/random/boot_id"))

	_, _ = p.c2.sh("nohup sh -c 'sleep 2; systemctl reboot' >/dev/null 2>&1 &")
	_ = p.m2.d.Close()
	for end := time.Now().Add(3 * time.Minute); time.Now().Before(end); time.Sleep(10 * time.Second) {
		for _, n := range []string{"stay", "vm", "moves"} {
			if h := c.silo(ns, n).Status.Host; h != metalHost2 {
				t.Fatalf("%s left its lost host for %q by itself", n, h)
			}
		}
	}
	t.Log("3 minutes with machine 2 down: every silo waits for it")
	c.eventually("machine 2 is back (a new boot, the pinned host key)", 15*time.Minute, func() (bool, string) {
		out, err := p.c2.sh("cat /proc/sys/kernel/random/boot_id")
		if err != nil {
			_ = p.m2.d.Close()
			return false, err.Error()
		}
		return strings.TrimSpace(out) != boot, out
	})
	c.eventually(metalHost2+" is Ready again", 10*time.Minute, func() (bool, string) {
		return c.hostReady(metalHost2)
	})
	c.waitRunning(ns, 15*time.Minute, "stay", "vm", "moves")
	for _, n := range []string{"stay", "vm", "moves"} {
		if h := c.silo(ns, n).Status.Host; h != metalHost2 {
			t.Errorf("%s runs on %s after the boot, want %s", n, h, metalHost2)
		}
	}
	c.expect("the microVM's unit is up on machine 2", p.c2.mustSh("systemctl is-active "+unit), "active")
	c.eventually("its volume kept the data", 5*time.Minute, func() (bool, string) {
		out, code := c.in(ns, "vm", "cat /data/marker")
		return code == 0 && out == marker, out
	})
	c.eventually("the Recreate silo runs on machine 2, one copy", 5*time.Minute, func() (bool, string) {
		// Its own container (the pause container, which holds its network, is not a copy).
		out, _ := p.c2.sh("docker ps -q --filter label=kevaso.com/uid=" + movesUID + " --filter label=kevaso.com/name")
		return len(strings.Fields(out)) == 1, out
	})
}

// TestMetal2Ingress is ingress on one host routing to a silo on the other: a stock nginx on
// machine 1's external IP, an Ingress to a service whose silo runs on machine 2 (over the mesh).
//
// Listens on machine 1's external IP while it runs: 80, 443.
func TestMetal2Ingress(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "web2"
	c.namespace(ns, "ingress/site")
	t.Cleanup(func() {
		for _, a := range [][]string{{"delete", "ingressclass", "edge"}, {"delete", "silo", "ingress-edge", "-n", "kevaso-system"}} {
			_, _ = c.kvo("", a...)
		}
	})
	name := "site." + strings.ReplaceAll(p.m1.cfg.ExternalIP, ".", "-") + ".sslip.io"
	c.apply(`apiVersion: kevaso/v1
kind: Namespace
metadata: { name: kevaso-system }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: ingress-edge, namespace: kevaso-system }
spec:
  runtime: docker
  container: { image: docker.io/library/nginx:1.27 }
` + on(metalHost) + `  ports: [{ name: http, port: 80 }, { name: https, port: 443 }]
  service:
    ports: [{ port: http, hostPort: [external] }, { port: https, hostPort: [external] }]
---
apiVersion: kevaso/v1
kind: IngressClass
metadata: { name: edge }
spec:
  controller: { driver: nginx, silo: ingress-edge, namespace: kevaso-system }
---
` + boxEcho(ns, "app", 8080) + on(metalHost2) + `  ports: [{ name: http, port: 8080 }]
  service:
    ports: [{ port: http }]
---
apiVersion: kevaso/v1
kind: Ingress
metadata: { name: site, namespace: ` + ns + ` }
spec:
  ingressClass: edge
  hosts: [` + name + `]
  tls: { none: true }
  rules: [{ path: /, service: { name: app, port: http } }]
`)
	c.waitRunning("kevaso-system", 10*time.Minute, "ingress-edge")
	c.waitRunning(ns, 10*time.Minute, "app")
	c.eventually("machine 1's nginx answers with the silo on machine 2", 3*time.Minute, func() (bool, string) {
		code, body, err := fromMac("http://"+p.m1.cfg.ExternalIP+"/", name, 5*time.Second)
		return err == nil && code == 200 && strings.Contains(body, "app 8080"), fmt.Sprint(code, " ", strings.TrimSpace(body), " ", err)
	})
}

// TestMetal2Drain is kvoadm host drain with the handoff (fixed after test-gaps proved two copies
// could run): a Recreate silo on machine 2 goes to machine 1, and at no moment do both hosts run
// it (both watched from the hosts themselves every half second); Wait silos stay.
//
// Listens on nothing outside.
func TestMetal2Drain(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "drain2"
	c.namespace(ns)
	t.Cleanup(func() { _, _ = c.kvo("", "get", "hosts"); p.kvoadm("host", "uncordon", metalHost2) })
	c.apply(boxEcho(ns, "job", 8080) + "  availability: { onHostLoss: Recreate }\n---\n" + boxEcho(ns, "stay", 8080) + on(metalHost2))
	c.waitRunning(ns, 10*time.Minute, "job", "stay")
	if c.silo(ns, "job").Status.Host != metalHost2 {
		c.must("", "move", "silo", "job", "-n", ns, "--to", metalHost2, "--recreate")
		c.eventually("job on "+metalHost2, 5*time.Minute, func() (bool, string) {
			s := c.silo(ns, "job")
			return s.Status.Host == metalHost2 && s.Status.Phase == "Running" && s.Status.MovingFrom == "", s.Status.Host
		})
	}
	uid := c.silo(ns, "job").UID
	done := make(chan struct{})
	both := make(chan string, 1)
	go func() { // never two copies: both hosts asked at once, over and over
		for {
			select {
			case <-done:
				return
			default:
			}
			r1, r2 := make(chan bool, 1), make(chan bool, 1)
			go func() { r1 <- running(p.c1, uid) }()
			go func() { r2 <- running(p.c2, uid) }()
			if <-r1 && <-r2 {
				select {
				case both <- time.Now().Format(time.TimeOnly):
				default:
				}
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()
	p.kvoadm("host", "drain", metalHost2)
	c.eventually("job runs on "+metalHost, 5*time.Minute, func() (bool, string) {
		s := c.silo(ns, "job")
		return s.Status.Host == metalHost && s.Status.Phase == "Running" && s.Status.MovingFrom == "", s.Status.Host + " " + s.Status.Phase + " " + s.Status.MovingFrom
	})
	close(done)
	select {
	case at := <-both:
		t.Errorf("both hosts ran job at %s: two copies", at)
	default:
		t.Log("never two copies of job")
	}
	if s := c.silo(ns, "stay"); s.Status.Host != metalHost2 || s.Status.Phase != "Running" {
		t.Errorf("a Wait silo left the drained host: %s %s", s.Status.Host, s.Status.Phase)
	}
	p.kvoadm("host", "uncordon", metalHost2)
}

// kvoadm runs kvoadm against the cluster's current context.
func (p *pair) kvoadm(args ...string) {
	p.t.Helper()
	var o strings.Builder
	if code := kvoadm.Run(p.c1.ctx, args, strings.NewReader(""), &o, &o); code != 0 {
		p.t.Errorf("kvoadm %v: exit %d\n%s", args, code, o.String())
	} else {
		p.t.Logf("kvoadm %v:\n%s", args, o.String())
	}
}

// TestMetal2KeptWhenMissing is K-004 on real hosts: a silo deleted while its worker's kevasod is
// down (so the worker never sees the delete, as after a restore from an older backup) is kept on
// the worker, still running, with its disk and volume; only a delete the worker sees removes
// data. The kept copy is left for the final reset.
//
// Listens on nothing outside.
func TestMetal2KeptWhenMissing(t *testing.T) {
	p := metal2(t)
	c := p.c1
	ns := "kept2"
	c.namespace(ns)
	place := ""
	if p.m1Worker {
		place = on(metalHost2)
	}
	c.apply(vmEcho(ns, "db", 8080) + place + "  volumes: [{ name: data, size: 1Gi, mountPath: /data }]\n")
	c.waitRunning(ns, 20*time.Minute, "db")
	s := c.silo(ns, "db")
	n := cloudhypervisor.NamesFor(kri.ID{Namespace: s.Namespace, Name: s.Name, UID: s.UID})
	lvs := func() string {
		return strings.TrimSpace(p.c2.mustSh("lvs --noheadings -o lv_name kevaso | tr -d ' ' | grep '^" + n.LV + "' | sort"))
	}
	before := lvs()
	if !strings.Contains(before, n.LV+"-") {
		t.Fatalf("no volume LV for db: %q", before)
	}
	p.c2.mustSh("systemctl stop kevasod")
	t.Cleanup(func() { _, _ = p.c2.sh("systemctl start kevasod") })
	c.must("", "delete", "silo", "db", "-n", ns)
	p.c2.mustSh("systemctl start kevasod")
	c.eventually(metalHost2+" is Ready again", 5*time.Minute, func() (bool, string) {
		return c.hostReady(metalHost2)
	})
	c.holds("the silo the worker never saw deleted keeps its disk and volume, and runs", 60*time.Second, func() (bool, string) {
		active, _ := p.c2.sh("systemctl is-active " + n.Unit)
		got := lvs()
		return got == before && strings.TrimSpace(active) == "active", got + " " + active
	})
	c.expect("kevasod says it keeps it", p.c2.mustSh("journalctl -u kevasod --no-pager --since '-10min' | grep -c 'keeping "+ns+"/db' || true"), "1")
}

// TestMetal2NeverTwice is K-015 on the machines: an opted-in silo (onControlPlaneLoss: Stop,
// onHostLoss: Recreate) on machine 2, machine 2 cut off, the silo stopped there and started on
// machine 1 by the control plane, the cut lifted the moment that restart is committed, and
// minutes after. Its init step (every boot) sleeps, so a start on machine 2 has a long gap
// between its read and its start, where the restart elsewhere lands. Both hosts are asked
// every half second, from themselves, throughout: at no moment do both run it.
//
// Listens on nothing outside.
func TestMetal2NeverTwice(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "twice2"
	c.namespace(ns)
	t.Cleanup(p.uncut)
	// Not pinned (on() would leave it nowhere else to go): moved to machine 2.
	c.apply(boxEcho(ns, "single", 8080) + "  availability: { onControlPlaneLoss: Stop, after: 30s, onHostLoss: Recreate }\n" +
		"  init: { when: everyBoot, steps: [{ name: slow, run: \"sleep 15\" }] }\n")
	c.waitRunning(ns, 10*time.Minute, "single")
	if c.silo(ns, "single").Status.Host != metalHost2 {
		c.must("", "move", "silo", "single", "-n", ns, "--to", metalHost2, "--recreate")
	}
	c.eventually("single on "+metalHost2, 5*time.Minute, func() (bool, string) {
		s := c.silo(ns, "single")
		return s.Status.Host == metalHost2 && s.Status.Phase == "Running" && s.Status.MovingFrom == "", s.Status.Host + " " + s.Status.Phase
	})
	uid := c.silo(ns, "single").UID
	c.eventually("its fence armed on "+metalHost2, 2*time.Minute, func() (bool, string) {
		s := c.silo(ns, "single")
		return fence.Armed(s), fmt.Sprint(s.Status.Conditions)
	})
	stop := make(chan struct{})
	both := make(chan string, 1)
	var checks atomic.Int64
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			r1, r2 := make(chan bool, 1), make(chan bool, 1)
			go func() { r1 <- running(p.c1, uid) }()
			go func() { r2 <- running(p.c2, uid) }()
			if a, b := <-r1, <-r2; a && b {
				select {
				case both <- time.Now().Format(time.TimeOnly):
				default:
				}
			}
			checks.Add(1)
			time.Sleep(500 * time.Millisecond)
		}
	}()
	p.cut()
	t.Log("machine 2 cut off from the system node")
	c.eventually("machine 2's fence stops it", 2*time.Minute, func() (bool, string) { return !running(p.c2, uid), "still running" })
	confirmMove(t, c, ns, "single", metalHost)
	c.eventually("the move committed", time.Minute, func() (bool, string) { s := c.silo(ns, "single"); return s.Status.Host == metalHost, s.Status.Host })
	p.uncut()
	t.Log("the confirmed move committed: the cut lifted at once")
	c.eventually("it runs on machine 1", 5*time.Minute, func() (bool, string) {
		s := c.silo(ns, "single")
		return s.Status.Host == metalHost && s.Status.Phase == "Running", s.Status.Host + " " + s.Status.Phase
	})
	c.eventually(metalHost2+" is Ready again", 5*time.Minute, func() (bool, string) { return c.hostReady(metalHost2) })
	time.Sleep(3 * time.Minute)
	close(stop)
	select {
	case at := <-both:
		t.Errorf("both machines ran the silo at %s: two copies", at)
	default:
		t.Logf("never two copies: both machines asked %d times", checks.Load())
	}
	if running(p.c2, uid) || !running(p.c1, uid) {
		t.Errorf("after: machine 1 runs it %v, machine 2 %v", running(p.c1, uid), running(p.c2, uid))
	}
	if j := p.c2.mustSh("journalctl -u kevasod --no-pager --since '-6min' | grep -c 'not starting " + ns + "/single' || true"); strings.TrimSpace(j) != "0" {
		t.Logf("machine 2 held back a start from its old cache %s times (K-015's guard)", strings.TrimSpace(j))
	}
}
