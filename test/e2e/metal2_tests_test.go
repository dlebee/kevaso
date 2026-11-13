//go:build metal

package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/sdk/kri"
)

// TestMetal2Worker is the owner's setup in miniature: machine 1 the system node only (until a
// later test makes it a worker too), machine 2 a worker that joined over the external IPs, the
// mesh between them; a microVM and a container on the worker answer this Mac on its external
// IP (and not on the system node's), and kvo exec reaches them through the agent's tunnel.
//
// Listens on machine 2's external IP while it runs: 18200, 18201.
func TestMetal2Worker(t *testing.T) {
	p := metal2(t)
	c := p.c1
	ns := "worker2"
	c.namespace(ns)
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
---
` + boxEcho(ns, "box", 18201) + place + `  ports: [{ name: web, port: 18201 }]
  service:
    ports: [{ port: web, hostPort: [external] }]
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
// other host with its data (a handoff: never two copies), and leaves nothing on the source; a
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
	c.apply(boxEcho(ns, "web", 8080) + "---\n" + vmEcho(ns, "db", 8080) + on(metalHost2) + "  volumes: [{ name: data, size: 1Gi, mountPath: /data }]\n")
	c.waitRunning(ns, 20*time.Minute, "web", "db")
	from := c.silo(ns, "web").Status.Host
	to := map[string]string{metalHost: metalHost2, metalHost2: metalHost}[from]
	src := map[string]*mt{metalHost: p.c1, metalHost2: p.c2}[from]
	marker := randomValue(t, "move-")
	if out, code := c.in(ns, "web", "echo "+marker+" > /root/marker && sync"); code != 0 {
		t.Fatalf("write: %d %s", code, out)
	}
	uid := c.silo(ns, "web").UID
	c.must("", "move", "silo", "web", "-n", ns, "--to", to)
	c.eventually("web runs on "+to, 10*time.Minute, func() (bool, string) {
		s := c.silo(ns, "web")
		return s.Status.Host == to && s.Status.Phase == "Running" && s.Status.MovingFrom == "", fmt.Sprint(s.Status.Host, s.Status.Phase, s.Status.MovingFrom)
	})
	c.expect("its data came along", func() string { o, _ := c.in(ns, "web", "cat /root/marker"); return o }(), marker)
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

// TestMetal2Fence is the fence acting (design §0.4): machine 2 cut off from the system node (a
// firewall rule on machine 2, never port 22) past the fence time stops only the silos the
// control plane may start elsewhere (onHostLoss: Recreate), keeps the Wait ones running; the
// control plane starts the Recreate one on machine 1; kvo move --confirm-fenced moves a Wait one
// off the lost host; with the cut lifted, machine 2 has one copy of nothing that moved, and the
// Wait silo that stayed never restarted.
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
		boxEcho(ns, "moves", 8080) + "  availability: { onHostLoss: Recreate }\n" + "---\n" + boxEcho(ns, "rescue", 8080))
	c.waitRunning(ns, 10*time.Minute, "stay", "moves", "rescue")
	for _, n := range []string{"moves", "rescue"} { // both on machine 2 to start with
		if s := c.silo(ns, n); s.Status.Host != metalHost2 {
			c.must("", "move", "silo", n, "-n", ns, "--to", metalHost2)
		}
	}
	c.eventually("all three on "+metalHost2, 5*time.Minute, func() (bool, string) {
		got := ""
		for _, n := range []string{"stay", "moves", "rescue"} {
			s := c.silo(ns, n)
			if s.Status.Host != metalHost2 || s.Status.Phase != "Running" {
				return false, n + " " + s.Status.Host + " " + s.Status.Phase
			}
			got += n + " "
		}
		return true, got
	})
	uids := map[string]string{}
	for _, n := range []string{"stay", "moves", "rescue"} {
		uids[n] = c.silo(ns, n).UID
	}
	stayStart := strings.TrimSpace(p.c2.mustSh("docker ps -q --filter label=kevaso.com/uid=" + uids["stay"] + " | xargs -r docker inspect -f '{{.State.StartedAt}}'"))
	rec := p.c2.mustSh("cat " + fence.Dir + "/" + fence.RecordFile)
	if !strings.Contains(rec, `"fence":true`) {
		t.Errorf("machine 2's fence record doesn't say fence: true (its control plane is elsewhere): %s", rec)
	}

	p.cut()
	t.Log("machine 2 cut off from the system node")
	c.eventually("the fence stops the Recreate silo on machine 2", fence.WorstStopped(fence.DefaultAfter)+30*time.Second, func() (bool, string) {
		return !running(p.c2, uids["moves"]), "still running"
	})
	if !running(p.c2, uids["stay"]) || !running(p.c2, uids["rescue"]) {
		t.Error("the fence stopped a Wait silo")
	} else {
		t.Log("the Wait silos keep running on machine 2")
	}
	c.eventually("the control plane starts the Recreate silo on machine 1", 5*time.Minute, func() (bool, string) {
		s := c.silo(ns, "moves")
		return s.Status.Host == metalHost && s.Status.Phase == "Running", s.Status.Host + " " + s.Status.Phase
	})
	if out, code := c.kvo("", "move", "silo", "rescue", "-n", ns, "--to", metalHost); code == 0 {
		t.Errorf("a move off a lost host without --confirm-fenced went ahead: %s", out)
	}
	// Machine 2 still runs rescue (Wait: never fenced). Confirming the fence is the operator's
	// word that it doesn't: make it true first, as an operator would on a host they can reach.
	p.c2.mustSh("docker ps -q --filter label=kevaso.com/uid=" + uids["rescue"] + " | xargs -r docker stop -t 2 >/dev/null; true")
	c.must("", "move", "silo", "rescue", "-n", ns, "--to", metalHost, "--confirm-fenced")
	c.eventually("--confirm-fenced: rescue runs on machine 1", 5*time.Minute, func() (bool, string) {
		s := c.silo(ns, "rescue")
		return s.Status.Host == metalHost && s.Status.Phase == "Running", s.Status.Host + " " + s.Status.Phase
	})

	p.uncut()
	t.Log("the cut lifted")
	c.eventually(metalHost2+" is Ready again", 5*time.Minute, func() (bool, string) {
		h := c.hostNamed(metalHost2)
		return meta(*h, "Ready"), fmt.Sprint(h.Status.Conditions)
	})
	c.eventually("machine 2 keeps no copy of what moved", 5*time.Minute, func() (bool, string) {
		return !running(p.c2, uids["moves"]) && !running(p.c2, uids["rescue"]), "a copy still runs"
	})
	if got := strings.TrimSpace(p.c2.mustSh("docker ps -q --filter label=kevaso.com/uid=" + uids["stay"] + " | xargs -r docker inspect -f '{{.State.StartedAt}}'")); got != stayStart {
		t.Errorf("the Wait silo restarted: %q → %q", stayStart, got)
	}
	c.waitRunning(ns, 3*time.Minute, "stay", "moves", "rescue")
}

// TestMetal2HostLoss is a worker lost and back: machine 2 rebooted while it holds silos. While
// it's down the control plane starts the Recreate silo on machine 1 and keeps the Wait ones
// waiting; back up, the Wait ones (a container, and a microVM with its volume's data) run on
// it again, and it keeps no copy of the one that moved.
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
		c.must("", "move", "silo", "moves", "-n", ns, "--to", metalHost2)
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
	c.eventually("the control plane starts the Recreate silo on machine 1", 5*time.Minute, func() (bool, string) {
		s := c.silo(ns, "moves")
		return s.Status.Host == metalHost && s.Status.Phase == "Running", s.Status.Host + " " + s.Status.Phase
	})
	if s := c.silo(ns, "stay"); s.Status.Host != metalHost2 {
		t.Errorf("a Wait silo left its lost host: %s", s.Status.Host)
	}
	c.eventually("machine 2 is back (a new boot, the pinned host key)", 15*time.Minute, func() (bool, string) {
		out, err := p.c2.sh("cat /proc/sys/kernel/random/boot_id")
		if err != nil {
			_ = p.m2.d.Close()
			return false, err.Error()
		}
		return strings.TrimSpace(out) != boot, out
	})
	c.eventually(metalHost2+" is Ready again", 10*time.Minute, func() (bool, string) {
		h := c.hostNamed(metalHost2)
		return meta(*h, "Ready"), fmt.Sprint(h.Status.Conditions)
	})
	c.waitRunning(ns, 15*time.Minute, "stay", "vm", "moves")
	for _, n := range []string{"stay", "vm"} {
		if h := c.silo(ns, n).Status.Host; h != metalHost2 {
			t.Errorf("%s runs on %s after the boot, want %s", n, h, metalHost2)
		}
	}
	c.expect("the microVM's unit is up on machine 2", p.c2.mustSh("systemctl is-active "+unit), "active")
	c.eventually("its volume kept the data", 5*time.Minute, func() (bool, string) {
		out, code := c.in(ns, "vm", "cat /data/marker")
		return code == 0 && out == marker, out
	})
	c.eventually("machine 2 keeps no copy of the silo that moved", 5*time.Minute, func() (bool, string) {
		out, _ := p.c2.sh("docker ps -aq --filter label=kevaso.com/uid=" + movesUID)
		return strings.TrimSpace(out) == "", out
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
