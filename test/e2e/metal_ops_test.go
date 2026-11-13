//go:build metal

package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/sdk/kri"
)

// TestMetalLeases is port leases on an [external] port (design §7.2d): closed until leased;
// opened for a minute, it answers this Mac, a connection held open is cut when the lease ends,
// and new ones are refused. A port whose lease needs approval opens at once for someone who
// holds approve (the admin's kvo open); asked for by the silo itself (its local endpoint), it
// stays closed until a person says yes, and closes again on kvo close.
//
// Listens on the external IP while it runs: 18120 (for its minute), 18121 (once approved).
func TestMetalLeases(t *testing.T) {
	c := metal(t)
	ns := "leases"
	c.namespace(ns)
	c.apply(boxEcho(ns, "dbg", 18120, 18121) + `  ports: [{ name: debug, port: 18120 }, { name: gated, port: 18121 }]
  service:
    ports:
      - { port: debug, hostPort: [external], lease: { max: 2m } }
      - { port: gated, hostPort: [external], lease: { max: 2m, approval: { required: true } } }
`)
	c.waitRunning(ns, 10*time.Minute, "dbg")
	c.holds("a leased port is closed until leased", 10*time.Second, func() (bool, string) { return c.closed(18120) })

	c.must("", "open", "silo", "dbg", "-n", ns, "--port", "debug", "--for", "1m")
	opened := time.Now()
	c.eventually("leased for a minute: it answers this Mac", 30*time.Second, func() (bool, string) { return c.open(18120) })
	// A connection held open across the lease's end.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(c.cfg.ExternalIP, "18120"), 5*time.Second)
	if err != nil {
		t.Fatalf("holding a connection: %v", err)
	}
	defer func() { _ = conn.Close() }()
	ask := func() error {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
			return err
		}
		r := bufio.NewReader(conn)
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		if !strings.HasPrefix(line, "HTTP/1.") {
			return fmt.Errorf("answer %q", line)
		}
		// Drain the small body so the next request starts clean.
		for {
			l, err := r.ReadString('\n')
			if err != nil || l == "\r\n" {
				break
			}
		}
		buf := make([]byte, 64)
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = r.Read(buf)
		return nil
	}
	if err := ask(); err != nil {
		t.Fatalf("the held connection, while leased: %v", err)
	}
	time.Sleep(time.Until(opened.Add(time.Minute + 15*time.Second)))
	if err := ask(); err == nil {
		t.Error("the held connection still answers after the lease ended")
	} else {
		t.Logf("the held connection was cut at the end: %v", err)
	}
	c.eventually("after the lease: closed to new connections", 30*time.Second, func() (bool, string) { return c.closed(18120) })

	// With approval required: someone who holds approve (the cluster's admin, this test's user)
	// opens it at once, by design; the silo itself asking through its local endpoint waits for a
	// person's yes.
	c.must("", "open", "silo", "dbg", "-n", ns, "--port", "gated", "--for", "1m")
	c.eventually("an admin's ask opens the gated port at once", 30*time.Second, func() (bool, string) { return c.open(18121) })
	c.must("", "close", "silo", "dbg", "-n", ns, "--port", "gated")
	c.eventually("kvo close: closed", 30*time.Second, func() (bool, string) { return c.closed(18121) })

	c.upload(ns, "dbg", "/tmp/ask.py", metalPortAsk)
	asked, _ := c.in(ns, "dbg", "python3 /tmp/ask.py gated 1m")
	t.Logf("the silo asked for port gated: %s", asked)
	var pending string
	c.eventually("the silo's ask makes an expose approval", time.Minute, func() (bool, string) {
		out, _ := c.kvo("", "get", "approvals", "-n", ns, "-o", "json")
		for _, raw := range metalItems(out) {
			var a v1.Approval
			if json.Unmarshal(raw, &a) == nil && a.Spec.Use == v1.ApprovalForExpose && a.Spec.Port == "gated" && a.Status.Phase == v1.ApprovalPending {
				pending = a.Name
				return true, ""
			}
		}
		return false, out
	})
	c.holds("unapproved: still closed", 5*time.Second, func() (bool, string) { return c.closed(18121) })
	if pending == "" {
		return
	}
	c.must("", "approve", pending, "-n", ns)
	c.eventually("approved: it opens", 30*time.Second, func() (bool, string) { return c.open(18121) })
	c.must("", "close", "silo", "dbg", "-n", ns, "--port", "gated")
	c.eventually("kvo close: closed again", 30*time.Second, func() (bool, string) { return c.closed(18121) })
}

// metalPortAsk is a silo asking its local endpoint to open one of its ports (ADR 0009):
// python3 ask.py PORT FOR. It prints the status and the answer.
const metalPortAsk = `import sys, urllib.request, urllib.error
req = urllib.request.Request("http://169.254.42.1/v1/ports/%s/open?for=%s" % (sys.argv[1], sys.argv[2]), method="POST", headers={"Kevaso-Local": "1"})
try:
    r = urllib.request.urlopen(req, timeout=15)
    print(r.status, r.read().decode())
except urllib.error.HTTPError as e:
    print(e.code, e.read().decode())
`

// TestMetalPanes is panes with no guest helper (ADR 0009) in both runtimes: a silo serves its
// panes over HTTP inside, the host fetches them (host → silo address, the real firewall in
// between) and kvo get panes shows them; a silo that answers too much is cut off, saying so.
//
// Listens on nothing outside (the host dials the silos on their private addresses).
func TestMetalPanes(t *testing.T) {
	c := metal(t)
	ns := "panes"
	c.namespace(ns)
	spec := "  panes: { http: { port: 7070, path: /panes }, every: 1s, allow: [status] }\n"
	c.apply(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: vm, namespace: ` + ns + ` }
spec:
  runtime: cloud-hypervisor
  vm: { image: ubuntu-24.04 }
  resources: { cpu: 1, memory: 768Mi }
  disk: { size: 5Gi }
  daemons:
    - { name: panes, run: "mkdir -p /srv/panes; while [ ! -f /usr/local/bin/pane-server ]; do sleep 1; done; exec python3 /usr/local/bin/pane-server" }
` + spec + `---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: box, namespace: ` + ns + ` }
spec:
  runtime: docker
  container: { image: docker.io/library/python:3.12-slim, command: [sh, -c, "mkdir -p /srv/panes; while [ ! -f /usr/local/bin/pane-server ]; do sleep 1; done; exec python3 /usr/local/bin/pane-server"] }
  resources: { cpu: 1, memory: 256Mi }
` + spec)
	c.waitRunning(ns, 20*time.Minute, "vm", "box")
	for _, silo := range []string{"vm", "box"} {
		t.Run(silo, func(t *testing.T) {
			c := &mt{metalSuite: c.metalSuite, t: t, ctx: c.ctx}
			report := func(list string) {
				t.Helper()
				c.upload(ns, silo, "/srv/panes/list.json.new", list)
				if out, code := c.in(ns, silo, "mv /srv/panes/list.json.new /srv/panes/list.json"); code != 0 {
					t.Fatalf("pane list: %d %s", code, out)
				}
			}
			report(`{"panes": [{"pane": "build", "kind": "status", "state": "running", "progress": 0.5, "title": "Building", "ttl": "5m"}]}`)
			c.upload(ns, silo, "/usr/local/bin/pane-server", metalPaneServer)
			c.eventually("the host fetched the pane: kvo get panes shows it", 2*time.Minute, func() (bool, string) {
				out, _ := c.kvo("", "get", "panes", "-n", ns)
				return strings.Contains(out, silo+".build"), out
			})
			report(`{"panes": [{"pane": "build", "kind": "status", "message": "` + strings.Repeat("x", 400<<10) + `"}]}`)
			c.eventually("an oversized answer cuts the silo off", time.Minute, func() (bool, string) {
				for _, cd := range c.silo(ns, silo).Status.Conditions {
					if cd.Type == "Panes" && cd.Reason == "CutOff" {
						return true, cd.Message
					}
				}
				return false, ""
			})
		})
	}
}

// metalPaneServer answers the pane protocol (ADR 0009) from /srv/panes/list.json on port 7070.
const metalPaneServer = `#!/usr/bin/env python3
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/panes":
            self.send_error(404); return
        try:
            b = open("/srv/panes/list.json", "rb").read()
        except OSError:
            self.send_error(404); return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("", 7070), H).serve_forever()
`

// TestMetalFence is restarts and the fence on the one machine (design §0.4): a quick systemctl
// restart kevasod stops no silo; kevasod stopped past the fence time stops only the silos that
// could be started elsewhere — on a one-machine cluster (control plane and worker in one), none
// can, so the fence record says fence: false and every silo, Wait or Recreate, keeps running. The
// fence acting on a worker whose control plane is elsewhere is the Linode-backed test's
// (metal_linode_test.go), and Lima's TestMoves.
//
// Listens on nothing outside.
func TestMetalFence(t *testing.T) {
	c := metal(t)
	ns := "fence"
	c.namespace(ns)
	c.apply(boxEcho(ns, "stay", 8080) + "---\n" + boxEcho(ns, "moves", 8080) + "  availability: { onHostLoss: Recreate }\n---\n" + vmEcho(ns, "vm", 8080))
	c.waitRunning(ns, 20*time.Minute, "stay", "moves", "vm")
	t.Cleanup(func() { _, _ = c.sh("systemctl start kevasod") })

	// Each silo's start time, from the host only (SSH): containers by their label, the microVM by
	// its unit. On a one-machine cluster the API is the kevasod being stopped, so what identifies
	// the silos is read now, while it answers.
	uids := map[string]string{}
	for _, name := range []string{"stay", "moves"} {
		uids[name] = c.silo(ns, name).UID
	}
	vm := c.silo(ns, "vm")
	unit := cloudhypervisor.NamesFor(kri.ID{Namespace: vm.Namespace, Name: vm.Name, UID: vm.UID}).Unit
	started := func() map[string]string {
		got := map[string]string{}
		for name, uid := range uids {
			got[name] = strings.TrimSpace(c.mustSh(`for id in $(docker ps -q --filter label=kevaso.com/uid=` + uid + `); do docker inspect -f '{{.Name}} {{.State.StartedAt}}' "$id"; done | sort`))
		}
		got["vm"] = strings.TrimSpace(c.mustSh("systemctl show -p ActiveEnterTimestamp,ActiveState " + unit))
		return got
	}
	same := func(what string, before map[string]string) {
		t.Helper()
		after := started()
		for k, v := range before {
			if after[k] != v || v == "" {
				t.Errorf("%s: %s changed: %q → %q", what, k, v, after[k])
			}
		}
		if !strings.Contains(after["vm"], "ActiveState=active") {
			t.Errorf("%s: the microVM isn't running: %s", what, after["vm"])
		} else {
			t.Logf("%s: every silo kept running", what)
		}
	}
	waitAPI := func() {
		c.eventually("the API answers again", 3*time.Minute, func() (bool, string) {
			out, code := c.kvo("", "get", "hosts")
			return code == 0 && strings.Contains(out, "Ready"), out
		})
	}

	before := started()
	c.mustSh("systemctl restart kevasod")
	waitAPI()
	c.waitRunning(ns, 2*time.Minute, "stay", "moves", "vm")
	same("a quick restart", before)

	// Past the fence time with kevasod stopped.
	rec := c.mustSh("cat " + fence.Dir + "/" + fence.RecordFile)
	var r fence.Record
	if err := json.Unmarshal([]byte(rec), &r); err != nil {
		t.Fatalf("fence record: %v\n%s", err, rec)
	}
	if r.Fence {
		t.Errorf("the fence record says fence: true on a one-machine cluster (nobody could start its silos elsewhere)")
	}
	c.mustSh("systemctl stop kevasod")
	wait := fence.DefaultAfter + fence.CheckEvery + fence.KillWithin + 30*time.Second
	t.Logf("kevasod stopped; waiting %s, past the fence time", wait)
	time.Sleep(wait)
	if out, _ := c.sh("systemctl is-active kevaso-fence"); strings.TrimSpace(out) != "active" {
		t.Errorf("the fence isn't running: %q", out)
	}
	same("kevasod stopped past the fence time (from the host)", before)
	c.mustSh("systemctl start kevasod")
	waitAPI()
	c.waitRunning(ns, 3*time.Minute, "stay", "moves", "vm")
	same("kevasod back: the same copies, never restarted", before)
}

// TestMetalVolumes is a local volume on a microVM (design §0.3): data written to it survives the
// guest rebooting, its VMM stopped and started from the host, and kvo reset (which makes the root
// disk fresh: a file there is gone); deleting the silo removes the volume's logical volume.
//
// Listens on nothing outside.
func TestMetalVolumes(t *testing.T) {
	c := metal(t)
	ns := "vols"
	c.namespace(ns)
	c.apply(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: db, namespace: ` + ns + ` }
spec:
  runtime: cloud-hypervisor
  vm: { image: ubuntu-24.04 }
  resources: { cpu: 1, memory: 768Mi }
  disk: { size: 5Gi }
  volumes: [{ name: data, size: 1Gi, mountPath: /data }]
`)
	c.waitRunning(ns, 20*time.Minute, "db")
	marker := randomValue(t, "vol-")
	if out, code := c.in(ns, "db", "echo "+marker+" > /data/marker && echo on-root > /root/on-root && sync"); code != 0 {
		t.Fatalf("write: %d %s", code, out)
	}
	s := c.silo(ns, "db")
	n := cloudhypervisor.NamesFor(kri.ID{Namespace: s.Namespace, Name: s.Name, UID: s.UID})
	lvs := func() string {
		return strings.TrimSpace(c.mustSh("lvs --noheadings -o lv_name " + cloudhypervisor.VG + " 2>/dev/null | tr -d ' ' | grep '^" + n.LV + "-' || true"))
	}
	if lvs() == "" {
		t.Fatalf("no logical volume for db's volume (want %s-*)", n.LV)
	}
	hasMarker := func(what string) {
		t.Helper()
		c.eventually(what+": the volume still has the data", 5*time.Minute, func() (bool, string) {
			out, code := c.in(ns, "db", "cat /data/marker")
			return code == 0 && out == marker, out
		})
	}

	_, _ = c.in(ns, "db", "nohup sh -c 'sleep 2; systemctl reboot' >/dev/null 2>&1 &") // returns before the guest goes
	time.Sleep(10 * time.Second)
	c.waitRunning(ns, 5*time.Minute, "db")
	hasMarker("after a reboot inside")

	c.mustSh("systemctl stop " + n.Unit)
	c.mustSh("sleep 5; systemctl is-active " + n.Unit + " || systemctl start " + n.Unit)
	hasMarker("after the VMM stopped and started")

	c.must("", "reset", "silo", "db", "-n", ns)
	c.eventually("reset: the root disk is fresh", 10*time.Minute, func() (bool, string) {
		out, code := c.in(ns, "db", "test -e /root/on-root && echo still || echo fresh")
		return code == 0 && out == "fresh", out
	})
	hasMarker("after kvo reset")

	c.must("", "delete", "silo", "db", "-n", ns)
	c.eventually("deleted: the volume's logical volume is gone", 5*time.Minute, func() (bool, string) {
		l := lvs()
		return l == "", l
	})
}
