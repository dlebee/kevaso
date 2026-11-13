//go:build metal

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
)

// TestMetalModel is the sealed model on a real external IP (design §7.0, ADR 0010): the host has
// the addresses it was given; a cloud-hypervisor silo and a docker silo each declare ports and
// open them on the external IP: one at its own number (reachable from this Mac), one with as: at
// another number (and not at its own), one with sources: that leaves this Mac out (closed to it),
// and, on the docker silo, one with sources: naming this Mac (open). A port asked for [internal]
// on a machine without an internal IP is refused with the reason (with one: it opens there and
// not on the external IP); two silos asking for one host port: the second is told who holds it.
//
// Listens on the external IP while it runs: 18080-18082 (vm), 18090-18093 (box), 18095 (first).
func TestMetalModel(t *testing.T) {
	c := metal(t)
	ns := "model"
	c.namespace(ns)

	h := c.host()
	if h.Spec.ExternalIP != c.cfg.ExternalIP || h.Spec.InternalIP != c.cfg.InternalIP {
		t.Errorf("host %s: internal %q external %q, want %q %q", metalHost, h.Spec.InternalIP, h.Spec.ExternalIP, c.cfg.InternalIP, c.cfg.ExternalIP)
	} else {
		t.Logf("host %s: external %s, internal %q, as given", metalHost, h.Spec.ExternalIP, h.Spec.InternalIP)
	}

	mine := c.macIP + "/32"
	c.apply(vmEcho(ns, "vm", 18080, 8081, 18082) + `  ports: [{ name: web, port: 18080 }, { name: alt, port: 8081 }, { name: shut, port: 18082 }]
  service:
    ports:
      - { port: web, hostPort: [external] }
      - { port: alt, hostPort: [external], as: 18081 }
      - { port: shut, hostPort: [external], sources: [` + testNet + `] }
---
` + boxEcho(ns, "box", 18090, 8091, 18092, 18093) + `  ports: [{ name: web, port: 18090 }, { name: alt, port: 8091 }, { name: mine, port: 18092 }, { name: shut, port: 18093 }]
  service:
    ports:
      - { port: web, hostPort: [external] }
      - { port: alt, hostPort: [external], as: 18091 }
      - { port: mine, hostPort: [external], sources: [` + mine + `] }
      - { port: shut, hostPort: [external], sources: [` + testNet + `] }
`)
	c.waitRunning(ns, 20*time.Minute, "vm", "box")

	for _, s := range []struct {
		silo                string
		web, alt, as, shut  int
		mine                int
		wantWeb, wantAsBody string
	}{
		{"vm", 18080, 8081, 18081, 18082, 0, "vm 18080", "vm 8081"},
		{"box", 18090, 8091, 18091, 18093, 18092, "box 18090", "box 8091"},
	} {
		t.Run(s.silo, func(t *testing.T) {
			c := &mt{metalSuite: c.metalSuite, t: t, ctx: c.ctx}
			c.eventually(fmt.Sprintf("%s: [external] port %d answers this Mac", s.silo, s.web), 2*time.Minute, func() (bool, string) {
				ok, got := c.open(s.web)
				return ok && strings.Contains(got, s.wantWeb), got
			})
			c.eventually(fmt.Sprintf("%s: as: %d answers this Mac (declared %d)", s.silo, s.as, s.alt), time.Minute, func() (bool, string) {
				ok, got := c.open(s.as)
				return ok && strings.Contains(got, s.wantAsBody), got
			})
			if ok, got := c.closed(s.alt); !ok {
				t.Errorf("%s: the declared number %d also answers on the external IP: %s", s.silo, s.alt, got)
			}
			c.holds(fmt.Sprintf("%s: sources: %s keeps port %d closed to this Mac", s.silo, testNet, s.shut), 10*time.Second,
				func() (bool, string) { return c.closed(s.shut) })
			if s.mine != 0 {
				c.eventually(fmt.Sprintf("%s: sources: [%s] opens port %d to this Mac", s.silo, mine, s.mine), time.Minute,
					func() (bool, string) { return c.open(s.mine) })
			}
			st := c.silo(ns, s.silo)
			for _, p := range st.Status.Service.Ports {
				if p.Port == "web" && !strings.Contains(p.External, c.cfg.ExternalIP) {
					t.Errorf("%s: status says port web is on %q, want the external IP", s.silo, p.External)
				}
			}
			t.Logf("%s: service ports %+v", s.silo, st.Status.Service.Ports)
		})
	}

	// [internal]: refused without an internal IP, with the reason; opened there (and only there) with one.
	c.apply(boxEcho(ns, "inner", 18096) + `  ports: [{ name: web, port: 18096 }]
  service:
    ports: [{ port: web, hostPort: [internal] }]
`)
	if c.cfg.InternalIP == "" {
		c.eventually("[internal] without an internal IP: refused, saying why", 2*time.Minute, func() (bool, string) {
			d, _ := c.kvo("", "describe", "silo", "inner", "-n", ns)
			return strings.Contains(d, "no internal IP") && c.silo(ns, "inner").Status.Phase != "Running", d
		})
	} else {
		c.waitRunning(ns, 10*time.Minute, "inner")
		c.eventually("[internal] answers on the internal IP (from the machine)", time.Minute, func() (bool, string) {
			out, err := c.sh(fmt.Sprintf("curl -sS --max-time 3 http://%s:18096/", c.cfg.InternalIP))
			return err == nil && strings.Contains(out, "inner 18096"), out
		})
		c.holds("[internal] stays closed on the external IP", 5*time.Second, func() (bool, string) { return c.closed(18096) })
	}

	// One host port, two silos: the second is told who holds it.
	c.apply(boxEcho(ns, "first", 18095) + `  ports: [{ name: web, port: 18095 }]
  service:
    ports: [{ port: web, hostPort: [external] }]
`)
	c.waitRunning(ns, 10*time.Minute, "first")
	c.apply(boxEcho(ns, "second", 18095) + `  ports: [{ name: web, port: 18095 }]
  service:
    ports: [{ port: web, hostPort: [external] }]
`)
	c.eventually("the second silo on port 18095 is told it's held by the first", 2*time.Minute, func() (bool, string) {
		d, _ := c.kvo("", "describe", "silo", "second", "-n", ns)
		return strings.Contains(d, "held by "+ns+"/first") && c.silo(ns, "second").Status.Phase != "Running", d
	})
	c.expect("port 18095 is still the first's", func() string { _, got := c.open(18095); return got }(), "first 18095")
}

// TestMetalNames is the names on a real machine (ADR 0010 §5). From inside a silo (a microVM and
// a container): a service resolves by its short name, SERVICE.NAMESPACE and its full name, to its
// silo IP; a silo with no service has no name; host names and the internal/external names don't
// resolve. From this Mac, with the host's DNS switch off, the external IP doesn't answer; with
// spec.network.dns: [external], it answers the external names only, with the external IP, and
// never forwards.
//
// Listens on the external IP while it runs: 18100 (api), 53/udp+tcp while the switch is on.
func TestMetalNames(t *testing.T) {
	c := metal(t)
	ns := "names"
	c.namespace(ns)
	c.apply(boxEcho(ns, "api", 8080, 18100) + `  ports: [{ name: http, port: 8080 }, { name: pub, port: 18100 }]
  service:
    ports: [{ port: http }, { port: pub, hostPort: [external] }]
---
` + boxEcho(ns, "quiet", 8080) + `---
` + vmEcho(ns, "asker", 8080))
	c.waitRunning(ns, 20*time.Minute, "api", "quiet", "asker")
	apiIP := c.silo(ns, "api").Status.SiloIP
	if apiIP == "" {
		t.Fatal("api has no silo IP")
	}
	sfx := c.suffix
	resolve := func(silo, name string) string {
		out, _ := c.in(ns, silo, "getent ahostsv4 "+name+" | awk 'NR==1 {print $1}'")
		return strings.TrimSpace(out)
	}
	for _, asker := range []string{"asker", "api"} { // a microVM, and a container (python:3.12-slim has getent)
		for _, name := range []string{"api", "api." + ns, "api." + ns + "." + sfx} {
			if got := resolve(asker, name); got != apiIP {
				t.Errorf("from %s, %s = %q, want the silo IP %s", asker, name, got, apiIP)
			} else {
				t.Logf("from %s, %s = %s", asker, name, got)
			}
		}
		for _, name := range []string{"quiet", "quiet." + ns + "." + sfx, // no service, no name
			metalHost + ".mesh." + sfx, metalHost + ".internal." + sfx, metalHost + ".external." + sfx, // host names
			"api." + ns + ".external." + sfx, "api." + ns + ".internal." + sfx, "api." + ns + ".mesh." + sfx} { // network names
			if got := resolve(asker, name); got != "" {
				t.Errorf("from %s, %s resolved to %s: a silo may resolve plain and short service names only", asker, name, got)
			}
		}
	}

	// From this Mac: the external IP as a DNS server.
	ask := func(name string) ([]netip.Addr, error) {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort(c.cfg.ExternalIP, "53"))
		}}
		ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
		defer cancel()
		return r.LookupNetIP(ctx, "ip4", name+".")
	}
	if a, err := ask("api." + ns + "." + sfx); err == nil {
		t.Errorf("with the DNS switch off, the external IP answered %v", a)
	} else {
		t.Logf("DNS switch off: no answer on the external IP (%v)", err)
	}
	setDNS := func(on []string) {
		h := c.host()
		h.Spec.Network.DNS = on
		h.Status = v1.HostStatus{}
		b, err := json.Marshal(h)
		if err != nil {
			t.Fatal(err)
		}
		c.apply(string(b))
	}
	setDNS([]string{v1.NetworkExternal})
	t.Cleanup(func() { setDNS(nil) })
	ext := netip.MustParseAddr(c.cfg.ExternalIP)
	c.eventually("the external listener answers the plain name with the external IP", 2*time.Minute, func() (bool, string) {
		a, err := ask("api." + ns + "." + sfx)
		return err == nil && len(a) == 1 && a[0] == ext, fmt.Sprint(a, err)
	})
	for _, name := range []string{"api." + ns + ".external." + sfx, metalHost + ".external." + sfx} {
		if a, err := ask(name); err != nil || len(a) != 1 || a[0] != ext {
			t.Errorf("from this Mac, %s = %v %v, want %s", name, a, err, ext)
		} else {
			t.Logf("from this Mac, %s = %s", name, a[0])
		}
	}
	for _, name := range []string{"api." + ns + ".mesh." + sfx, "api." + ns + ".internal." + sfx, metalHost + ".mesh." + sfx,
		metalHost + ".internal." + sfx, "quiet." + ns + "." + sfx, "example.com"} {
		if a, err := ask(name); err == nil && len(a) > 0 {
			t.Errorf("from this Mac, %s = %v: anyone outside gets external names only, and nothing is forwarded", name, a)
		}
	}
	if a, _ := ask("api." + ns + "." + sfx); len(a) == 1 && a[0].String() == apiIP {
		t.Errorf("this Mac got the silo IP %s: the plain name's answer depends on who asks", apiIP)
	}
}
