//go:build metal

package e2e

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/internal/cli/kvoadm"
)

// metalEcho6 answers "NAME PORT CLIENT" on every port it is given, over IPv4 and IPv6 (one
// dual-stack socket per port): CLIENT is the address the connection came from, as the silo sees
// it, unmapped.
const metalEcho6 = `import http.server as h, socket, threading as t, sys
class S(h.ThreadingHTTPServer):
    address_family = socket.AF_INET6
    def server_bind(s):
        s.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()
class H(h.BaseHTTPRequestHandler):
    def do_GET(s):
        c = s.client_address[0]
        if c.startswith("::ffff:"): c = c[7:]
        b = ("%s %d %s\n" % (sys.argv[1], s.server.server_port, c)).encode()
        s.send_response(200); s.send_header("Content-Length", str(len(b))); s.end_headers(); s.wfile.write(b)
    def log_message(s, *a): pass
for p in sys.argv[2:]:
    t.Thread(target=S(("::", int(p)), H).serve_forever).start()
`

func echo6Argv(name string, ports ...int) []string {
	argv := []string{"python3", "-c", "exec(__import__('base64').b64decode('" + base64.StdEncoding.EncodeToString([]byte(metalEcho6)) + "'))", name}
	for _, p := range ports {
		argv = append(argv, fmt.Sprint(p))
	}
	return argv
}

// trace6 asks Cloudflare's resolver over IPv6 who is calling (its /cdn-cgi/trace, "ip=…"):
// the silo's address out, or "FAIL …" when it can't get there.
const trace6 = `python3 -c "
import ssl, urllib.request as u
try:
    c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    b = u.urlopen('https://[2606:4700:4700::1111]/cdn-cgi/trace', timeout=8, context=c).read().decode()
    print([l for l in b.splitlines() if l.startswith('ip=')][0])
except Exception as e:
    print('FAIL', type(e).__name__, e)
"`

// fromMac6 GETs http://[addr]:port/ from this Mac over IPv6, and says which of the Mac's
// addresses it went from.
func fromMac6(addr string, port int) (body, from string, err error) {
	target := net.JoinHostPort(addr, fmt.Sprint(port))
	if c, err := net.Dial("udp6", target); err == nil { // the source the Mac picks for it (nothing is sent)
		from = c.LocalAddr().(*net.UDPAddr).IP.String()
		_ = c.Close()
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	client := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true,
		DialContext: d.DialContext}}
	resp, err := client.Get("http://" + target + "/")
	if err != nil {
		return "", from, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return strings.TrimSpace(string(b)), from, err
}

// TestMetalIPv6 is the IPv6 effort's wave 2 on a real machine (the worker's wiring and the
// runtimes): the worker finds the machine's global IPv6 address (spec.externalIPv6); a docker
// silo gets an address in the host's IPv6 /64; its HostPort answers this Mac over IPv6 on the
// worker's address with the Mac's address kept (DNAT, not NAT), and still over IPv4; a port it
// listens on but doesn't open stays closed over IPv6; it reaches an IPv6 destination only while
// a grant opens it, from the worker's address (NAT66). With KEVASO_METAL_IPV6_EXTRA (another
// address of the machine's /64), a kept IPv6 IP too: the service on it, egress from it, the
// address on the uplink as Kevaso's /128 and off it again.
//
// Listens on the external IP (IPv4 and IPv6) while it runs: 18150; 18151 on the extra address.
func TestMetalIPv6(t *testing.T) {
	c := metal(t)
	h := c.host()
	ext6 := h.Spec.ExternalIPv6
	if ext6 == "" {
		t.Fatalf("no spec.externalIPv6 detected on %s (the machine has a global IPv6 address): %s", metalHost, c.journal(20))
	}
	if h.Status.Network.SiloSubnetIPv6 == "" {
		t.Fatalf("no silo IPv6 subnet on %s", metalHost)
	}
	sub6 := netip.MustParsePrefix(h.Status.Network.SiloSubnetIPv6)
	t.Logf("%s: externalIPv6 %s, silo /64 %s", metalHost, ext6, sub6)
	c.expect("the silos' gateway is on the bridge", c.mustSh(`ip -6 -o addr show dev kvbr0 scope global | awk '{print $4}'`),
		netip.PrefixFrom(sub6.Addr().Next(), 64).String())
	c.expect("IPv6 forwarding is on", c.mustSh("sysctl -n net.ipv6.conf.all.forwarding"), "1")

	ns := "six"
	c.namespace(ns, "grant/net6")
	grant := func(to ...string) {
		rules := ""
		for _, d := range to {
			rules += "    - { to: " + yamlStr(d) + ", ports: [\"443\"] }\n"
		}
		c.apply("apiVersion: kevaso/v1\nkind: Grant\nmetadata: { name: net6, namespace: " + ns + " }\nspec:\n  egress:\n" + rules)
	}
	grant("192.0.2.1/32") // something that isn't IPv6
	c.apply(fmt.Sprintf(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: web, namespace: %s }
spec:
  runtime: docker
  container: { image: docker.io/library/python:3.12-slim, command: %s }
  resources: { cpu: 1, memory: 256Mi }
  grants: [net6]
  ports: [{ name: web, port: 18150 }]
  services:
    - type: HostPort
      ports: [{ port: web }]
`, ns, yamlList(echo6Argv("web", 18150, 18151))))
	c.waitRunning(ns, 10*time.Minute, "web")
	s := c.silo(ns, "web")
	silo6, err := netip.ParseAddr(s.Status.SiloIPv6)
	if err != nil || !sub6.Contains(silo6) {
		t.Fatalf("status.siloIPv6 %q, not in %s", s.Status.SiloIPv6, sub6)
	}
	t.Logf("web: %s, %s", s.Status.SiloIP, silo6)

	// In over IPv6, the client kept; IPv4 as before.
	c.eventually("web answers this Mac over IPv6 on the worker's address, seeing the Mac's address", time.Minute, func() (bool, string) {
		body, from, err := fromMac6(ext6, 18150)
		if err != nil {
			return false, err.Error()
		}
		return from != "" && body == "web 18150 "+from, body + " (the Mac sent from " + from + ")"
	})
	c.eventually("and over IPv4", time.Minute, func() (bool, string) {
		ok, got := c.open(18150)
		return ok && strings.HasPrefix(got, "200 web 18150 "), got
	})
	// Nothing else: the port it listens on but doesn't open, over IPv6.
	c.holds("18151 stays closed over IPv6", 10*time.Second, func() (bool, string) {
		body, _, err := fromMac6(ext6, 18151)
		return err != nil, body
	})

	// Out over IPv6: only with a grant, from the worker's address.
	c.holds("no IPv6 out without a grant", 20*time.Second, func() (bool, string) {
		got, _ := c.in(ns, "web", trace6)
		return strings.HasPrefix(got, "FAIL"), got
	})
	grant("192.0.2.1/32", "2606:4700:4700::1111/128")
	c.eventually("with the grant, out over IPv6 from the worker's address", time.Minute, func() (bool, string) {
		got, _ := c.in(ns, "web", trace6)
		return got == "ip="+ext6, got
	})
	grant("192.0.2.1/32")
	c.eventually("the grant taken back: no IPv6 out again", time.Minute, func() (bool, string) {
		got, _ := c.in(ns, "web", trace6)
		return strings.HasPrefix(got, "FAIL"), got
	})

	extra := os.Getenv("KEVASO_METAL_IPV6_EXTRA")
	if extra == "" {
		t.Log("KEVASO_METAL_IPV6_EXTRA unset: the kept IPv6 IP part is skipped")
		return
	}
	grant("192.0.2.1/32", "2606:4700:4700::1111/128")
	var o strings.Builder
	c.kvoadmOrFail(&o, "host", "addresses", metalHost, "add", "edge6", extra)
	t.Cleanup(func() {
		c.kvo("", "delete", "silo", "kept", "-n", ns)
		c.eventually("kept gone", 3*time.Minute, func() (bool, string) {
			_, code := c.kvo("", "get", "silo", "kept", "-n", ns)
			return code != 0, ""
		})
		c.kvo("", "delete", "ip", "edge6", "-n", ns)
		var o strings.Builder
		c.kvoadmOrFail(&o, "host", "addresses", metalHost, "remove", "edge6")
		c.eventually("the extra address is off the uplink", time.Minute, func() (bool, string) {
			out, _ := c.sh(`ip -6 -o addr show | grep -F ' ` + extra + `/128 '; true`)
			return strings.TrimSpace(out) == "", out
		})
	})
	c.apply(fmt.Sprintf(`apiVersion: kevaso/v1
kind: IP
metadata: { name: edge6, namespace: %s }
spec: { type: Host, hostAddress: edge6, family: IPv6 }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: kept, namespace: %s }
spec:
  runtime: docker
  container: { image: docker.io/library/python:3.12-slim, command: %s }
  resources: { cpu: 1, memory: 256Mi }
  grants: [net6]
  ports: [{ name: web, port: 18151 }]
  network: { egress: { source: { ip: edge6 } } }
  services:
    - type: HostPort
      hostPort: { ip: edge6 }
      ports: [{ port: web }]
`, ns, ns, yamlList(echo6Argv("kept", 18151))))
	c.waitRunning(ns, 10*time.Minute, "kept")
	c.eventually("the kept address is on the uplink as a deprecated /128, in Kevaso's ledger", time.Minute, func() (bool, string) {
		out, _ := c.sh(`ip -6 -o addr show | grep -F ' ` + extra + `/128 '; echo ledger: $(cat /run/kevaso/ipv6-addresses)`)
		addrs, ledger, _ := strings.Cut(out, "ledger: ")
		return strings.Contains(addrs, "deprecated") && strings.Contains(ledger, extra+"/128"), out
	})
	c.eventually("kept answers this Mac on its IPv6 address, seeing the Mac's address", time.Minute, func() (bool, string) {
		body, from, err := fromMac6(extra, 18151)
		if err != nil {
			return false, err.Error()
		}
		return from != "" && body == "kept 18151 "+from, body + " (the Mac sent from " + from + ")"
	})
	c.holds("not on the worker's own address", 10*time.Second, func() (bool, string) {
		body, _, err := fromMac6(ext6, 18151)
		return err != nil, body
	})
	c.eventually("out over IPv6 from the kept address", time.Minute, func() (bool, string) {
		got, _ := c.in(ns, "kept", trace6)
		return got == "ip="+extra, got
	})
	c.expect("the host still goes out from its own address", strings.TrimSpace(c.mustSh(`ip -6 -o route get 2606:4700:4700::1111 | sed -n 's/.* src \([^ ]*\).*/\1/p'`)), ext6)
}

// kvoadmOrFail runs kvoadm as the suite's admin (KVO_CONFIG), failing the test on an error.
func (c *mt) kvoadmOrFail(o *strings.Builder, args ...string) {
	c.t.Helper()
	if code := kvoadm.Run(c.ctx, args, strings.NewReader(""), o, o); code != 0 {
		c.t.Errorf("kvoadm %v: exit %d\n%s", args, code, o.String())
	}
}
