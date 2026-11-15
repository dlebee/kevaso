//go:build metal

package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/sdk/kri"
)

// The long soak: a small mixed set of silos left running on both machines for days, checked
// from this Mac every few hours (test/e2e/longsoak-check.sh). TestMetal2LongSoakSetup makes it
// and writes the baseline; TestMetal2LongSoakCheck compares. Both need KEVASO_METAL_REUSE (the
// cluster is kept between runs; the setup makes it if there is none). Remove it with
// go test -tags metal -run TestMetal2DiskReset… or kvoadm reset on both machines.
//
// Listens on the external IPs while it runs: 80 and 443 on the ingress silo's machine (the
// public ingress class, for the staging certificate's HTTP-01 and the route), and 18160 on
// machine 1 while its lease is open (kvo open, 24h).

const longSoakNS = "longsoak"

// longSoak is the baseline the check compares with.
type longSoak struct {
	Made        time.Time                    `json:"made"`
	UIDs        map[string]string            `json:"uids"`   // silo → UID
	Starts      map[string]string            `json:"starts"` // silo → host and start time
	Checksum    string                       `json:"checksum"`
	IngressHost string                       `json:"ingressHost"` // the name the certificate is for
	IngressIP   string                       `json:"ingressIP"`
	CertExpires time.Time                    `json:"certExpires"`
	LeaseUntil  time.Time                    `json:"leaseUntil"`
	Leaks       map[string]map[string]string `json:"leaks"` // host → what it holds
}

var longSoakSilos = []string{"vm", "app", "stops", "leased"}

func longSoakFile(p *pair) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".kevaso-metal", "pair-"+p.m1.cfg.ExternalIP, "longsoak.json")
}

// longSoakLeaks is hostLeaks and more: every link, the mounts under Kevaso's folders, the
// helper processes.
func (p *pair) longSoakLeaks(c *mt) map[string]string {
	got := p.hostLeaks(c)
	for k, script := range map[string]string{
		"links":       `ip -o link show | wc -l`,
		"mounts":      `awk '$2 ~ /^\/(var\/lib|run)\/kevaso/' /proc/mounts | wc -l`,
		"virtiofsd":   `pgrep -c virtiofsd || true`,
		"nft tables":  `nft list tables | wc -l`,
		"kevasod":     `pgrep -c -x kevasod || true`,
		"listening":   `ss -Htln | wc -l`,
		"kevaso unit": `systemctl list-units --plain --no-legend 'kevaso*' | wc -l`,
	} {
		got[k] = strings.TrimSpace(c.mustSh(script))
	}
	return got
}

func needReuse(t *testing.T) {
	t.Helper()
	if os.Getenv("KEVASO_METAL_REUSE") == "" {
		t.Skip("the long soak keeps its cluster between runs: set KEVASO_METAL_REUSE=1")
	}
}

func TestMetal2LongSoakSetup(t *testing.T) {
	needReuse(t)
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	c.apply("apiVersion: kevaso/v1\nkind: Namespace\nmetadata: { name: " + longSoakNS + " }\n")
	var o strings.Builder
	if code := kvoadm.Run(c.ctx, []string{"ingress", "install", "--host-port", "external", "--context", "metal2"}, strings.NewReader(""), &o, &o); code != 0 {
		t.Fatalf("kvoadm ingress install: exit %d\n%s", code, o.String())
	}
	c.waitRunning("kevaso-system", 10*time.Minute, "ingress-public")
	edge := c.silo("kevaso-system", "ingress-public").Status.Host
	ip := map[string]string{metalHost: p.m1.cfg.ExternalIP, metalHost2: p.m2.cfg.ExternalIP}[edge]
	name := "soak." + strings.ReplaceAll(ip, ".", "-") + ".sslip.io"
	ns := longSoakNS
	c.apply(vmEcho(ns, "vm", 8080) + on(metalHost2) + "  volumes: [{ name: data, size: 1Gi, mountPath: /data }]\n---\n" +
		boxEcho(ns, "app", 8080) + on(metalHost) + "  ports: [{ name: http, port: 8080 }]\n  service:\n    ports: [{ port: http }]\n---\n" +
		boxEcho(ns, "stops", 8080) + on(metalHost2) + "  availability: { onControlPlaneLoss: Stop, after: 2m }\n---\n" +
		boxEcho(ns, "leased", 18160) + on(metalHost) + "  ports: [{ name: debug, port: 18160 }]\n  service:\n    ports: [{ port: debug, hostPort: [external], lease: { max: 24h } }]\n---\n" +
		`apiVersion: kevaso/v1
kind: Issuer
metadata: { name: le-staging }
spec:
  acme:
    server: ` + letsEncryptStaging + `
    solvers: [{ http01: {} }]
---
apiVersion: kevaso/v1
kind: Ingress
metadata: { name: soak, namespace: ` + ns + ` }
spec:
  ingressClass: public
  hosts: [` + name + `]
  tls: { issuer: le-staging }
  rules: [{ path: /, service: { name: app, port: http } }]
`)
	c.waitRunning(ns, 20*time.Minute, longSoakSilos...)
	sum := strings.TrimSpace(func() string {
		out, code := c.in(ns, "vm", "head -c 33554432 /dev/urandom > /data/blob && sha256sum /data/blob | tee /data/blob.sha256 && sync")
		if code != 0 {
			t.Fatalf("checksum file: %d %s", code, out)
		}
		return out
	}())
	c.must("", "open", "silo", "leased", "-n", ns, "--port", "debug", "--for", "24h")
	leaseUntil := time.Now().Add(24 * time.Hour)
	c.eventually("a certificate from Let's Encrypt STAGING", 15*time.Minute, func() (bool, string) {
		out, _ := c.kvo("", "get", "certificate", "soak-tls", "-n", ns)
		return strings.Contains(out, " yes"), out
	})
	var expires time.Time
	c.eventually("443 serves it", 3*time.Minute, func() (bool, string) {
		leaf, err := servedCert(ip, name)
		if err != nil {
			return false, err.Error()
		}
		expires = leaf.NotAfter
		return strings.Contains(leaf.Issuer.String(), "STAGING"), leaf.Issuer.String()
	})
	time.Sleep(30 * time.Second) // settled: the baseline is what it holds at rest
	b := longSoak{Made: time.Now().UTC(), UIDs: map[string]string{}, Starts: p.startTimes(ns, longSoakSilos...), Checksum: sum,
		IngressHost: name, IngressIP: ip, CertExpires: expires, LeaseUntil: leaseUntil,
		Leaks: map[string]map[string]string{metalHost: p.longSoakLeaks(p.c1), metalHost2: p.longSoakLeaks(p.c2)}}
	for _, s := range longSoakSilos {
		b.UIDs[s] = c.silo(ns, s).UID
	}
	data, _ := json.MarshalIndent(b, "", "  ")
	if err := os.WriteFile(longSoakFile(p), data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("baseline in %s:\n%s", longSoakFile(p), data)
	for _, h := range []*mt{p.c1, p.c2} {
		t.Logf("listening on %s (all addresses or the external IP):\n%s", h.cfg.ExternalIP, externalListeners(h))
	}
}

func TestMetal2LongSoakCheck(t *testing.T) {
	needReuse(t)
	p := metal2(t)
	c := p.c1
	data, err := os.ReadFile(longSoakFile(p))
	if err != nil {
		t.Fatalf("no long soak to check (TestMetal2LongSoakSetup makes it): %v", err)
	}
	var b longSoak
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	t.Logf("the long soak made %s ago", time.Since(b.Made).Round(time.Minute))
	ns := longSoakNS
	// Every silo running, the same copy (never restarted), and exactly once across both hosts.
	for _, s := range longSoakSilos {
		cur := c.silo(ns, s)
		if cur.UID != b.UIDs[s] || cur.Status.Phase != "Running" {
			t.Errorf("%s: %s %s (was %s)", s, cur.UID, cur.Status.Phase, b.UIDs[s])
		}
		n := 0
		for _, h := range []*mt{p.c1, p.c2} {
			if cur.Spec.Runtime == "cloud-hypervisor" {
				unit := cloudhypervisor.NamesFor(kri.ID{Namespace: ns, Name: s, UID: cur.UID}).Unit
				if out, _ := h.sh("systemctl is-active " + unit); strings.TrimSpace(out) == "active" {
					n++
				}
				continue
			}
			out, _ := h.sh("docker ps -q --filter label=kevaso.com/uid=" + cur.UID + " --filter label=kevaso.com/name")
			n += len(strings.Fields(out))
		}
		if n != 1 {
			t.Errorf("%s runs %d times across the two machines, want once", s, n)
		}
	}
	sameStarts(t, "since the setup", b.Starts, p.startTimes(ns, longSoakSilos...))
	if out, code := c.in(ns, "vm", "cd /data && sha256sum -c blob.sha256"); code != 0 || !strings.Contains(out, "OK") {
		t.Errorf("the volume's checksum: %d %s", code, out)
	} else {
		t.Log("the volume's checksum file: OK")
	}
	if leaf, err := servedCert(b.IngressIP, b.IngressHost); err != nil {
		t.Errorf("443 on %s for %s: %v", b.IngressIP, b.IngressHost, err)
	} else if time.Now().After(leaf.NotAfter) || !strings.Contains(leaf.Issuer.String(), "STAGING") {
		t.Errorf("the certificate: issuer %s, valid until %s", leaf.Issuer, leaf.NotAfter)
	} else {
		t.Logf("the staging certificate is served, valid until %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if time.Now().Before(b.LeaseUntil.Add(-time.Minute)) {
		if ok, got := c.open(18160); !ok {
			t.Errorf("the lease (until %s) doesn't answer: %s", b.LeaseUntil.Format(time.RFC3339), got)
		}
	} else if ok, got := c.closed(18160); !ok {
		t.Errorf("the lease ended at %s and 18160 still answers: %s", b.LeaseUntil.Format(time.RFC3339), got)
	}
	for host, h := range map[string]*mt{metalHost: p.c1, metalHost2: p.c2} {
		now := p.longSoakLeaks(h)
		keys := make([]string, 0, len(now))
		for k := range now {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if now[k] != b.Leaks[host][k] {
				t.Errorf("%s: %s %s at the setup, %s now", host, k, b.Leaks[host][k], now[k])
			}
		}
	}
	for _, h := range []*mt{p.c1, p.c2} {
		t.Logf("listening on %s:\n%s", h.cfg.ExternalIP, externalListeners(h))
	}
}

// servedCert is the certificate 443 serves for name (staging roots are untrusted by design: the
// issuer is checked instead).
func servedCert(ip, name string) (*x509.Certificate, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", net.JoinHostPort(ip, "443"),
		&tls.Config{ServerName: name, InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate")
	}
	if err := certs[0].VerifyHostname(name); err != nil {
		return nil, err
	}
	return certs[0], nil
}

// externalListeners is what listens on a machine's external IP or on every address.
func externalListeners(h *mt) string {
	out, _ := h.sh(`ss -Htlnp | awk '{print $4, $6}' | grep -E '^(0\.0\.0\.0|\*|\[::\]|` + strings.ReplaceAll(h.cfg.ExternalIP, ".", `\.`) + `):' | sort -u`)
	return out
}
