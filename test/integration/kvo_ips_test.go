package integration

import (
	"strings"
	"testing"
)

// kvo's IP commands against the API server (no controllers: the address stays empty): create,
// get, keep and release, describe; and the example of design §7.2c-1 applies as written.
func TestKvoIPs(t *testing.T) {
	h := newHarness(t)
	h.ok(manifest, "apply", "-f", "-")
	if out := h.ok("", "create", "ip", "eth", "--class", "ip-pool", "--host", "hv1", "-n", "demo"); !strings.Contains(out, "ip/eth created") {
		t.Fatalf("create ip: %s", out)
	}
	if _, errs, code := h.kvo(t.Context(), "", "create", "ip", "nope", "-n", "demo"); code == 0 || !strings.Contains(errs, "--class") {
		t.Fatalf("create ip without a class: %d %s", code, errs)
	}
	out := h.ok("", "get", "ips", "-n", "demo")
	for _, want := range []string{"ADDRESS", "CLASS", "HELD-BY", "KEPT", "eth", "ip-pool", "yes"} {
		if !strings.Contains(out, want) {
			t.Fatalf("get ips lacks %q:\n%s", want, out)
		}
	}
	if out := h.ok("", "ip", "keep", "eth", "-n", "demo"); !strings.Contains(out, "kept already") {
		t.Fatalf("keep a kept one: %s", out)
	}
	if out := h.ok("", "describe", "ip", "eth", "-n", "demo"); !strings.Contains(out, "Kept:") || !strings.Contains(out, "reclaim Retain") || !strings.Contains(out, "Held by:") {
		t.Fatalf("describe ip:\n%s", out)
	}
	// Released while nobody holds it: it's deleted.
	if out := h.ok("", "ip", "release", "eth", "-n", "demo"); !strings.Contains(out, "nothing held it") {
		t.Fatalf("release: %s", out)
	}
	if out := h.ok("", "get", "ips", "-n", "demo"); strings.Contains(out, "eth") {
		t.Fatalf("released IP still there:\n%s", out)
	}
	// The design's example applies: an IP and a silo naming it.
	h.ok(`apiVersion: kevaso/v1
kind: IP
metadata: { name: eth-node-1, namespace: demo }
spec: { class: linode-shared-ip, region: ca-central, reclaim: Retain }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: eth-node-1, namespace: demo }
spec:
  runtime: cloud-hypervisor
  image: ubuntu-24.04
  resources: { cpu: 2, memory: 4Gi }
  service:
    ports: [{ name: p2p, port: 30303 }]
    expose: loadBalancer
    loadBalancer: { class: linode-shared-ip, ip: eth-node-1 }
  network: { egress: { source: sameAsService } }
`, "apply", "-f", "-")
	if out := h.ok("", "describe", "silo", "eth-node-1", "-n", "demo"); !strings.Contains(out, "In and out:") {
		t.Fatalf("describe silo:\n%s", out)
	}
	// A silo naming an IP of another class is refused.
	if _, errs, code := h.kvo(t.Context(), `apiVersion: kevaso/v1
kind: Silo
metadata: { name: other, namespace: demo }
spec:
  runtime: cloud-hypervisor
  image: ubuntu-24.04
  resources: { cpu: 2, memory: 4Gi }
  service:
    ports: [{ name: p2p, port: 30303 }]
    expose: loadBalancer
    loadBalancer: { class: ip-pool, ip: eth-node-1 }
`, "apply", "-f", "-"); code == 0 || !strings.Contains(errs, "class linode-shared-ip, not ip-pool") {
		t.Fatalf("naming an IP of another class: %d %s", code, errs)
	}
}
