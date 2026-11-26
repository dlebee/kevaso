package integration

import (
	"strings"
	"testing"
)

// kvo's IP commands against the API server (no controllers: the address stays empty): create,
// get, describe and delete; keep and release are gone; and the example of networking v2 applies
// as written.
func TestKvoIPs(t *testing.T) {
	h := newHarness(t)
	h.ok(manifest, "apply", "-f", "-")
	if out := h.ok("", "create", "ip", "eth", "--type", "Host", "--host-address", "eth-extra", "-n", "demo"); !strings.Contains(out, "ip/eth created") {
		t.Fatalf("create ip: %s", out)
	}
	if _, errs, code := h.kvo(t.Context(), "", "create", "ip", "nope", "-n", "demo"); code == 0 || !strings.Contains(errs, "--type") {
		t.Fatalf("create ip without a type: %d %s", code, errs)
	}
	out := h.ok("", "get", "ips", "-n", "demo")
	for _, want := range []string{"TYPE", "ADDRESS", "WHERE", "SET", "USED BY", "MOVES", "eth", "Host", "no: pinned to its host"} {
		if !strings.Contains(out, want) {
			t.Fatalf("get ips lacks %q:\n%s", want, out)
		}
	}
	if _, errs, code := h.kvo(t.Context(), "", "ip", "keep", "eth", "-n", "demo"); code == 0 || !strings.Contains(errs, "no keep or release") {
		t.Fatalf("kvo ip keep: %d %s", code, errs)
	}
	if out := h.ok("", "describe", "ip", "eth", "-n", "demo"); !strings.Contains(out, "Host (host address eth-extra)") || !strings.Contains(out, "Used by:") {
		t.Fatalf("describe ip:\n%s", out)
	}
	// A balancer can't answer on a host's address.
	if _, errs, code := h.kvo(t.Context(), `apiVersion: kevaso/v1
kind: Silo
metadata: { name: other, namespace: demo }
spec:
  runtime: cloud-hypervisor
  vm: { image: ubuntu-24.04 }
  resources: { cpu: 2, memory: 4Gi }
  ports: [{ name: p2p, port: 30303 }]
  services:
    - type: LoadBalancer
      loadBalancer: { provider: linode, ip: eth }
      ports: [{ port: p2p }]
`, "apply", "-f", "-"); code == 0 || !strings.Contains(errs, "is a host's address (type Host)") {
		t.Fatalf("a balancer on a Host IP: %d %s", code, errs)
	}
	h.ok("", "delete", "ip", "eth", "-n", "demo")
	if out := h.ok("", "get", "ips", "-n", "demo"); strings.Contains(out, "eth") {
		t.Fatalf("deleted IP still there:\n%s", out)
	}
	// The design's example applies: an IP and a silo naming it, in and out.
	h.ok(`apiVersion: kevaso/v1
kind: IP
metadata: { name: eth-node-1, namespace: demo }
spec: { type: Provider, provider: linode, region: ca-central }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: eth-node-1, namespace: demo }
spec:
  runtime: cloud-hypervisor
  vm: { image: ubuntu-24.04 }
  resources: { cpu: 2, memory: 4Gi }
  ports: [{ name: p2p, port: 30303 }]
  services:
    - type: HostPort
      hostPort: { ip: eth-node-1 }
      ports: [{ port: p2p }]
  network: { egress: { source: { ip: eth-node-1 } } }
`, "apply", "-f", "-")
	if out := h.ok("", "describe", "silo", "eth-node-1", "-n", "demo"); !strings.Contains(out, "In and out:") || !strings.Contains(out, "(ip: eth-node-1)") ||
		!strings.Contains(out, "Can move:") || !strings.Contains(out, "ip: eth-node-1") {
		t.Fatalf("describe silo:\n%s", out)
	}
}
