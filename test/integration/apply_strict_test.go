package integration

import (
	"context"
	"strings"
	"testing"
)

// A misspelled field is refused, never dropped: the server decodes strictly, and kvo apply must
// not lose the field on its way there (a silo whose "allowfrom" vanished would be reachable by
// nobody, or one whose "sources" vanished by everybody).
func TestApplyRefusesUnknownFields(t *testing.T) {
	h := newHarness(t)
	h.ok("apiVersion: kevaso/v1\nkind: Namespace\nmetadata: { name: demo }\n", "apply", "-f", "-")
	for name, doc := range map[string]string{
		"spec": `apiVersion: kevaso/v1
kind: Silo
metadata: { name: typo, namespace: demo }
spec:
  runtime: docker
  container: { image: nginx:1.27 }
  ports: [{ name: web, port: 80 }]
  servce: { ports: [{ port: web, hostPort: [external] }] }
`,
		"nested": `apiVersion: kevaso/v1
kind: Silo
metadata: { name: typo, namespace: demo }
spec:
  runtime: docker
  container: { image: nginx:1.27 }
  ports: [{ name: web, port: 80 }]
  service: { ports: [{ port: web, hostPort: [external], source: [10.0.0.0/8] }] }
`,
		"metadata": `apiVersion: kevaso/v1
kind: Namespace
metadata: { name: other, lables: { a: b } }
`,
	} {
		t.Run(name, func(t *testing.T) {
			_, errs, code := h.kvo(context.Background(), doc, "apply", "-f", "-")
			if code == 0 || !strings.Contains(errs, "unknown field") {
				t.Fatalf("apply with a misspelled field: exit %d, %q; want a refusal naming the unknown field", code, errs)
			}
		})
	}
}
