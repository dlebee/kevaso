package worker

import (
	"os"
	"path/filepath"
	"testing"

	"kevaso.com/core/api/informer"
)

// Review claim D (network lane; host-code.md has the fix): a kept last state that is there but
// says nothing of a kind the network caches ({} after a power cut, a file from a build that kept
// fewer kinds) must not seed that kind as empty and ready: the first pass would install that
// view, closing every running silo's ports at a start without the control plane. Such a file is
// no last state: the worker waits for the control plane, as on a first start.
func TestALastStateMissingAKindSeedsNothing(t *testing.T) {
	t.Skip("review claim D, network lane: seedLastState accepts a file missing kinds (host-code.md, \"Claim D\")")
	for name, body := range map[string]string{
		"empty object":  `{}`,
		"a kind absent": `{"Silo":[]}`,
		"a kind null":   `{"Silo":[],"Service":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), LastStateFile)
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			silos, services := informer.New(nil, "Silo"), informer.New(nil, "Service")
			if seedLastState(p, silos, services) {
				t.Fatal("seeded from a last state that doesn't hold every kind: its view would be installed as the truth")
			}
		})
	}
	p := filepath.Join(t.TempDir(), LastStateFile)
	if err := os.WriteFile(p, []byte(`{"Silo":[],"Service":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !seedLastState(p, informer.New(nil, "Silo"), informer.New(nil, "Service")) {
		t.Fatal("a whole last state (every kind listed, some empty) is a last state")
	}
}
