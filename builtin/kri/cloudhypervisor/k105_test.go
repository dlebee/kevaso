package cloudhypervisor

import (
	"context"
	"slices"
	"testing"
)

// K-105: a VM whose state file can't be read isn't in List (no ID can be read from it), so the
// runtime names its file (Unreadable): the agent lists it on the Host, as something that may run.
func TestAnUnreadableStateIsNamedThoughNotListed(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	r := newRuntime(t, h)
	for _, name := range []string{"web", "db"} {
		if err := r.Create(ctx, spec(name)); err != nil {
			t.Fatal(err)
		}
	}
	if got := r.Unreadable(ctx); len(got) != 0 {
		t.Fatalf("every state is readable, yet Unreadable names %v", got)
	}
	bad := NamesFor(spec("web").ID).Dir + "/silo.json"
	h.files[bad] = []byte(`{"id": `)
	ids, err := r.List(ctx)
	if err != nil || len(ids) != 1 || ids[0] != spec("db").ID {
		t.Fatalf("List: %v %v", ids, err)
	}
	if got := r.Unreadable(ctx); !slices.Equal(got, []string{bad}) {
		t.Fatalf("Unreadable: %v, want %s", got, bad)
	}
}
