package container

import (
	"context"
	"slices"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// K-105: a container silo whose state file can't be read isn't in List (no ID can be read from
// it), so the runtime names its file (Unreadable): the agent lists it on the Host, as something
// that may run.
func TestAnUnreadableStateIsNamedThoughNotListed(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := runtime(t, f)
	if err := r.Create(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	if got := r.Unreadable(ctx); len(got) != 0 {
		t.Fatalf("its state is readable, yet Unreadable names %v", got)
	}
	f.files[statePath(silo)] = []byte(`{"id": `)
	if ids, _ := r.List(ctx); len(ids) != 0 {
		t.Fatalf("List: %v", ids)
	}
	if got := r.Unreadable(ctx); !slices.Equal(got, []string{statePath(silo)}) {
		t.Fatalf("Unreadable: %v, want %s", got, statePath(silo))
	}
	if st, err := r.Status(ctx, silo); err != nil || st.State != kri.Running {
		t.Fatalf("Status %s %v: its main container runs", st.State, err)
	}
}
