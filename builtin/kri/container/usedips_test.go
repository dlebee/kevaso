package container

import (
	"context"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// K-105's shape in the container runtime: a silo whose state file can't be read is never made
// again over it (its file, with its address, written over, while its containers may run), and no
// other silo is given an address while that file holds one nobody can tell.
func TestAnUnreadableStateIsNeitherMadeOverNorItsAddressGivenOut(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := runtime(t, f)
	if err := r.Create(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	broken := []byte(`{"id": `)
	f.files[statePath(silo)] = broken
	if err := r.Create(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"}); err == nil {
		t.Fatal("made again over its unreadable state")
	}
	if string(f.files[statePath(silo)]) != string(broken) {
		t.Fatalf("its unreadable state was written over: %s", f.files[statePath(silo)])
	}
	other := kri.ID{Namespace: "shop", Name: "web", UID: "u2"}
	err := r.Create(ctx, kri.Spec{ID: other, Image: "ubuntu-24.04"})
	if err == nil || !strings.Contains(err.Error(), statePath(silo)) {
		t.Fatalf("another silo's Create with %s unreadable: %v, want a refusal naming it", statePath(silo), err)
	}
}
