package container

import (
	"context"
	"errors"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// K-094: a silo whose state file can't be read is never taken for absent: Status doesn't say
// "not here" (a fence would count it stopped) and Kill still kills it, by its names.
func TestAnUnreadableStateIsNotAnAbsentSilo(t *testing.T) {
	for _, engine := range []string{"docker", "podman"} {
		t.Run(engine, func(t *testing.T) {
			ctx := context.Background()
			f := newFake()
			r := runtime(t, f)
			r.Engine = engine
			if err := r.Create(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"}); err != nil {
				t.Fatal(err)
			}
			if err := r.Start(ctx, silo); err != nil {
				t.Fatal(err)
			}
			f.files[statePath(silo)] = []byte("{\"id\": ") // a power cut mid-write
			st, err := r.Status(ctx, silo)
			if err == nil && st.State != kri.Running {
				t.Fatalf("its main container runs, its state is unreadable: Status %s", st.State)
			}
			err = kri.Kill(ctx, r, silo)
			if errors.Is(err, kri.ErrNotFound) {
				t.Fatalf("Kill: %v: a fence would count it stopped", err)
			}
			n := NamesFor(silo)
			if f.containers[n.Main] == "running" {
				t.Fatalf("Kill left its main container running (%v)", err)
			}
			if st, err := r.Status(ctx, silo); err == nil && (st.State == kri.Absent || st.State == kri.Running) {
				t.Fatalf("after the kill, Status %s: neither absent nor running, it is there and stopped", st.State)
			}
		})
	}
}
