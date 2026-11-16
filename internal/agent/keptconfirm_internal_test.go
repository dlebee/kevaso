package agent

import (
	"testing"

	"kevaso.com/core/internal/engine"
	"kevaso.com/core/sdk/kri"
)

// A person confirmed removal of a kept copy, and the store then places that same copy here.
// The confirmation was for a copy the control plane didn't have. Once the store places it here,
// that confirmation is finished: a later loss of the silo, with no delete seen here, keeps the copy.
func TestAConfirmedRemovalIsDroppedOnceTheStorePlacesTheCopyHere(t *testing.T) {
	for _, cache := range []string{"behind", "placed here"} {
		t.Run(cache, func(t *testing.T) {
			g := newGuardRig(t, nil, nil)
			s := g.create(guardSilo("single", nil), "hv1", "")
			id := idOf(s)
			if err := g.rt.Create(g.ctx, kri.Spec{ID: id, Image: "ubuntu-24.04"}); err != nil {
				t.Fatal(err)
			}
			if err := g.rt.Start(g.ctx, id); err != nil {
				t.Fatal(err)
			}
			g.a.removeConfirmed.Store(id.UID, id)
			key := engine.Key{Kind: "Silo", Namespace: "dev", Name: "single"}
			if cache == "behind" {
				stale := *s
				stale.Status.Host = "hv2"
				g.cacheIs(&stale)
				if _, err := g.reconcile("single"); err != nil {
					t.Fatal(err)
				}
			} else if err := g.a.removeEverywhere(g.ctx, key, s); err != nil {
				t.Fatal(err)
			}
			if st, _ := g.rt.Status(g.ctx, id); st.State == kri.Absent {
				t.Fatal("the copy was removed while the store places it here")
			}
			if err := g.c.Delete(g.ctx, "Silo", "dev", "single"); err != nil {
				t.Fatal(err)
			}
			g.a.silos.Seed(nil)
			if _, err := g.reconcile("single"); err != nil {
				t.Fatal(err)
			}
			if st, _ := g.rt.Status(g.ctx, id); st.State == kri.Absent {
				t.Fatal("after the store lost the silo, the old confirmation removed the copy")
			}
		})
	}
}
