package agent

import (
	"context"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// A copy listed as kept while the control plane didn't know it (a system node behind, a cache
// from one) that the control plane places here again is no longer kept: it left KeptSilos
// listing a silo the control plane knows and runs here.
func TestACopyKnownAgainIsNoLongerListedAsKept(t *testing.T) {
	ctx := context.Background()
	rt := fake.New()
	id := kri.ID{Namespace: "dev", Name: "single", UID: "u1"}
	if err := rt.Create(ctx, kri.Spec{ID: id, Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	a := &Agent{HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}}
	a.keptNoted.Store(id.UID, keptCopy{runtime: "docker", name: keptName(id, "fake")})
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "single", UID: "u1"}, Status: v1.SiloStatus{Host: "hv1"}}
	if err := a.removeEverywhere(ctx, engine.Key{Kind: "Silo", Namespace: "dev", Name: "single"}, s); err != nil {
		t.Fatal(err)
	}
	if v, ok := a.keptNoted.Load(id.UID); ok {
		t.Fatalf("still listed as kept, though placed here and known: %v", v)
	}
}
