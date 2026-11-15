package agent

import (
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/sdk/kri"
)

// From the Linodes (linode-3.md, core finding 8): two kept copies of one name were listed alike,
// "ha-f/late (docker), ha-f/late (docker)". Each is listed with the start of its UID.
func TestKeptCopiesOfOneNameAreToldApart(t *testing.T) {
	g := newGuardRig(t, nil, nil)
	if err := g.c.Create(g.ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv1"},
		Spec: v1.HostSpec{InternalIP: "10.0.0.1", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
		t.Fatal(err)
	}
	for _, uid := range []string{"1111aaaa-0000-0000-0000-000000000000", "2222bbbb-0000-0000-0000-000000000000"} {
		if err := g.rt.Create(g.ctx, kri.Spec{ID: kri.ID{Namespace: "dev", Name: "late", UID: uid}, Image: "ubuntu-24.04"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.a.removeEverywhere(g.ctx, engine.Key{Kind: "Silo", Namespace: "dev", Name: "late"}, nil); err != nil {
		t.Fatal(err)
	}
	g.a.reportKept(g.ctx, "")
	var h v1.Host
	if err := g.c.Get(g.ctx, "Host", "", "hv1", &h); err != nil {
		t.Fatal(err)
	}
	c := meta.FindCondition(h.Status.Conditions, ConditionKeptSilos)
	if c == nil || !strings.Contains(c.Message, "1111aaaa") || !strings.Contains(c.Message, "2222bbbb") {
		t.Fatalf("the two kept copies of dev/late can't be told apart: %+v", c)
	}
}
