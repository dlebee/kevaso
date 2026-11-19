package apiserver

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/store"
)

// Saying the old copy is off is a cluster permission of its own. editor and admin can move a
// silo. They cannot pass --confirm-fenced or --insist. cluster-admin can. The refusal names the
// permission.
func TestConfirmFencedNeedsItsOwnPermission(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory(0)
	srv, err := NewWithAuth(st, clock.Real{}, &Auth{CA: ca})
	if err != nil {
		t.Fatal(err)
	}
	comp, done := srv.InProcess()
	defer done()
	ed, doneEd := srv.InProcessAs(pki.Identity{Type: "user", Name: "ed", Role: "member"})
	defer doneEd()
	ad, doneAd := srv.InProcessAs(pki.Identity{Type: "user", Name: "ad", Role: "member"})
	defer doneAd()
	root, doneRoot := srv.InProcessAs(pki.Identity{Type: "user", Name: "root", Role: "cluster-admin"})
	defer doneRoot()

	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(comp.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "shop"}}))
	must(comp.Create(ctx, &v1.RoleBinding{TypeMeta: tm("RoleBinding"), ObjectMeta: meta.ObjectMeta{Name: "ed", Namespace: "shop"},
		RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "editor"}, Subjects: []v1.Subject{{Kind: "User", Name: "ed"}}}))
	must(comp.Create(ctx, &v1.RoleBinding{TypeMeta: tm("RoleBinding"), ObjectMeta: meta.ObjectMeta{Name: "ad", Namespace: "shop"},
		RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "admin"}, Subjects: []v1.Subject{{Kind: "User", Name: "ad"}}}))
	now := time.Now().UTC()
	for _, n := range []string{"hv1", "hv2"} {
		h := &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: n},
			Spec: v1.HostSpec{InternalIP: "10.0.0." + n[len(n)-1:], Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}}}
		must(comp.Create(ctx, h))
		h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
		h.Status.Allocatable = v1.Resources{CPU: 4, Memory: "8Gi"}
		h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionTrue, LastTransitionTime: now}}
		must(comp.UpdateStatus(ctx, h))
	}
	place := func(name string) {
		t.Helper()
		s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "shop"},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
				Availability: v1.Availability{OnHostLoss: "Recreate"}}}
		must(comp.Create(ctx, s))
		s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
		must(comp.UpdateStatus(ctx, s))
	}
	place("web")
	place("other")

	move := func(c *client.Client, name string, fenced, insist bool) error {
		t.Helper()
		var out v1.Silo
		return c.Call(ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/shop/silos/"+name+"/move",
			moves.Request{To: "hv2", Recreate: true, ConfirmFenced: fenced, Insist: insist}, &out)
	}
	for _, c := range []struct {
		name string
		c    *client.Client
	}{{"editor", ed}, {"admin", ad}} {
		err := move(c.c, "web", true, false)
		if codeOf(err) != http.StatusForbidden || !strings.Contains(err.Error(), "hosts/confirm-off") || !strings.Contains(err.Error(), "silos/move") {
			t.Fatalf("%s --confirm-fenced: %v, want 403 naming hosts/confirm-off and silos/move", c.name, err)
		}
		err = move(c.c, "web", false, true)
		if codeOf(err) != http.StatusForbidden || !strings.Contains(err.Error(), "hosts/confirm-off") {
			t.Fatalf("%s --insist: %v, want 403 naming hosts/confirm-off", c.name, err)
		}
	}
	if err := move(ed, "web", false, false); err != nil {
		t.Fatalf("an editor's plain move: %v", err)
	}
	if err := move(root, "other", true, false); err != nil {
		t.Fatalf("cluster-admin --confirm-fenced: %v", err)
	}
}
