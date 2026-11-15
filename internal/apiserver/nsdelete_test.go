package apiserver_test

import (
	"net/http"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Deleting a Namespace while it holds anything is refused (audit checkpoint 4, deletes and data):
// deleting it left its silos running, with no namespace to name them by. The refusal says what is
// in it, counted per kind with the first few names, and what to do instead.
func TestANamespaceThatHoldsAnythingIsNotDeleted(t *testing.T) {
	e := setupAuth(t)
	if err := e.admin.Create(e.ctx, ns("shop")); err != nil {
		t.Fatal(err)
	}
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	for _, n := range []string{"web-a", "web-b", "web-c", "web-d"} {
		if err := e.admin.Create(e.ctx, &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: n, Namespace: "shop"},
			Spec: v1.SiloSpec{Runtime: "cloud-hypervisor"}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.admin.Create(e.ctx, &v1.ServiceAccount{TypeMeta: tm("ServiceAccount"), ObjectMeta: meta.ObjectMeta{Name: "ci", Namespace: "shop"}}); err != nil {
		t.Fatal(err)
	}
	err := e.admin.Delete(e.ctx, "Namespace", "", "shop")
	if code(err) != http.StatusConflict {
		t.Fatalf("deleting a namespace that holds 4 silos and a service account: %v, want 409", err)
	}
	msg := err.(*client.Error).Message
	for _, want := range []string{"4 Silo (web-a, web-b, web-c, …)", "1 ServiceAccount (ci)", "kvo delete", "-n shop"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal %q doesn't say %q", msg, want)
		}
	}
	if err := e.admin.Get(e.ctx, "Namespace", "", "shop", &v1.Namespace{}); err != nil {
		t.Fatalf("the namespace is gone: %v", err)
	}
	// Emptied, it goes.
	for _, n := range []string{"web-a", "web-b", "web-c", "web-d"} {
		if err := e.admin.Delete(e.ctx, "Silo", "shop", n); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.admin.Delete(e.ctx, "ServiceAccount", "shop", "ci"); err != nil {
		t.Fatal(err)
	}
	if err := e.admin.Delete(e.ctx, "Namespace", "", "shop"); err != nil {
		t.Fatalf("deleting an empty namespace: %v", err)
	}
}
