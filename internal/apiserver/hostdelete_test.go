package apiserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// Deleting a Host that still has silos needs ?confirmOff=true. One with none deletes as before.
func TestHostDeleteNeedsConfirmOffWhenSilosRemain(t *testing.T) {
	ctx := context.Background()
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	if err := c.Create(ctx, ns("dev")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hv1", "hv2", "empty"} {
		if err := c.Create(ctx, host(name)); err != nil {
			t.Fatal(err)
		}
	}
	put := func(name, on, from string) {
		t.Helper()
		s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}}}
		if err := c.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		s.Status.Host, s.Status.MovingFrom = on, from
		if err := c.UpdateStatus(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	put("on", "hv1", "")
	put("from", "hv2", "hv1")

	err = c.Delete(ctx, "Host", "", "hv1")
	if code(err) != http.StatusConflict || !strings.Contains(err.Error(), "confirmOff=true") || !strings.Contains(err.Error(), "2 silo") {
		t.Fatalf("delete without confirmation: %v", err)
	}
	var still v1.Host
	if err := c.Get(ctx, "Host", "", "hv1", &still); err != nil {
		t.Fatalf("the host was deleted: %v", err)
	}
	if err := c.Delete(ctx, "Host", "", "hv1", client.Precondition{ConfirmOff: true}); err != nil {
		t.Fatalf("delete with confirmation: %v", err)
	}
	if err := c.Get(ctx, "Host", "", "hv1", &still); !client.IsNotFound(err) {
		t.Fatalf("hv1 after a confirmed delete: %v", err)
	}
	if err := c.Delete(ctx, "Host", "", "empty"); err != nil {
		t.Fatalf("a host with no silos, no confirmation: %v", err)
	}
}
