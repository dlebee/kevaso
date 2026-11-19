package apiserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/store"
)

// A kevaso.com finalizer on a deleting object stays until kevasod removes it. The admin socket,
// which may update the object, cannot. A finalizer that is not the controller's, and
// kevaso.com/plugin-uninstall, still go when that writer removes them.
func TestAControllerFinalizerStaysUntilItsControllerRemovesIt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewWithAuth(store.NewMemory(0), clock.Real{}, &Auth{CA: ca})
	if err != nil {
		t.Fatal(err)
	}
	comp, done := srv.InProcess()
	defer done()
	as := httptest.NewUnstartedServer(srv)
	as.Config = srv.HTTPServer(true)
	as.Start()
	defer as.Close()
	admin := client.New(as.URL)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	if err := comp.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}); err != nil {
		t.Fatal(err)
	}
	silo := func(name, finalizer string) *v1.Silo {
		return &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "d", Finalizers: []string{finalizer}},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"}}}
	}
	hold := func(name, finalizer string) *v1.Silo {
		t.Helper()
		s := silo(name, finalizer)
		if err := comp.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		if err := comp.Delete(ctx, "Silo", "d", name); err != nil {
			t.Fatal(err)
		}
		if err := comp.Get(ctx, "Silo", "d", name, s); err != nil || s.DeletionTimestamp == nil {
			t.Fatalf("%s after delete: %v timestamp %v", name, err, s.DeletionTimestamp)
		}
		return s
	}
	clear := func(c *client.Client, s *v1.Silo) error {
		t.Helper()
		s.Finalizers = nil
		return c.Update(ctx, s)
	}

	volumes := hold("db", "kevaso.com/volumes")
	if err := clear(admin, volumes); codeOf(err) != http.StatusForbidden || !strings.Contains(err.Error(), "kevaso.com/volumes") {
		t.Fatalf("admin socket removing kevaso.com/volumes: %v, want 403", err)
	}
	if err := comp.Get(ctx, "Silo", "d", "db", volumes); err != nil || len(volumes.Finalizers) != 1 || volumes.Finalizers[0] != "kevaso.com/volumes" {
		t.Fatalf("after the refused removal: %v %+v", err, volumes.Finalizers)
	}
	if err := clear(comp, volumes); err != nil {
		t.Fatal(err)
	}
	if err := comp.Get(ctx, "Silo", "d", "db", volumes); !client.IsNotFound(err) {
		t.Fatalf("after the controller removed the finalizer: %v", err)
	}

	own := hold("own", "acme.dev/hold")
	if err := clear(admin, own); err != nil {
		t.Fatal(err)
	}
	if err := comp.Get(ctx, "Silo", "d", "own", own); !client.IsNotFound(err) {
		t.Fatalf("a finalizer that is not the controller's: %v", err)
	}

	plug := hold("plug", v1.PluginFinalizer)
	if err := clear(admin, plug); err != nil {
		t.Fatalf("removing %s: %v", v1.PluginFinalizer, err)
	}
	if err := comp.Get(ctx, "Silo", "d", "plug", plug); !client.IsNotFound(err) {
		t.Fatalf("after removing %s: %v", v1.PluginFinalizer, err)
	}
}
