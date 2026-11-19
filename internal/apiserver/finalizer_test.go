package apiserver

import (
	"context"
	"encoding/json"
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

// A kevaso.com finalizer stays until kevasod removes it, before the delete and during it.
// The admin socket may clear a stuck one. A cluster-admin user may not. A finalizer that is
// not the controller's, and kevaso.com/plugin-uninstall, still go when that user removes them.
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
	user, doneUser := srv.InProcessAs(pki.Identity{Type: "user", Name: "ada", Role: "cluster-admin"})
	defer doneUser()
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

	early := silo("early", "kevaso.com/volumes")
	if err := comp.Create(ctx, early); err != nil {
		t.Fatal(err)
	}
	if err := comp.Get(ctx, "Silo", "d", "early", early); err != nil {
		t.Fatal(err)
	}
	if err := clear(user, early); codeOf(err) != http.StatusForbidden || !strings.Contains(err.Error(), "kevaso.com/volumes") {
		t.Fatalf("before delete: %v, want 403", err)
	}
	if err := comp.Get(ctx, "Silo", "d", "early", early); err != nil || len(early.Finalizers) != 1 || early.DeletionTimestamp != nil {
		t.Fatalf("still held before delete: %v %+v", err, early.Finalizers)
	}
	if err := clear(admin, early); err != nil {
		t.Fatalf("admin socket before delete: %v", err)
	}
	if err := comp.Get(ctx, "Silo", "d", "early", early); err != nil || len(early.Finalizers) != 0 || early.DeletionTimestamp != nil {
		t.Fatalf("admin cleared it before delete: %v finalizers %v timestamp %v", err, early.Finalizers, early.DeletionTimestamp)
	}

	volumes := hold("db", "kevaso.com/volumes")
	if err := clear(user, volumes); codeOf(err) != http.StatusForbidden || !strings.Contains(err.Error(), "kevaso.com/volumes") {
		t.Fatalf("cluster-admin removing kevaso.com/volumes: %v, want 403", err)
	}
	if err := comp.Get(ctx, "Silo", "d", "db", volumes); err != nil || len(volumes.Finalizers) != 1 || volumes.Finalizers[0] != "kevaso.com/volumes" {
		t.Fatalf("after the refused removal: %v %+v", err, volumes.Finalizers)
	}
	if err := clear(admin, volumes); err != nil {
		t.Fatalf("admin socket during delete: %v", err)
	}
	if err := comp.Get(ctx, "Silo", "d", "db", volumes); !client.IsNotFound(err) {
		t.Fatalf("after the admin socket removed the finalizer: %v", err)
	}

	own := hold("own", "acme.dev/hold")
	if err := clear(user, own); err != nil {
		t.Fatal(err)
	}
	if err := comp.Get(ctx, "Silo", "d", "own", own); !client.IsNotFound(err) {
		t.Fatalf("a finalizer that is not the controller's: %v", err)
	}

	plug := hold("plug", v1.PluginFinalizer)
	if err := clear(user, plug); err != nil {
		t.Fatalf("removing %s: %v", v1.PluginFinalizer, err)
	}
	if err := comp.Get(ctx, "Silo", "d", "plug", plug); !client.IsNotFound(err) {
		t.Fatalf("after removing %s: %v", v1.PluginFinalizer, err)
	}
}

func TestADefinedKindFinalizerStaysUntilItsControllerRemovesIt(t *testing.T) {
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
	user, doneUser := srv.InProcessAs(pki.Identity{Type: "user", Name: "ada", Role: "cluster-admin"})
	defer doneUser()
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	if err := comp.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}); err != nil {
		t.Fatal(err)
	}
	d := &v1.KindDefinition{TypeMeta: tm("KindDefinition"), ObjectMeta: meta.ObjectMeta{Name: "databases.acme.dev"},
		Spec: v1.KindDefinitionSpec{Group: "acme.dev", Version: "v1", Scope: v1.Namespaced,
			Names: v1.KindNames{Kind: "Database", Plural: "databases"}}}
	if err := json.Unmarshal([]byte(`{"type":"object","properties":{"spec":{"type":"object"}}}`), &d.Spec.Schema); err != nil {
		t.Fatal(err)
	}
	if err := comp.Create(ctx, d); err != nil {
		t.Fatal(err)
	}
	o := &v1.Unstructured{TypeMeta: meta.TypeMeta{APIVersion: "acme.dev/v1", Kind: "Database"},
		ObjectMeta: meta.ObjectMeta{Name: "main", Namespace: "d", Finalizers: []string{"kevaso.com/db"}},
		Fields:     map[string]any{"spec": map[string]any{}}}
	if err := comp.Create(ctx, o); err != nil {
		t.Fatal(err)
	}
	if err := comp.Get(ctx, "Database", "d", "main", o); err != nil {
		t.Fatal(err)
	}
	o.Finalizers = nil
	if err := user.Update(ctx, o); codeOf(err) != http.StatusForbidden || !strings.Contains(err.Error(), "kevaso.com/db") {
		t.Fatalf("before delete: %v, want 403", err)
	}
	if err := comp.Get(ctx, "Database", "d", "main", o); err != nil || len(o.Finalizers) != 1 || o.Finalizers[0] != "kevaso.com/db" {
		t.Fatalf("still held: %v %+v", err, o.Finalizers)
	}
}
