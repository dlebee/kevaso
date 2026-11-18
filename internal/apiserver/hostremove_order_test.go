package apiserver_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// orderStore notes whether a silo list happens after the host's removal record exists.
type orderStore struct {
	store.Store
	removalBeforeList bool
}

func (o *orderStore) List(ctx context.Context, sel store.Selector) ([]store.Object, int64, error) {
	if sel.Kind == "Silo" {
		_, err := o.Get(ctx, store.Key{Kind: "HostRemoval", Name: "hv1"})
		if err == nil {
			o.removalBeforeList = true
		}
	}
	return o.Store.List(ctx, sel)
}

// A refused host delete records the removal before it counts silos, and puts that record back
// when the delete is refused. A record left by a host that joined again keeps its serials.
func TestHostDeleteRecordsRemovalBeforeItCountsSilos(t *testing.T) {
	ctx := context.Background()
	mem := store.NewMemory(0)
	ord := &orderStore{Store: mem}
	srv, err := apiserver.New(ord, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	if err := c.Create(ctx, ns("dev")); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(ctx, host("hv1")); err != nil {
		t.Fatal(err)
	}
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host = "hv1"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}

	err = c.Delete(ctx, "Host", "", "hv1")
	if code(err) != 409 {
		t.Fatalf("delete: %v", err)
	}
	if !ord.removalBeforeList {
		t.Fatal("the silos were counted before the removal was recorded")
	}
	if _, err := mem.Get(ctx, store.Key{Kind: "HostRemoval", Name: "hv1"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the removal record after a refused delete: %v", err)
	}
	var still v1.Host
	if err := c.Get(ctx, "Host", "", "hv1", &still); err != nil {
		t.Fatalf("the host was deleted: %v", err)
	}
}

func TestRefusedHostDeleteKeepsARejoinRecord(t *testing.T) {
	ctx := context.Background()
	mem := store.NewMemory(0)
	prev := []byte(`{"removedAt":"2020-01-01T00:00:00Z","serials":["abc"]}`)
	if _, err := mem.Create(ctx, store.Key{Kind: "HostRemoval", Name: "hv1"}, prev); err != nil {
		t.Fatal(err)
	}
	srv, err := apiserver.New(mem, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	if err := c.Create(ctx, ns("dev")); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(ctx, host("hv1")); err != nil {
		t.Fatal(err)
	}
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host = "hv1"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	if code(c.Delete(ctx, "Host", "", "hv1")) != 409 {
		t.Fatal("the delete was not refused")
	}
	o, err := mem.Get(ctx, store.Key{Kind: "HostRemoval", Name: "hv1"})
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		Serials []string `json:"serials"`
	}
	if json.Unmarshal(o.Data, &rec) != nil || len(rec.Serials) != 1 || rec.Serials[0] != "abc" {
		t.Fatalf("re-join record: %s", o.Data)
	}
}
