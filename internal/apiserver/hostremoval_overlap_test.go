package apiserver_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// countHookStore runs fn once, inside the first silo count of a host delete.
type countHookStore struct {
	store.Store
	done atomic.Bool
	fn   func()
}

func (h *countHookStore) List(ctx context.Context, sel store.Selector) ([]store.Object, int64, error) {
	if sel.Kind == "Silo" && h.fn != nil && h.done.CompareAndSwap(false, true) {
		h.fn()
	}
	return h.Store.List(ctx, sel)
}

// Two deletes of one host overlap: A without the confirmation (refused), B with it, while A is
// between its record and its count. B's delete goes through, so its removal record stays: A's
// refusal undoes only a record A itself wrote, and nothing once the Host is gone.
func TestARefusedHostDeleteLeavesAnotherDeletesRemoval(t *testing.T) {
	ctx := context.Background()
	mem := store.NewMemory(0)
	hs := &countHookStore{Store: mem}
	srv, err := apiserver.New(hs, clock.Real{})
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
	var errB error
	hs.fn = func() { // B, whole, while A is between its record and its count
		errB = c.Delete(ctx, "Host", "", "hv1", client.Precondition{ConfirmOff: true})
	}
	errA := c.Delete(ctx, "Host", "", "hv1")
	t.Logf("RESULT A (no confirmation): %v", errA)
	t.Logf("RESULT B (confirmOff): %v", errB)
	var h v1.Host
	gone := client.IsNotFound(c.Get(ctx, "Host", "", "hv1", &h))
	_, rerr := mem.Get(ctx, store.Key{Kind: "HostRemoval", Name: "hv1"})
	t.Logf("RESULT host deleted=%v; removal record: %v", gone, rerr)
	if gone && errors.Is(rerr, store.ErrNotFound) {
		t.Fatal("the host was deleted with confirmation, and its removal record is gone: its old certificate is accepted again")
	}
}
