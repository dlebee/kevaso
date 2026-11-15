package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/store"
)

// noRevision is a store whose revision can't be read (no quorum, or slower than the stamp's
// deadline).
type noRevision struct{ store.Store }

func (noRevision) Revision(context.Context) (int64, error) { return 0, errors.New("no leader") }

func stampOf(t *testing.T, h http.Handler) (client.ControlPlaneSeen, bool) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	return client.ParseControlPlane(rec.Header())
}

// A system node stamps its answers with the cluster's history and epoch as the store holds them
// now, not as they were when the node started: after a restore another system node writes the
// new history into the shared store, and this one, never restarted, must not go on saying the
// old one (a worker that accepted the new history would take it for an older control plane).
func TestTheStampIsTheStoresIdentityNow(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory(0)
	id := ClusterIdentity{ID: "c", Name: "lab", History: "h1", Epoch: 1, Created: time.Now().UTC()}
	b, _ := json.Marshal(id)
	o, err := st.Create(ctx, identityKey, b)
	if err != nil {
		t.Fatal(err)
	}
	h := withControlPlane(http.NotFoundHandler(), st, false)
	if s, ok := stampOf(t, h); !ok || s.History != "h1" || s.Epoch != 1 || s.ClusterID != "c" {
		t.Fatalf("before the restore: %+v %v", s, ok)
	}
	// The restore, on another system node of this store.
	id.History, id.Epoch = "h2", 2
	b, _ = json.Marshal(id)
	if _, err := st.Update(ctx, identityKey, b, o.Revision); err != nil {
		t.Fatal(err)
	}
	s, ok := stampOf(t, h)
	if !ok || s.History != "h2" || s.Epoch != 2 {
		t.Fatalf("after the restore, this node still says %+v %v", s, ok)
	}
	rev, _ := st.Revision(ctx)
	if s.Revision != rev {
		t.Fatalf("revision %d, the store's is %d", s.Revision, rev)
	}
}

// Without the store's revision there is no stamp at all: a worker judges such an answer NotYet,
// never applies it as if it were judged.
func TestNoRevisionNoStamp(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory(0)
	b, _ := json.Marshal(ClusterIdentity{ID: "c", History: "h1", Epoch: 1})
	if _, err := st.Create(ctx, identityKey, b); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	withControlPlane(http.NotFoundHandler(), noRevision{st}, false).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	for _, k := range []string{client.HeaderClusterID, client.HeaderHistory, client.HeaderEpoch, client.HeaderRevision} {
		if v := rec.Header().Get(k); v != "" {
			t.Errorf("%s: %q on an answer whose store gave no revision", k, v)
		}
	}
	// A store with no identity yet: no stamp either.
	if _, ok := stampOf(t, withControlPlane(http.NotFoundHandler(), store.NewMemory(0), false)); ok {
		t.Error("stamped with no identity in the store")
	}
}

// K-008, the second way in: a system node that still answers but whose store has no quorum must
// be told apart from a healthy one. On the API listener it answers 503 with
// client.HeaderUnavailable before handling anything, so a worker's client sends the request to
// another node as it is. The admin socket (a person on this machine, maybe repairing the store)
// still gets the request, unstamped.
func TestK008ANodeWithoutAStoreSaysSoBeforeHandling(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory(0)
	b, _ := json.Marshal(ClusterIdentity{ID: "c", History: "h1", Epoch: 1})
	if _, err := st.Create(ctx, identityKey, b); err != nil {
		t.Fatal(err)
	}
	handled := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handled++ })
	rec := httptest.NewRecorder()
	withControlPlane(next, noRevision{st}, true).ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/apis/kevaso/v1/hosts/hv1/status", nil))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get(client.HeaderUnavailable) == "" || handled != 0 {
		t.Fatalf("API listener, no store: %d %q, handled %d", rec.Code, rec.Header().Get(client.HeaderUnavailable), handled)
	}
	rec = httptest.NewRecorder()
	withControlPlane(next, noRevision{st}, false).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if handled != 1 || rec.Header().Get(client.HeaderUnavailable) != "" {
		t.Fatalf("admin socket, no store: handled %d", handled)
	}
	// A healthy store: handled, stamped.
	rec = httptest.NewRecorder()
	withControlPlane(next, st, true).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if _, ok := client.ParseControlPlane(rec.Header()); !ok || handled != 2 {
		t.Fatalf("healthy: stamped %v, handled %d", ok, handled)
	}
}
