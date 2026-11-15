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
	h := withControlPlane(http.NotFoundHandler(), st)
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
	withControlPlane(http.NotFoundHandler(), noRevision{st}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	for _, k := range []string{client.HeaderClusterID, client.HeaderHistory, client.HeaderEpoch, client.HeaderRevision} {
		if v := rec.Header().Get(k); v != "" {
			t.Errorf("%s: %q on an answer whose store gave no revision", k, v)
		}
	}
	// A store with no identity yet: no stamp either.
	if _, ok := stampOf(t, withControlPlane(http.NotFoundHandler(), store.NewMemory(0))); ok {
		t.Error("stamped with no identity in the store")
	}
}
