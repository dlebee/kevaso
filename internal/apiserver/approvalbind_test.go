package apiserver_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/approvals"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// K-017: a person's yes is for the request they read. A silo that asks again under the same name
// with something else (longer access, another payload) before the answer lands gets no yes for
// it; the person must look at the new request and answer that one.
func TestK017AnApprovalIsForWhatTheApproverSaw(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st := store.NewMemory(0)
	srv, err := apiserver.New(st, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}))
	now := time.Now().UTC().Truncate(time.Second)
	a := &v1.Approval{TypeMeta: tm("Approval"), ObjectMeta: meta.ObjectMeta{Name: "s-1234", Namespace: "d"},
		Spec: v1.ApprovalSpec{Silo: "s", SiloUID: "u1", Secret: "key", Use: v1.ApprovalForSign, Grant: "g", For: "1m",
			PayloadHash: "aaaa", Summary: "sign 32 bytes with key", RequestedAt: now, ExpiresAt: now.Add(10 * time.Minute)},
		Status: v1.ApprovalStatus{Phase: v1.ApprovalPending}}
	a.UID = "a-uid"
	key := store.Key{Kind: "Approval", Namespace: "d", Name: a.Name}
	b, _ := json.Marshal(a)
	o, err := st.Create(ctx, key, b) // as the broker writes it
	must(err)
	saw := approvals.RequestID(a) // what the person read in kvo get approvals
	// The silo asks again before the answer: same name, another request.
	a.Spec.For, a.Spec.PayloadHash, a.Spec.Summary = "12h", "bbbb", "sign 9000 bytes with key"
	b, _ = json.Marshal(a)
	_, err = st.Update(ctx, key, b, o.Revision)
	must(err)
	answer := func(request string) (*v1.Approval, error) {
		var out v1.Approval
		err := c.Call(ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/d/approvals/s-1234/approve", map[string]string{"request": request}, &out)
		return &out, err
	}
	var ce *client.Error
	if _, err := answer(saw); !errors.As(err, &ce) || ce.Code != http.StatusConflict {
		t.Fatalf("approving what was read, after it changed: %v (want 409)", err)
	}
	var cur v1.Approval
	must(c.Get(ctx, "Approval", "d", "s-1234", &cur))
	if cur.Status.Phase != v1.ApprovalPending {
		t.Fatalf("the changed request was answered: %s for %s", cur.Status.Phase, cur.Spec.For)
	}
	if _, err := answer(""); err == nil {
		t.Fatal("a yes that says nothing about which request was accepted")
	}
	got, err := answer(approvals.RequestID(&cur))
	if err != nil || got.Status.Phase != v1.ApprovalApproved || got.Spec.For != "12h" {
		t.Fatalf("approving the request as it is now: %v %+v", err, got.Status)
	}
}
