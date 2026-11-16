package apiserver_test

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
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// bumpAfterTerminate moves a namespace's revision once it has been marked Terminating, the way a
// write that lands between the mark and the delete would. The delete is handed the revision from
// before that write.
type bumpAfterTerminate struct {
	store.Store
	bumped bool
}

func (b *bumpAfterTerminate) Update(ctx context.Context, key store.Key, data []byte, expected int64) (store.Object, error) {
	o, err := b.Store.Update(ctx, key, data, expected)
	if err != nil || b.bumped || key.Kind != "Namespace" {
		return o, err
	}
	obj, _, decErr := v1.Decode(data)
	if decErr != nil {
		return o, err
	}
	n, ok := obj.(*v1.Namespace)
	if !ok || n.Status.Phase != "Terminating" {
		return o, err
	}
	b.bumped = true
	if n.Labels == nil {
		n.Labels = map[string]string{}
	}
	n.Labels["changed"] = "while-deleting"
	raw, mErr := json.Marshal(n)
	if mErr != nil {
		return o, mErr
	}
	if _, uErr := b.Store.Update(ctx, key, raw, o.Revision); uErr != nil {
		return o, uErr
	}
	return o, nil
}

// A namespace that changes after it was marked Terminating and found empty is kept. The delete
// saw one revision; what is stored is a later one.
func TestANamespaceChangedWhileItWasBeingDeletedIsKept(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st := &bumpAfterTerminate{Store: store.NewMemory(0)}
	srv, err := apiserver.New(st, clock.NewFake(time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	ns := &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "empty"}}
	if err := c.Create(ctx, ns); err != nil {
		t.Fatal(err)
	}
	err = c.Delete(ctx, "Namespace", "", "empty")
	if code(err) != http.StatusConflict || !strings.Contains(err.Error(), "changed while it was being deleted") {
		t.Fatalf("delete after the namespace changed: %v", err)
	}
	var got v1.Namespace
	if err := c.Get(ctx, "Namespace", "", "empty", &got); err != nil {
		t.Fatalf("namespace after the refused delete: %v", err)
	}
	if got.Labels["changed"] != "while-deleting" {
		t.Fatalf("stored namespace: %+v", got)
	}
}
