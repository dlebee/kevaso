package client

import (
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Review of the control-plane fixes, item 3: after a timeout, only what can't apply twice is sent
// to the next system node: a read, or an object update (Update, UpdateStatus), which carries the
// version it was read at, so a second send conflicts. Any other PUT (a scale with no
// resourceVersion, a raw Call) may have landed on the node that didn't answer: it fails as a
// timeout, sent once.
func TestOnlyWhatCantApplyTwiceIsResentAfterATimeout(t *testing.T) {
	short(t)
	release := make(chan struct{})
	defer close(release)
	var hitsA, hitsB atomic.Int32
	a := h2Server(t, func(w http.ResponseWriter, r *http.Request) {
		hitsA.Add(1)
		_, _ = io.Copy(io.Discard, r.Body) // it lands here, and the answer never comes
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	b := h2Server(t, func(w http.ResponseWriter, r *http.Request) {
		hitsB.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`{"metadata":{"name":"s","namespace":"d","resourceVersion":"8"}}`))
	})
	ctx := context.Background()
	mk := func() *Client {
		c, err := NewTLSEndpoints([]string{a.URL, b.URL}, caOf(a), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	// A scale (unconditional when it has no resourceVersion): sent once, a timeout.
	a0, b0 := hitsA.Load(), hitsB.Load()
	sc := &v1.Scale{ObjectMeta: meta.ObjectMeta{Name: "s", Namespace: "d"}}
	if err := mk().UpdateScale(ctx, "SiloSet", sc); !IsTimeout(err) || hitsA.Load()-a0 != 1 || hitsB.Load()-b0 != 0 {
		t.Fatalf("a scale: %v, sent to a %d, to b %d; want a timeout, sent once", err, hitsA.Load()-a0, hitsB.Load()-b0)
	}
	// A raw PUT: the same.
	a0, b0 = hitsA.Load(), hitsB.Load()
	if err := mk().Call(ctx, http.MethodPut, "/apis/x", map[string]string{"a": "b"}, nil); !IsTimeout(err) || hitsA.Load()-a0 != 1 || hitsB.Load()-b0 != 0 {
		t.Fatalf("a raw PUT: %v, sent to a %d, to b %d", err, hitsA.Load()-a0, hitsB.Load()-b0)
	}
	// An object update (conditional on its resourceVersion): sent on to b.
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "s", Namespace: "d", ResourceVersion: "7"}}
	b0 = hitsB.Load()
	if err := mk().UpdateStatus(ctx, s); err != nil || hitsB.Load()-b0 != 1 {
		t.Fatalf("an object update: %v, sent to b %d; want it sent on", err, hitsB.Load()-b0)
	}
	// One without a resourceVersion is unconditional: not sent on.
	s.ResourceVersion = ""
	b0 = hitsB.Load()
	if err := mk().Update(ctx, s); !IsTimeout(err) || hitsB.Load()-b0 != 0 {
		t.Fatalf("an update with no resourceVersion: %v, sent to b %d", err, hitsB.Load()-b0)
	}
}
