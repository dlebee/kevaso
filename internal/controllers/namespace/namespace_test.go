package namespace

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/store"
)

// A delete refused for now (409: an IP held until its silo's release is seen, say) is waited out,
// shown on the namespace; refused longer than StuckAfter, the cascade stops and says why. Asked
// again, it resumes.
func TestARefusalIsWaitedOutThenStops(t *testing.T) {
	ctx := context.Background()
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	var refuse atomic.Bool
	refuse.Store(true)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if refuse.Load() && r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/services/rpc") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"code":409,"reason":"Conflict","message":"still held"}`))
			return
		}
		srv.ServeHTTP(w, r)
	}))
	defer ts.Close()
	c := client.New(ts.URL)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}}))
	must(c.Create(ctx, &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "rpc", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}}}))
	must(c.Create(ctx, &v1.Service{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Service"}, ObjectMeta: meta.ObjectMeta{Name: "rpc", Namespace: "dev"},
		Spec: v1.ServiceSpec{Selector: map[string]string{"app": "rpc"}, Ports: []v1.ServicePortSpec{{Name: "rpc", Port: 8545}}}}))
	must(c.DeleteNamespace(ctx, "dev", client.DeleteOptions{Cascade: true}))

	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFake(now)
	ctl := &Controller{Client: c, Clock: clk, StuckAfter: time.Minute}
	key := engine.Key{Kind: "Namespace", Name: "dev"}
	get := func() v1.Namespace {
		t.Helper()
		var n v1.Namespace
		must(c.Get(ctx, "Namespace", "", "dev", &n))
		return n
	}

	res, err := ctl.Reconcile(ctx, key)
	must(err)
	n := get()
	if res.RequeueAfter == 0 || n.Annotations[client.AnnotationCascadeStep] != "step 2/5, remove load balancers: waiting on 1 service (rpc); refused for now: service rpc: still held" {
		t.Fatalf("first look: %v %q", res, n.Annotations[client.AnnotationCascadeStep])
	}
	if l, _ := c.List(ctx, "Silo", "dev"); len(l.Items) != 0 {
		t.Fatal("the silo is still there after its step")
	}
	clk.Step(30 * time.Second)
	_, err = ctl.Reconcile(ctx, key)
	must(err)
	if n := get(); n.Annotations[client.AnnotationCascadeFailed] != "" {
		t.Fatalf("stopped before StuckAfter: %q", n.Annotations[client.AnnotationCascadeFailed])
	}
	clk.Step(31 * time.Second)
	res, err = ctl.Reconcile(ctx, key)
	must(err)
	n = get()
	if want := "step 2/5, remove load balancers: refused for 1m0s: service rpc: still held. Left: 1 service (rpc)"; res.RequeueAfter != 0 || n.Annotations[client.AnnotationCascadeFailed] != want {
		t.Fatalf("stuck: %v %q, want %q", res, n.Annotations[client.AnnotationCascadeFailed], want)
	}
	if n.Status.Phase != "Terminating" {
		t.Fatalf("phase %q", n.Status.Phase)
	}
	// Stopped: looking again does nothing until the delete is asked again.
	_, err = ctl.Reconcile(ctx, key)
	must(err)
	if l, _ := c.List(ctx, "Service", "dev"); len(l.Items) != 1 {
		t.Fatal("the service went while stopped")
	}

	refuse.Store(false)
	must(c.DeleteNamespace(ctx, "dev", client.DeleteOptions{Cascade: true}))
	if n := get(); n.Annotations[client.AnnotationCascadeFailed] != "" || n.Annotations[client.AnnotationCascadeRetry] == "" {
		t.Fatalf("after asking again: %v", n.Annotations)
	}
	_, err = ctl.Reconcile(ctx, key)
	must(err)
	var gone v1.Namespace
	if err := c.Get(ctx, "Namespace", "", "dev", &gone); !client.IsNotFound(err) {
		t.Fatalf("namespace after the resume: %v %v", err, gone.Annotations)
	}
}
