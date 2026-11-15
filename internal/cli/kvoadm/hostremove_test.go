package kvoadm

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// K-119: a host a silo is still moving from (a handoff it hasn't let go of) isn't removed: the
// handoff would never end, and its copy there may still run.
func TestHostRemoveRefusesAHostASiloIsMovingFrom(t *testing.T) {
	ctx := context.Background()
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	for _, h := range []string{"hv1", "hv2"} {
		if err := c.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: h},
			Spec: v1.HostSpec{InternalIP: "10.0.0.1", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
			t.Fatal(err)
		}
	}
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.MovingFrom = "hv2", "hv1"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	err := removeWorkerHost(ctx, c, "hv1", func(string, ...any) {})
	if err == nil || !strings.Contains(err.Error(), "moving from hv1") {
		t.Fatalf("removing a host a silo is moving from: %v", err)
	}
	var h v1.Host
	if err := c.Get(ctx, "Host", "", "hv1", &h); err != nil {
		t.Fatalf("the host was removed: %v", err)
	}
}
