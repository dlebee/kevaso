package apiserver_test

import (
	"context"
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

func TestAWorkerCannotMarkASiloSettled(t *testing.T) {
	e := setupAuth(t)
	mustCreate(t, e, ns("dev"))
	w := enrollHost(t, e, "hv1", "worker")
	s := place(t, e, "web", "dev", "hv1", v1.SiloSpec{Runtime: "cloud-hypervisor"})
	if err := e.admin.Get(e.ctx, "Silo", "dev", "web", s); err != nil {
		t.Fatal(err)
	}
	s.Status.Restore = &v1.SiloRestore{History: "h2", Phase: v1.RestorePending}
	if err := e.admin.UpdateStatus(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := w.Get(e.ctx, "Silo", "dev", "web", s); err != nil {
		t.Fatal(err)
	}
	s.Status.Restore.Phase = v1.RestoreSettled
	if err := w.UpdateStatus(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	var got v1.Silo
	if err := e.admin.Get(e.ctx, "Silo", "dev", "web", &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Restore == nil || got.Status.Restore.Phase != v1.RestorePending {
		t.Fatalf("a worker marked the silo settled: %+v", got.Status.Restore)
	}
}

func TestARequiredHostDuringAnOpenRestoreNeedsConfirmOff(t *testing.T) {
	ctx := context.Background()
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
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
	if err := c.Create(ctx, &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"},
		ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev"},
		Spec:       v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(ctx, &v1.RestoreGate{
		TypeMeta:   meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RestoreGate"},
		ObjectMeta: meta.ObjectMeta{Name: v1.RestoreGateName},
		Spec: v1.RestoreGateSpec{
			History: "h2", Started: time.Now().Add(time.Hour).UTC(), NoHostsAdded: true, Required: []string{"hv1"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	err = c.Delete(ctx, "Host", "", "hv1")
	if code(err) != http.StatusConflict || !strings.Contains(err.Error(), "restored history") {
		t.Fatalf("delete without confirmation: %v", err)
	}
	var still v1.Host
	if err := c.Get(ctx, "Host", "", "hv1", &still); err != nil {
		t.Fatalf("the host was deleted: %v", err)
	}
	if err := c.Delete(ctx, "Host", "", "hv1", client.Precondition{ConfirmOff: true}); err != nil {
		t.Fatalf("delete with confirmation: %v", err)
	}
	var g v1.RestoreGate
	if err := c.Get(ctx, "RestoreGate", "", v1.RestoreGateName, &g); err != nil {
		t.Fatal(err)
	}
	if len(g.Spec.ConfirmedOff) != 1 || g.Spec.ConfirmedOff[0] != "hv1" {
		t.Fatalf("confirmed off: %+v", g.Spec.ConfirmedOff)
	}
}
