package kvo

import (
	"bytes"
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

func TestDeleteHostConfirmOff(t *testing.T) {
	ctx := context.Background()
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	t.Setenv("KVO_SERVER", ts.URL)
	c := client.New(ts.URL)
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hv1", "empty"} {
		if err := c.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: name},
			Spec: v1.HostSpec{ExternalIP: "203.0.113.10", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
			t.Fatal(err)
		}
	}
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host = "hv1"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}

	var errb bytes.Buffer
	if code := Run(ctx, []string{"delete", "host", "hv1"}, nil, &bytes.Buffer{}, &errb); code == 0 || !strings.Contains(errb.String(), "confirmOff=true") {
		t.Fatalf("without --confirm-off: code %d\n%s", code, errb.String())
	}
	var h v1.Host
	if err := c.Get(ctx, "Host", "", "hv1", &h); err != nil {
		t.Fatalf("hv1 was deleted: %v", err)
	}
	errb.Reset()
	if code := Run(ctx, []string{"delete", "host", "hv1", "--confirm-off"}, nil, &bytes.Buffer{}, &errb); code != 0 {
		t.Fatalf("with --confirm-off: code %d\n%s", code, errb.String())
	}
	if err := c.Get(ctx, "Host", "", "hv1", &h); !client.IsNotFound(err) {
		t.Fatalf("hv1 after --confirm-off: %v", err)
	}
	errb.Reset()
	if code := Run(ctx, []string{"delete", "host", "empty"}, nil, &bytes.Buffer{}, &errb); code != 0 {
		t.Fatalf("a host with no silos: code %d\n%s", code, errb.String())
	}
}
