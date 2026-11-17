package kvoadm

import (
	"bytes"
	"context"
	"fmt"
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

// host remove lists what a delete starts elsewhere and what stays, refuses without a yes, and
// sends the confirmation with one. The API refuses the delete otherwise.
func TestHostRemoveListsSilosAndConfirmsTheMachineIsOff(t *testing.T) {
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
	mk := func(name string, spec v1.SiloSpec, on, from string) {
		t.Helper()
		s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"}, Spec: spec}
		if err := c.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		s.Status.Host, s.Status.MovingFrom = on, from
		if err := c.UpdateStatus(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	box := v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"}}
	web := box
	web.Availability.OnHostLoss = v1.OnHostLossRecreate
	mk("web", web, "hv1", "")
	pinned := box
	pinned.Volumes = []v1.Volume{{Name: "data", Class: v1.VolumeLocal, Size: "1Gi", MountPath: "/data"}}
	mk("pin", pinned, "hv1", "")
	mk("move", box, "hv2", "hv1")

	var out bytes.Buffer
	say := func(f string, a ...any) { fmt.Fprintf(&out, f+"\n", a...) }
	err := removeWorkerHost(ctx, c, "hv1", false, strings.NewReader("n\n"), say)
	if err == nil || !strings.Contains(err.Error(), "was not removed") {
		t.Fatalf("a no: %v", err)
	}
	text := out.String()
	start := strings.Index(text, "starts these silos elsewhere")
	stay := strings.Index(text, "stay unschedulable")
	ask := strings.Index(text, "Is hv1 off or wiped? [y/N]")
	if start < 0 || stay < start || ask < stay {
		t.Fatalf("the list:\n%s", text)
	}
	elsewhere, kept := text[start:stay], text[stay:ask]
	if !strings.Contains(elsewhere, "dev/web") || !strings.Contains(elsewhere, "dev/move") || strings.Contains(elsewhere, "dev/pin") {
		t.Fatalf("started elsewhere:\n%s", elsewhere)
	}
	if !strings.Contains(kept, "dev/pin") || strings.Contains(kept, "dev/web") {
		t.Fatalf("stay unschedulable:\n%s", kept)
	}
	var h v1.Host
	if err := c.Get(ctx, "Host", "", "hv1", &h); err != nil {
		t.Fatalf("the host was removed: %v", err)
	}

	out.Reset()
	if err := removeWorkerHost(ctx, c, "hv1", false, strings.NewReader("y\n"), say); err != nil {
		t.Fatalf("a yes: %v\n%s", err, out.String())
	}
	if err := c.Get(ctx, "Host", "", "hv1", &h); !client.IsNotFound(err) {
		t.Fatalf("hv1 after yes: %v", err)
	}
}
