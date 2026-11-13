package apiserver_test

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/internal/store"
)

// cloud-hypervisor silos have volumes (ADR 0006): local ones and any class's; not over the VM's own
// root; and their disk may live on a mount class (an image file on it), not a device class.
func TestVMVolumesAdmission(t *testing.T) {
	c, ctx := setup(t)
	s := newSilo("vm")
	s.Spec.Volumes = []v1.Volume{{Name: "data", MountPath: "/data", Size: "5Gi"}, {Name: "home", Class: "juicefs", Size: "5Gi", MountPath: "/home"}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatalf("a VM with volumes: %v", err)
	}
	root := newSilo("root")
	root.Spec.Volumes = []v1.Volume{{Name: "data", MountPath: "/", Size: "5Gi"}}
	if err := c.Create(ctx, root); !client.IsInvalid(err) || !strings.Contains(err.Error(), "mountPath / is the VM's own disk") {
		t.Fatalf("a volume over the root: %v", err)
	}
	oshell := newSilo("os")
	oshell.Spec.Runtime, oshell.Spec.VM, oshell.Spec.Container = "openshell", nil, &v1.ContainerSource{Image: "ghcr.io/acme/agent:v1"}
	oshell.Spec.Volumes = s.Spec.Volumes[:1]
	if err := c.Create(ctx, oshell); !client.IsInvalid(err) || !strings.Contains(err.Error(), "volumes on openshell come later") {
		t.Fatalf("openshell with volumes: %v", err)
	}

	srv, err := apiserver.New(store.NewMemory(0), clock.NewFake(time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	srv.SetClasses(func() map[string]scheduler.Class {
		return map[string]scheduler.Class{"juicefs": {Plugin: "juicefs", Topology: "global", Mount: true}, "block": {Plugin: "linode", Topology: "region"}}
	})
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	c2 := client.New(ts.URL)
	if err := c2.Create(ctx, ns("dev")); err != nil {
		t.Fatal(err)
	}
	onMount := newSilo("movable")
	onMount.Spec.Disk = v1.Disk{Class: "juicefs", Size: "20Gi"}
	onMount.Spec.Availability.OnHostLoss = v1.OnHostLossMove // its disk moves with it
	if err := c2.Create(ctx, onMount); err != nil {
		t.Fatalf("a VM whose disk is on a mount class: %v", err)
	}
	onDevice := newSilo("blocky")
	onDevice.Spec.Disk = v1.Disk{Class: "block", Size: "20Gi"}
	if err := c2.Create(ctx, onDevice); !client.IsInvalid(err) || !strings.Contains(err.Error(), "not a device class") {
		t.Fatalf("a VM whose disk is on a device class: %v", err)
	}
	pinned := newSilo("pinned")
	pinned.Spec.Availability.OnHostLoss = v1.OnHostLossMove
	if err := c2.Create(ctx, pinned); !client.IsInvalid(err) {
		t.Fatalf("Move with a local disk: %v", err)
	}
}
