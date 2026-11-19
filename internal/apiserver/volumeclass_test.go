package apiserver_test

import (
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
)

func TestAVolumeClassCannotChangeInPlace(t *testing.T) {
	c, ctx := setup(t)
	db := newSilo("db")
	db.Spec.Runtime = "docker"
	db.Spec.VM = nil
	db.Spec.Container = &v1.ContainerSource{Image: "nginx:1.27"}
	db.Spec.Volumes = []v1.Volume{{Name: "data", Class: "juicefs", Size: "1Gi", MountPath: "/data"}}
	if err := c.Create(ctx, db); err != nil {
		t.Fatal(err)
	}
	var cur v1.Silo
	if err := c.Get(ctx, "Silo", "dev", "db", &cur); err != nil {
		t.Fatal(err)
	}
	cur.Spec.Volumes[0].Class = "local"
	if err := c.Update(ctx, &cur); !client.IsInvalid(err) {
		t.Fatalf("class change: %v", err)
	}
	cur.Spec.Volumes[0].Class = "juicefs"
	cur.Spec.Volumes[0].MountPath = "/var/data"
	if err := c.Update(ctx, &cur); err != nil {
		t.Fatalf("mount path: %v", err)
	}
	if err := c.Get(ctx, "Silo", "dev", "db", &cur); err != nil {
		t.Fatal(err)
	}
	cur.Spec.Volumes = nil
	if err := c.Update(ctx, &cur); err != nil {
		t.Fatalf("removing the volume: %v", err)
	}

	local := newSilo("plain")
	local.Spec.Runtime = "docker"
	local.Spec.VM = nil
	local.Spec.Container = &v1.ContainerSource{Image: "nginx:1.27"}
	local.Spec.Volumes = []v1.Volume{{Name: "data", MountPath: "/data"}}
	if err := c.Create(ctx, local); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, "Silo", "dev", "plain", &cur); err != nil {
		t.Fatal(err)
	}
	cur.Spec.Volumes[0].Class = "local"
	if err := c.Update(ctx, &cur); err != nil {
		t.Fatalf("empty and local are the same class: %v", err)
	}

	vm := newSilo("vm")
	vm.Spec.Disk = v1.Disk{Class: "juicefs", Size: "20Gi"}
	if err := c.Create(ctx, vm); err != nil {
		t.Fatal(err)
	}
	var disk v1.Silo
	if err := c.Get(ctx, "Silo", "dev", "vm", &disk); err != nil {
		t.Fatal(err)
	}
	disk.Spec.Disk.Size = "30Gi"
	if err := c.Update(ctx, &disk); err != nil {
		t.Fatalf("disk size: %v", err)
	}
	if err := c.Get(ctx, "Silo", "dev", "vm", &disk); err != nil {
		t.Fatal(err)
	}
	disk.Spec.Disk.Class = "local"
	if err := c.Update(ctx, &disk); !client.IsInvalid(err) {
		t.Fatalf("disk.class: %v", err)
	}

	set := newSilo("t")
	set.Name = "pool"
	set.Spec.Runtime = "docker"
	set.Spec.VM = nil
	set.Spec.Container = &v1.ContainerSource{Image: "nginx:1.27"}
	set.Spec.Volumes = []v1.Volume{{Name: "data", Class: "juicefs", Size: "1Gi", MountPath: "/data"}}
	ss := &v1.SiloSet{TypeMeta: set.TypeMeta, ObjectMeta: set.ObjectMeta, Spec: v1.SiloSetSpec{Instances: 1, Template: v1.SiloTemplate{SiloSpec: set.Spec}}}
	ss.Kind = "SiloSet"
	if err := c.Create(ctx, ss); err != nil {
		t.Fatal(err)
	}
	var got v1.SiloSet
	if err := c.Get(ctx, "SiloSet", "dev", "pool", &got); err != nil {
		t.Fatal(err)
	}
	got.Spec.Template.Volumes[0].Class = "local"
	if err := c.Update(ctx, &got); !client.IsInvalid(err) {
		t.Fatalf("set class change: %v", err)
	}
}

// Dropping a volume and adding the name back under another class is the same refusal as
// changing the class in place. The class recorded in status is what the name already has.
// The same class is accepted.
func TestAKeptNameCannotComeBackUnderAnotherClass(t *testing.T) {
	c, ctx := setup(t)
	db := newSilo("db")
	db.Spec.Runtime = "docker"
	db.Spec.VM = nil
	db.Spec.Container = &v1.ContainerSource{Image: "nginx:1.27"}
	db.Spec.Volumes = []v1.Volume{{Name: "data", Class: "juicefs", Size: "1Gi", MountPath: "/data"}}
	if err := c.Create(ctx, db); err != nil {
		t.Fatal(err)
	}
	var cur v1.Silo
	if err := c.Get(ctx, "Silo", "dev", "db", &cur); err != nil {
		t.Fatal(err)
	}
	cur.Status.Volumes = []v1.VolumeStatus{{Name: "data", Class: "juicefs", Handle: "vol-1"}}
	if err := c.UpdateStatus(ctx, &cur); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, "Silo", "dev", "db", &cur); err != nil {
		t.Fatal(err)
	}
	cur.Spec.Volumes = nil
	if err := c.Update(ctx, &cur); err != nil {
		t.Fatalf("removing the volume: %v", err)
	}
	if err := c.Get(ctx, "Silo", "dev", "db", &cur); err != nil {
		t.Fatal(err)
	}
	cur.Spec.Volumes = []v1.Volume{{Name: "data", Class: "local", Size: "1Gi", MountPath: "/data"}}
	if err := c.Update(ctx, &cur); !client.IsInvalid(err) || !strings.Contains(err.Error(), "class can't change") {
		t.Fatalf("kept name under another class: %v", err)
	}
	cur.Spec.Volumes = []v1.Volume{{Name: "data", Class: "juicefs", Size: "1Gi", MountPath: "/data"}}
	if err := c.Update(ctx, &cur); err != nil {
		t.Fatalf("same class: %v", err)
	}
}
