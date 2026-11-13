package integration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controlplane"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// What a silo starts from (design §0.2, "Decided"): a container silo from container.image with a
// pull secret, a VM silo from a disk stated inline, and one from a VMImage's version, in a real
// control plane with a worker that runs VMs (the fake runtime records what it's given). A set of
// VMs on an inline disk rolls when the disk changes; the wrong block for a runtime is refused,
// naming the right one.
func TestWhatASiloStartsFrom(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dir, _ := os.MkdirTemp("/tmp", "kvsrc")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cp, err := controlplane.Start(ctx, controlplane.Config{ClusterName: "it", HostName: "cp-1", InternalIP: "127.0.0.1",
		DataDir: filepath.Join(dir, "cp"), Listen: "127.0.0.1:0", AdminSocket: filepath.Join(dir, "a.sock"), Heartbeat: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	admin := client.NewUnix(filepath.Join(dir, "a.sock"))
	rt := fake.New()
	joinWorker(t, ctx, admin, "https://"+cp.APIAddr, cp.CA.PEM, dir, "w1", rt)
	_ = admin.Create(ctx, ns("demo"))

	disk := func(n string) *v1.VMDisk {
		return &v1.VMDisk{URL: "https://images.example.com/geth-" + n + ".img", SHA256: strings.Repeat(n, 64)[:64]}
	}
	if err := admin.Create(ctx, &v1.VMImage{TypeMeta: tm("VMImage"), ObjectMeta: meta.ObjectMeta{Name: "geth-node", Namespace: "demo"},
		Spec: v1.VMImageSpec{Versions: []v1.VMImageVersion{{Name: "v1", Disk: disk("a")}, {Name: "v2", Disk: disk("b")}}}}); err != nil {
		t.Fatal(err)
	}
	pull := &v1.Secret{TypeMeta: tm("Secret"), ObjectMeta: meta.ObjectMeta{Name: "ghcr-pull", Namespace: "demo"},
		Spec: v1.SecretSpec{Type: v1.SecretRegistry, Server: "ghcr.io", Username: "bot", Value: []byte("tok")}}
	if err := admin.Create(ctx, pull); err != nil {
		t.Fatal(err)
	}
	mk := func(name, runtime string, f func(*v1.SiloSpec)) *v1.Silo {
		s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "demo"},
			Spec: v1.SiloSpec{Runtime: runtime, Resources: v1.Resources{CPU: 1, Memory: "1Gi"}}}
		f(&s.Spec)
		return s
	}
	given := func(s *v1.Silo) string { return rt.Image(kri.ID{Namespace: s.Namespace, Name: s.Name, UID: s.UID}) }

	// The wrong block, or both vm ways at once: refused, naming the right one.
	for what, bad := range map[string]struct {
		s   *v1.Silo
		msg string
	}{
		"vm on docker": {mk("bad", "docker", func(s *v1.SiloSpec) { s.VM = &v1.VMSource{Image: "geth-node"} }), "say it in container: { image: REF }"},
		"container on cloud-hypervisor": {mk("bad", "cloud-hypervisor", func(s *v1.SiloSpec) { s.Container = &v1.ContainerSource{Image: "nginx:1.27"} }),
			"say what it boots in vm:"},
		"both vm ways": {mk("bad", "cloud-hypervisor", func(s *v1.SiloSpec) { s.VM = &v1.VMSource{Image: "geth-node", Disk: disk("a")} }), "not both"},
		"a VMImage as a container image": {mk("bad", "docker", func(s *v1.SiloSpec) { s.Container = &v1.ContainerSource{Image: "geth-node"} }),
			"geth-node is a VMImage"},
	} {
		if err := admin.Create(ctx, bad.s); !client.IsInvalid(err) || !strings.Contains(err.Error(), bad.msg) {
			t.Errorf("%s: %v, want %q", what, err, bad.msg)
		}
	}

	// A container silo: its image is the registry reference as it is, pulled with its secret.
	api := mk("api", "docker", func(s *v1.SiloSpec) {
		s.Container = &v1.ContainerSource{Image: "ghcr.io/acme/api:v1", Pull: &v1.ImagePull{SecretRef: "ghcr-pull"}, Command: []string{"/app", "--serve"}}
	})
	inline := mk("inline", "cloud-hypervisor", func(s *v1.SiloSpec) { s.VM = &v1.VMSource{Disk: disk("c")} })
	named := mk("named", "cloud-hypervisor", func(s *v1.SiloSpec) { s.VM = &v1.VMSource{Image: "geth-node:v1"} })
	for _, s := range []*v1.Silo{api, inline, named} {
		if err := admin.Create(ctx, s); err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
	}
	s := waitSilo(t, ctx, admin, "api", func(s *v1.Silo) bool { return s.Status.Image != nil && s.Status.Image.Ref != "" })
	if s.Status.Image.From != "ghcr.io/acme/api:v1" || s.Status.Image.Ref != "ghcr.io/acme/api:v1" || s.Spec.Pull().SecretRef != "ghcr-pull" {
		t.Fatalf("container: %+v", s.Status.Image)
	}
	// An inline disk goes to the runtime as a VMImage version's does: its URL and the hash it must have.
	s = waitSilo(t, ctx, admin, "inline", func(s *v1.Silo) bool { return s.Status.Phase == "Running" })
	if want := v1.DiskRef(*disk("c")); s.Status.Image.Ref != want || given(s) != want {
		t.Fatalf("inline disk: status %+v, runtime got %q", s.Status.Image, given(s))
	}
	s = waitSilo(t, ctx, admin, "named", func(s *v1.Silo) bool { return s.Status.Phase == "Running" })
	if want := v1.DiskRef(*disk("a")); s.Status.Image.From != "geth-node:v1" || s.Status.Image.Ref != want || given(s) != want {
		t.Fatalf("VMImage version: status %+v, runtime got %q", s.Status.Image, given(s))
	}

	// A set of VMs on an inline disk rolls when the disk changes.
	set := &v1.SiloSet{TypeMeta: tm("SiloSet"), ObjectMeta: meta.ObjectMeta{Name: "pool", Namespace: "demo"},
		Spec: v1.SiloSetSpec{Instances: 1, UpgradePolicy: v1.UpgradeRolling, Template: v1.SiloTemplate{
			SiloSpec: v1.SiloSpec{Runtime: "cloud-hypervisor", Resources: v1.Resources{CPU: 1, Memory: "1Gi"}, VM: &v1.VMSource{Disk: disk("d")}}}}}
	if err := admin.Create(ctx, set); err != nil {
		t.Fatal(err)
	}
	s = waitSilo(t, ctx, admin, "pool-0", func(s *v1.Silo) bool { return s.Status.Phase == "Running" })
	if given(s) != v1.DiskRef(*disk("d")) {
		t.Fatalf("pool-0 got %q", given(s))
	}
	for attempt := 0; ; attempt++ {
		_ = admin.Get(ctx, "SiloSet", "demo", "pool", set)
		set.Spec.Template.VM.Disk = disk("e")
		err := admin.Update(ctx, set)
		if err == nil {
			break
		}
		if !client.IsConflict(err) || attempt > 10 {
			t.Fatal(err)
		}
	}
	s = waitSilo(t, ctx, admin, "pool-0", func(s *v1.Silo) bool {
		return s.Status.Image != nil && s.Status.Image.Running == v1.DiskRef(*disk("e"))
	})
	if given(s) != v1.DiskRef(*disk("e")) {
		t.Fatalf("rolled pool-0, runtime has %q", given(s))
	}
}
