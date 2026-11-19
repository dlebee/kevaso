package agent

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// A cloud-hypervisor silo's root disk on a mount class is disk.root in status, not in
// spec.volumes. The create pass sees the silo absent, and that volume stays mounted.
func TestAMicroVMsRootDiskStaysMounted(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	c := client.New(ts.URL)
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}}); err != nil {
		t.Fatal(err)
	}
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "vm", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor", VM: &v1.VMSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Disk: v1.Disk{Class: "juicefs", Size: "20Gi"}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	var cur v1.Silo
	if err := c.Get(ctx, "Silo", "dev", "vm", &cur); err != nil {
		t.Fatal(err)
	}
	cur.Status = v1.SiloStatus{Host: "hv1", Phase: "Scheduled", Volumes: []v1.VolumeStatus{
		{Name: v1.RootDiskVolume, Class: "juicefs", Handle: "disk-1", AttachedTo: "hv1", Mounted: true}}}
	if err := c.UpdateStatus(ctx, &cur); err != nil {
		t.Fatal(err)
	}
	h := &mountHost{mounted: map[string]bool{}}
	a := &Agent{Client: c, HostName: "hv1", Host: h, Log: t.Logf}
	dir := a.VolumePath(cur.UID, v1.RootDiskVolume)
	h.mounted[dir] = true
	if err := a.releaseDropped(ctx, fake.New(), &cur, kri.Absent); err != nil {
		t.Fatal(err)
	}
	if !h.isMounted(dir) {
		t.Fatal("disk.root was unmounted while the silo is still placed here")
	}
	var got v1.Silo
	if err := c.Get(ctx, "Silo", "dev", "vm", &got); err != nil {
		t.Fatal(err)
	}
	for _, vs := range got.Status.Volumes {
		if vs.Name == v1.RootDiskVolume && !vs.Mounted {
			t.Fatal("disk.root was reported unmounted")
		}
	}
}
