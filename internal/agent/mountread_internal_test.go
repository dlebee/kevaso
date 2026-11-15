package agent

import (
	"context"
	"net/http/httptest"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// Review (check-then-act) claim 2: a volume is mounted, and above all formatted, only on what is
// stored now: the same silo, placed here and free to start here, its volume attached here at the
// same device. A cache from before a move ("still here") mounts and formats nothing.
func TestAStaleCacheMountsAndFormatsNothing(t *testing.T) {
	ctx := context.Background()
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	const dev = "/dev/disk/by-id/scsi-0Linode_Volume_data"
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
			Volumes: []v1.Volume{{Name: "data", MountPath: "/data", Class: "linode-block", Size: "10Gi"}}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	cached := *s
	cached.Status = v1.SiloStatus{Host: "hv1", Volumes: []v1.VolumeStatus{{Name: "data", Class: "linode-block", Handle: "v-1", AttachedTo: "hv1", Device: dev}}}
	// What is stored: moved to hv2 since, its volume on its way there.
	s.Status = v1.SiloStatus{Host: "hv2", Phase: "Scheduled", Volumes: []v1.VolumeStatus{{Name: "data", Class: "linode-block", Handle: "v-1", AttachedTo: "hv2", Device: dev}}}
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	h := &fakeHost{codes: map[string]int{"mountpoint": 1, "blkid": 2}}
	a := &Agent{Client: c, HostName: "hv1", Host: h, Clock: clock.Real{}}
	_, ready, msg, err := a.mountVolumes(ctx, &cached)
	if h.did("mkfs") || h.did("mount -o") {
		t.Fatalf("mounted or formatted on a cache from before the move: %v", h.ran)
	}
	if ready || err != nil {
		t.Fatalf("ready %v, err %v (want waiting: %q)", ready, err, msg)
	}
	// Placed here, attached here, as stored: mounted (and formatted, being empty) as before.
	s.Status.Host, s.Status.Volumes[0].AttachedTo = "hv1", "hv1"
	if err := c.Get(ctx, "Silo", "dev", "db", &cached); err != nil {
		t.Fatal(err)
	}
	cached.Status.Host, cached.Status.Volumes = s.Status.Host, s.Status.Volumes
	if err := c.UpdateStatus(ctx, &cached); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, "Silo", "dev", "db", &cached); err != nil {
		t.Fatal(err)
	}
	if _, ready, msg, err := a.mountVolumes(ctx, &cached); !ready || err != nil || !h.did("mkfs") || !h.did("mount -o noatime "+dev) {
		t.Fatalf("placed here: ready %v %q %v, ran %v", ready, msg, err, h.ran)
	}
}
