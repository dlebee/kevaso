package provider_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/controllers/provider"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kplugin"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

// K-033: the volumes controller decides from its cached silo and writes onto the fresh one. A
// reconcile on a cache that is behind (it still shows the volume on the host the silo moved
// from) must not detach and attach again a volume that has moved and is mounted where the silo
// runs now.
func TestK033StaleReconcileLeavesAMountedVolumeAlone(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	defer cancel()
	c := client.New(ts.URL)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	dir, _ := os.MkdirTemp("/tmp", "kvp")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	fake := kplugintest.New()
	reg := &plugins.Registry{Dir: filepath.Join(dir, "plugins")}
	must(reg.Add(ctx, fake))

	must(c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}))
	for i, n := range []string{"w1", "w2"} {
		h := &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: n},
			Spec: v1.HostSpec{InternalIP: "10.0.0.5", Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}}}
		must(c.Create(ctx, h))
		h.Status.Provider = &v1.HostProvider{Name: "fake", ID: []string{"1", "2"}[i], Region: "r"}
		h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionTrue, LastTransitionTime: time.Now().UTC().Truncate(time.Second)}}
		must(c.UpdateStatus(ctx, h))
	}
	s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "d", Finalizers: []string{provider.FinalizerVolumes}},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Volumes: []v1.Volume{{Name: "data", Class: kplugintest.ClassBlock, Size: "1Gi", MountPath: "/data"}}}}
	must(c.Create(ctx, s))
	// Moved from w1 to w2; w1 has let go of the volume (unmounted), still attached there.
	s.Status.Host, s.Status.Phase = "w2", "Scheduled"
	s.Status.Volumes = []v1.VolumeStatus{{Name: "data", Class: kplugintest.ClassBlock, Handle: "vol-1", Region: "r", AttachedTo: "w1", Device: "/dev/old"}}
	must(c.UpdateStatus(ctx, s))
	fake.Volumes["vol-1"] = &kplugintest.FakeVolume{Volume: kplugin.Volume{Class: kplugintest.ClassBlock, Region: "r"}, Handle: "vol-1", AttachedTo: "1"}

	frozen := func(kind string) *informer.Informer {
		ictx, stop := context.WithCancel(ctx)
		inf := informer.New(c, kind)
		go inf.Run(ictx)
		if !inf.WaitSynced(ctx) {
			t.Fatalf("%s never synced", kind)
		}
		stop()
		return inf
	}
	ctl := &provider.Volumes{Client: c, Silos: frozen("Silo"), Hosts: frozen("Host"), Plugins: reg}
	key := engine.Key{Kind: "Silo", Namespace: "d", Name: "db"}
	if _, err := ctl.Reconcile(ctx, key); err != nil {
		t.Fatal(err)
	}
	var cur v1.Silo
	must(c.Get(ctx, "Silo", "d", "db", &cur))
	if v := cur.Status.Volumes[0]; v.AttachedTo != "w2" || v.Device == "" {
		t.Fatalf("not moved to w2: %+v", v)
	}
	// w2's agent mounts it and says so.
	cur.Status.Volumes[0].Mounted = true
	must(c.UpdateStatus(ctx, &cur))
	before := len(fake.CallLog())

	// Again, on the same cache: it still shows the volume on w1.
	if _, err := ctl.Reconcile(ctx, key); err != nil {
		t.Fatal(err)
	}
	for _, call := range fake.CallLog()[before:] {
		if strings.HasPrefix(call, "detach") || strings.HasPrefix(call, "attach") {
			t.Errorf("a stale reconcile called %q on a volume mounted on w2", call)
		}
	}
	if v := fake.Volumes["vol-1"]; v.AttachedTo != "2" {
		t.Errorf("the volume is attached to machine %q, not w2's", v.AttachedTo)
	}
}
