package agent

import (
	"context"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/hostexec"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// mountHost is a host whose mounts are kept: mount makes one, umount ends it, mountpoint says.
type mountHost struct {
	mu      sync.Mutex
	mounted map[string]bool
	ran     []string
}

func (h *mountHost) Run(_ context.Context, c hostexec.Cmd) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ran = append(h.ran, c.Name+" "+strings.Join(c.Args, " "))
	last := ""
	if len(c.Args) > 0 {
		last = c.Args[len(c.Args)-1]
	}
	switch c.Name {
	case "mountpoint":
		if h.mounted[last] {
			return 0, nil
		}
		return notAMountPoint, nil
	case "mount":
		h.mounted[last] = true
	case "umount":
		delete(h.mounted, last)
	case "blkid":
		if c.Stdout != nil {
			_, _ = c.Stdout.Write([]byte("ext4\n"))
		}
	}
	return 0, nil
}
func (h *mountHost) WriteFile(string, []byte, os.FileMode) error { return nil }
func (h *mountHost) ReadFile(string) ([]byte, error)             { return nil, os.ErrNotExist }
func (h *mountHost) RemoveAll(string) error                      { return nil }
func (h *mountHost) Glob(string) ([]string, error)               { return nil, nil }
func (h *mountHost) isMounted(dir string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.mounted[dir]
}

// withVolumes is the fake saying what its copy of a silo uses (the built-in runtimes'
// VolumesOf); asVM adds SetVolumes, as a VM changes them (a restart while it runs).
type withVolumes struct {
	*fake.Runtime
	mu  sync.Mutex
	set map[kri.ID][]kri.Volume
}

func (r *withVolumes) VolumesOf(id kri.ID) ([]kri.Volume, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := r.set[id]; ok {
		return v, true
	}
	sp, ok := r.Spec(id)
	return sp.Volumes, ok
}

// asVM adds SetVolumes.
type asVM struct{ *withVolumes }

func (r asVM) SetVolumes(ctx context.Context, id kri.ID, vols []kri.Volume) (bool, error) {
	cur, _ := r.VolumesOf(id)
	if volumeNames(cur) == volumeNames(vols) {
		return false, nil
	}
	if st, _ := r.Status(ctx, id); st.State == kri.Running {
		return true, nil
	}
	r.mu.Lock()
	r.set[id] = vols
	r.mu.Unlock()
	return false, nil
}

func volumeNames(vols []kri.Volume) string {
	var n []string
	for _, v := range vols {
		n = append(n, v.Name)
	}
	return strings.Join(n, ",")
}

// From the Linodes (linode-3.md, core finding 6): a provider volume dropped from a running silo's
// spec stayed mounted for good, and the control plane waited for ever to detach and delete it. A
// VM changes its volumes stop-first (SetVolumes): the dropped one is unmounted and reported so. A
// container's mounts can't change: the silo says the removal waits for its next reset, and after
// that reset the volume is let go.
func TestAVolumeDroppedFromARunningSilosSpecIsLetGo(t *testing.T) {
	for _, vm := range []bool{true, false} {
		name := map[bool]string{true: "a VM (SetVolumes)", false: "a container (its mounts are fixed)"}[vm]
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
			ts := httptest.NewServer(srv)
			t.Cleanup(func() { cancel(); ts.Close() })
			c := client.New(ts.URL)
			_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
			wv := &withVolumes{Runtime: fake.New(), set: map[kri.ID][]kri.Volume{}}
			var rt kri.Runtime = wv
			if vm {
				rt = asVM{wv}
			}
			h := &mountHost{mounted: map[string]bool{}}
			a := &Agent{Client: c, HostName: "hv1", Host: h, Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{}, Log: t.Logf,
				VolumesDir: "/var/lib/kevaso/volumes"}
			RunForTest(t, ctx, a)
			s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "dev"},
				Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "postgres:17"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
					Volumes: []v1.Volume{{Name: "data", MountPath: "/data", Class: "linode-block", Size: "10Gi"}, {Name: "wal", MountPath: "/wal", Class: "linode-block", Size: "10Gi"}}}}
			if err := c.Create(ctx, s); err != nil {
				t.Fatal(err)
			}
			s.Status = v1.SiloStatus{Host: "hv1", Phase: "Scheduled", Volumes: []v1.VolumeStatus{
				{Name: "data", Class: "linode-block", Handle: "v-1", AttachedTo: "hv1", Device: "/dev/sdc"},
				{Name: "wal", Class: "linode-block", Handle: "v-2", AttachedTo: "hv1", Device: "/dev/sdd"}}}
			if err := c.UpdateStatus(ctx, s); err != nil {
				t.Fatal(err)
			}
			get := func() *v1.Silo {
				var cur v1.Silo
				if err := c.Get(ctx, "Silo", "dev", "db", &cur); err != nil {
					t.Fatal(err)
				}
				return &cur
			}
			wait := func(what string, ok func(*v1.Silo) bool) *v1.Silo {
				t.Helper()
				for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
					if cur := get(); ok(cur) {
						return cur
					}
					if time.Now().After(deadline) {
						t.Fatalf("never: %s: %+v", what, get().Status)
					}
				}
			}
			mounted := func(cur *v1.Silo, vol string) bool {
				for _, vs := range cur.Status.Volumes {
					if vs.Name == vol {
						return vs.Mounted
					}
				}
				return false
			}
			edit := func(f func(*v1.Silo)) {
				for {
					cur := get()
					f(cur)
					err := c.Update(ctx, cur)
					if err == nil {
						return
					}
					if !client.IsConflict(err) {
						t.Fatal(err)
					}
				}
			}
			wait("it runs with both volumes mounted", func(cur *v1.Silo) bool {
				return cur.Status.Phase == PhaseRunning && mounted(cur, "data") && mounted(cur, "wal")
			})
			walDir := a.VolumePath(s.UID, "wal")
			edit(func(cur *v1.Silo) { cur.Spec.Volumes = cur.Spec.Volumes[:1] })
			if !vm {
				cur := wait("the silo says the removal waits for its reset", func(cur *v1.Silo) bool {
					u := meta.FindCondition(cur.Status.Conditions, "Updated")
					return u != nil && u.Reason == reasonVolumeRemovalWaits && strings.Contains(u.Message, "wal")
				})
				if !mounted(cur, "wal") || !h.isMounted(walDir) {
					t.Fatal("wal was let go while the container still has it mounted")
				}
				edit(func(cur *v1.Silo) { cur.Spec.Reset = "2026-11-15T12:00:00Z" })
			}
			wait("wal reported unmounted, data still mounted, the silo running", func(cur *v1.Silo) bool {
				return !mounted(cur, "wal") && mounted(cur, "data") && cur.Status.Phase == PhaseRunning
			})
			if h.isMounted(walDir) {
				t.Fatalf("%s is still mounted on the host", walDir)
			}
		})
	}
}
