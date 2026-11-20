package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/jointoken"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/internal/routing"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kplugin"
	"kevaso.com/core/sdk/kplugin/kplugintest"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// A kept copy of a silo whose disk travels is dropped when the silo is placed elsewhere:
// this host holds no disk of its own. A host-local volume is still kept.
func TestATravellingDiskIsDroppedWhenTheSiloIsPlacedElsewhere(t *testing.T) {
	g := newGuardRig(t, nil, func(a *Agent) {
		a.Runtimes = map[string]kri.Runtime{"cloud-hypervisor": a.Runtimes["docker"]}
	})
	s := g.create(travellingSilo("web", ""), "hv2", "")
	g.runtimeCopy(s, kri.Created)
	g.cacheIs(g.stored("web"))
	if _, err := g.reconcile("web"); err != nil {
		t.Fatal(err)
	}
	if len(g.calls("delete")) != 1 {
		t.Fatalf("calls %v, want the kept copy dropped", g.rt.Calls)
	}
	if _, kept := g.a.keptNoted.Load(s.UID); kept {
		t.Fatal("the travelling copy was kept")
	}
}

// diskRT is a runtime whose copy still holds a logical volume after that volume left the spec.
// Delete is what would lvremove it.
type diskRT struct {
	*fake.Runtime
	lv      string
	removed []string
	err     error
}

func (d *diskRT) HasHostStorage(context.Context, kri.ID) (bool, error) {
	if d.err != nil {
		return false, d.err
	}
	return d.lv != "", nil
}

// HasHostVolume is a volume LV (kv-<id>-<name>), not the root LV (kv-<id>).
func (d *diskRT) HasHostVolume(context.Context, kri.ID) (bool, error) {
	if d.err != nil {
		return false, d.err
	}
	return strings.Count(d.lv, "-") >= 2, nil
}

func (d *diskRT) Delete(ctx context.Context, id kri.ID) error {
	if d.lv != "" {
		d.removed = append(d.removed, "lvremove "+d.lv)
	}
	return d.Runtime.Delete(ctx, id)
}

// A local volume taken out of the spec is still on this host. Placing the silo elsewhere,
// with no handoff, must not lvremove it, and the copy stays.
func TestAVolumeTakenOutOfTheSpecIsKeptWhenTheCopyIsDropped(t *testing.T) {
	inner := fake.New()
	const lv = "kv-web-data"
	rt := &diskRT{Runtime: inner, lv: lv}
	g := newGuardRig(t, rt, func(a *Agent) {
		a.Runtimes = map[string]kri.Runtime{"cloud-hypervisor": rt}
	})
	g.rt = inner
	s := g.create(travellingSilo("web", ""), "hv2", "")
	g.runtimeCopy(s, kri.Created)
	g.cacheIs(g.stored("web"))
	if _, err := g.reconcile("web"); err != nil {
		t.Fatal(err)
	}
	if len(rt.removed) != 0 || len(g.calls("delete")) != 0 {
		t.Fatalf("lvremove of %s, a volume taken out of the spec: %v calls %v", lv, rt.removed, g.rt.Calls)
	}
	if ids, _ := inner.List(g.ctx); len(ids) != 1 {
		t.Fatalf("the copy was not kept: %v", ids)
	}
	if _, kept := g.a.keptNoted.Load(s.UID); !kept {
		t.Fatal("the copy was not kept")
	}
}

// The same volume, handed off: the copy stays and that LV is not removed.
func TestAVolumeTakenOutOfTheSpecIsKeptWhenTheCopyIsHandedOff(t *testing.T) {
	inner := fake.New()
	const lv = "kv-web-data"
	rt := &diskRT{Runtime: inner, lv: lv}
	g := newGuardRig(t, rt, func(a *Agent) {
		a.Runtimes = map[string]kri.Runtime{"cloud-hypervisor": rt}
	})
	g.rt = inner
	s := g.create(travellingSilo("web", ""), "hv2", "hv1")
	g.runtimeCopy(s, kri.Created)
	g.cacheIs(g.stored("web"))
	if _, err := g.reconcile("web"); err != nil {
		t.Fatal(err)
	}
	if len(rt.removed) != 0 || len(g.calls("delete")) != 0 {
		t.Fatalf("lvremove of %s, a volume taken out of the spec: %v calls %v", lv, rt.removed, g.rt.Calls)
	}
	if ids, _ := inner.List(g.ctx); len(ids) != 1 {
		t.Fatalf("the copy was not kept: %v", ids)
	}
}

// A recreate hands the silo off and makes it afresh on the other host. The old root disk is
// this host's, and it goes with the copy: nothing of it is kept.
func TestARecreateHandoffOfAHostLocalRootRemovesTheCopy(t *testing.T) {
	inner := fake.New()
	rt := &diskRT{Runtime: inner}
	g := newGuardRig(t, rt, func(a *Agent) {
		a.Runtimes = map[string]kri.Runtime{"cloud-hypervisor": rt}
	})
	g.rt = inner
	s := g.create(hostLocalVM("web"), "hv2", "hv1")
	rt.lv = cloudhypervisor.NamesFor(idOf(s)).LV
	g.runtimeCopy(s, kri.Created)
	g.cacheIs(g.stored("web"))
	if _, err := g.reconcile("web"); err != nil {
		t.Fatal(err)
	}
	if len(g.calls("delete")) != 1 {
		t.Fatalf("the old copy was kept: calls %v removed %v", g.rt.Calls, rt.removed)
	}
	if len(rt.removed) != 1 || rt.removed[0] != "lvremove "+rt.lv {
		t.Fatalf("root LV %s: %v", rt.lv, rt.removed)
	}
	if ids, _ := inner.List(g.ctx); len(ids) != 0 {
		t.Fatalf("the copy stayed: %v", ids)
	}
}

func TestATravellingDiskWithAHostLocalVolumeIsKept(t *testing.T) {
	g := newGuardRig(t, nil, func(a *Agent) {
		a.Runtimes = map[string]kri.Runtime{"cloud-hypervisor": a.Runtimes["docker"]}
	})
	s := g.create(travellingSilo("web", "data"), "hv2", "")
	g.runtimeCopy(s, kri.Created)
	g.cacheIs(g.stored("web"))
	if _, err := g.reconcile("web"); err != nil {
		t.Fatal(err)
	}
	if len(g.calls("delete")) != 0 {
		t.Fatalf("deleted a copy that holds a host-local volume: %v", g.rt.Calls)
	}
	if _, kept := g.a.keptNoted.Load(s.UID); !kept {
		t.Fatal("the copy was not kept")
	}
}

// Coming back to a host that kept a travelling copy starts from the silo's current state,
// trusting the guest host key the silo reports, not the copy that was left here.
func TestAKeptTravellingCopyIsNotResumedWhenTheSiloReturns(t *testing.T) {
	share := kplugintest.New()
	reg := &plugins.Registry{}
	g := newGuardRig(t, nil, func(a *Agent) {
		a.Runtimes = map[string]kri.Runtime{"cloud-hypervisor": a.Runtimes["docker"]}
		a.Nodes = reg
	})
	if err := reg.Add(g.ctx, share.Node("hv1")); err != nil {
		t.Fatal(err)
	}
	const reported = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIReportedGuestKey000000000"
	s := g.create(travellingSilo("web", ""), "hv1", "")
	st, err := share.EnsureVolume(g.ctx, kplugin.Volume{Class: kplugintest.ClassShare, ID: s.UID + "/disk.root"})
	if err != nil {
		t.Fatal(err)
	}
	g.setGuestKey(s, reported, st.Handle)
	s = g.stored("web")
	g.runtimeCopy(s, kri.Created)
	g.rt.Calls = nil
	g.a.keptNoted.Store(s.UID, keptCopy{runtime: "cloud-hypervisor", id: idOf(s), name: "kept"})
	g.a.nodeMounts.Store(g.a.VolumePath(s.UID, v1.RootDiskVolume), st.Handle)
	g.until("web", "create")
	sawDelete := false
	for _, c := range g.rt.Calls {
		if strings.HasPrefix(c, "delete") {
			sawDelete = true
		}
		if strings.HasPrefix(c, "start") && !sawDelete {
			t.Fatalf("started the kept copy: %v", g.rt.Calls)
		}
	}
	if !sawDelete {
		t.Fatalf("the kept copy was not dropped: %v", g.rt.Calls)
	}
	spec, ok := g.rt.Spec(idOf(g.stored("web")))
	if !ok || spec.GuestHostKey != reported {
		t.Fatalf("create trusted %q, want %q (ok %v)", spec.GuestHostKey, reported, ok)
	}
}

func TestAHostLocalDiskDoesNotTrustAReportedGuestKey(t *testing.T) {
	g := newGuardRig(t, nil, nil)
	s := g.create(guardSilo("web", nil), "hv1", "")
	g.setGuestKey(s, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIReportedGuestKey000000000", "")
	g.until("web", "create")
	spec, ok := g.rt.Spec(idOf(g.stored("web")))
	if !ok || spec.GuestHostKey != "" {
		t.Fatalf("a host-local disk's create trusted %q", spec.GuestHostKey)
	}
}

type keyRT struct {
	*fake.Runtime
	key string
}

func (k *keyRT) GuestHostKey(kri.ID) (string, bool) { return k.key, k.key != "" }

func TestARunningSiloReportsTheGuestKeyItTrusts(t *testing.T) {
	inner := fake.New()
	rt := &keyRT{Runtime: inner, key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPinnedOnThisHost00000000"}
	g := newGuardRig(t, rt, func(a *Agent) { a.endpoint = &Endpoint{} })
	g.rt = inner
	g.create(guardSilo("web", nil), "hv1", "")
	g.until("web", "start")
	g.cacheIs(g.stored("web"))
	if _, err := g.reconcile("web"); err != nil {
		t.Fatal(err)
	}
	if got := g.stored("web").Status.GuestHostKey; got != rt.key {
		t.Fatalf("status guest key %q, want %q", got, rt.key)
	}
}

type adoptRT struct {
	*fake.Runtime
	adopted string
}

func (a *adoptRT) SetGuestHostKey(_ context.Context, _ kri.ID, pub string) error {
	a.adopted = pub
	return nil
}

// A travelling disk that also has a host-local volume stays (that volume is this host's),
// and the key this host trusts becomes the one the silo reports.
func TestAKeptLocalVolumeAdoptsTheReportedGuestKey(t *testing.T) {
	inner := fake.New()
	rt := &adoptRT{Runtime: inner}
	share := kplugintest.New()
	reg := &plugins.Registry{}
	g := newGuardRig(t, rt, func(a *Agent) {
		a.Runtimes = map[string]kri.Runtime{"cloud-hypervisor": rt}
		a.Nodes = reg
	})
	g.rt = inner
	if err := reg.Add(g.ctx, share.Node("hv1")); err != nil {
		t.Fatal(err)
	}
	const reported = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIReportedGuestKey000000000"
	s := g.create(travellingSilo("web", "data"), "hv1", "")
	st, err := share.EnsureVolume(g.ctx, kplugin.Volume{Class: kplugintest.ClassShare, ID: s.UID + "/disk.root"})
	if err != nil {
		t.Fatal(err)
	}
	g.setGuestKey(s, reported, st.Handle)
	s = g.stored("web")
	g.runtimeCopy(s, kri.Stopped)
	g.a.keptNoted.Store(s.UID, keptCopy{runtime: "cloud-hypervisor", id: idOf(s), name: "kept"})
	g.a.nodeMounts.Store(g.a.VolumePath(s.UID, v1.RootDiskVolume), st.Handle)
	g.cacheIs(s)
	if _, err := g.reconcile("web"); err != nil {
		t.Fatal(err)
	}
	if len(g.calls("delete")) != 0 {
		t.Fatalf("deleted a copy that holds a host-local volume: %v", g.rt.Calls)
	}
	if rt.adopted != reported {
		t.Fatalf("adopted %q, want %q", rt.adopted, reported)
	}
}

func TestRemovingAKeptCopyOfALocalDiskSaysTheSharedVolumeStays(t *testing.T) {
	g := newGuardRig(t, nil, nil)
	g.create(guardSilo("web", func(s *v1.Silo) {
		s.Spec.Runtime = "cloud-hypervisor"
		s.Spec.Container = nil
		s.Spec.VM = &v1.VMSource{Image: "ubuntu-24.04"}
		s.Spec.Disk = v1.Disk{Size: "20Gi"}
		s.Spec.Volumes = []v1.Volume{{Name: "home", Class: kplugintest.ClassShare, Size: "5Gi", MountPath: "/home"}}
	}), "hv2", "")
	g.cacheIs(g.stored("web"))
	id := idOf(g.stored("web"))
	g.a.keptNoted.Store(id.UID, keptCopy{runtime: "cloud-hypervisor", id: id, name: keptName(id, `cloud-hypervisor, stopped`)})
	dir := t.TempDir()
	g.a.DeletesFile = filepath.Join(dir, "seen-deletes.json")
	if err := os.Mkdir(filepath.Join(dir, KeptRemoveDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, KeptRemoveDir, id.UID), []byte("remove\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var lines []string
	g.a.Log = func(f string, args ...any) { lines = append(lines, fmt.Sprintf(f, args...)) }
	g.a.takeKeptRemovals()
	got := strings.Join(lines, "\n")
	if !strings.Contains(got, "for good") || !strings.Contains(got, "the volumes on "+kplugintest.ClassShare+" stay") {
		t.Fatalf("log:\n%s", got)
	}
	if strings.Contains(got, "only this host's copy") {
		t.Fatalf("a local disk was said to delete only the copy:\n%s", got)
	}
}

func TestRemovingAKeptCopySaysWhatThisHostDeletesAndWhatStays(t *testing.T) {
	g := newGuardRig(t, nil, nil)
	g.create(mixedSilo("web"), "hv2", "")
	g.cacheIs(g.stored("web"))
	id := idOf(g.stored("web"))
	g.a.keptNoted.Store(id.UID, keptCopy{runtime: "cloud-hypervisor", id: id, name: keptName(id, `cloud-hypervisor, stopped`)})
	dir := t.TempDir()
	g.a.DeletesFile = filepath.Join(dir, "seen-deletes.json")
	if err := os.Mkdir(filepath.Join(dir, KeptRemoveDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, KeptRemoveDir, id.UID), []byte("remove\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var lines []string
	g.a.Log = func(f string, args ...any) { lines = append(lines, fmt.Sprintf(f, args...)) }
	g.a.writeKeptFile()
	var list []KeptEntry
	if err := json.Unmarshal(mustReadFile(t, filepath.Join(dir, KeptFile)), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Shared != kplugintest.ClassShare || !list[0].OnHost {
		t.Fatalf("kept list: %+v", list)
	}
	g.a.takeKeptRemovals()
	got := strings.Join(lines, "\n")
	if !strings.Contains(got, "for good") || !strings.Contains(got, "the volumes on "+kplugintest.ClassShare+" stay") {
		t.Fatalf("log:\n%s", got)
	}
	if strings.Contains(got, "only this host's copy") {
		t.Fatalf("a copy with a disk on this host was said to delete only the copy:\n%s", got)
	}
}

// The volume is gone from the spec, but this host still holds its LV. The removal says both.
func TestRemovingAKeptCopyWithStorageOnTheHostSaysBoth(t *testing.T) {
	inner := fake.New()
	rt := &diskRT{Runtime: inner, lv: "kv-web-data"}
	g := newGuardRig(t, rt, func(a *Agent) {
		a.Runtimes = map[string]kri.Runtime{"cloud-hypervisor": rt}
	})
	g.create(travellingSilo("web", ""), "hv2", "")
	home := g.stored("web")
	home.Spec.Volumes = []v1.Volume{{Name: "home", Class: kplugintest.ClassShare, Size: "5Gi", MountPath: "/home"}}
	g.cacheIs(home)
	id := idOf(home)
	g.a.keptNoted.Store(id.UID, keptCopy{runtime: "cloud-hypervisor", id: id, name: keptName(id, `cloud-hypervisor, stopped`)})
	dir := t.TempDir()
	g.a.DeletesFile = filepath.Join(dir, "seen-deletes.json")
	if err := os.Mkdir(filepath.Join(dir, KeptRemoveDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, KeptRemoveDir, id.UID), []byte("remove\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var lines []string
	g.a.Log = func(f string, args ...any) { lines = append(lines, fmt.Sprintf(f, args...)) }
	g.a.takeKeptRemovals()
	got := strings.Join(lines, "\n")
	if !strings.Contains(got, "for good") || !strings.Contains(got, "the volumes on "+kplugintest.ClassShare+" stay") {
		t.Fatalf("log:\n%s", got)
	}
	if strings.Contains(got, "only this host's copy") {
		t.Fatalf("a copy that holds a disk here was said to delete only the copy:\n%s", got)
	}
}

// A list that fails is not "nothing on this host": the removal still says the disk here goes.
func TestRemovingAKeptCopyDoesNotTreatAFailedListAsNothingHere(t *testing.T) {
	inner := fake.New()
	rt := &diskRT{Runtime: inner, err: errors.New("lvs failed")}
	g := newGuardRig(t, rt, func(a *Agent) {
		a.Runtimes = map[string]kri.Runtime{"cloud-hypervisor": rt}
	})
	g.create(travellingSilo("web", ""), "hv2", "")
	home := g.stored("web")
	home.Spec.Volumes = []v1.Volume{{Name: "home", Class: kplugintest.ClassShare, Size: "5Gi", MountPath: "/home"}}
	g.cacheIs(home)
	id := idOf(home)
	g.a.keptNoted.Store(id.UID, keptCopy{runtime: "cloud-hypervisor", id: id, name: keptName(id, `cloud-hypervisor, stopped`)})
	dir := t.TempDir()
	g.a.DeletesFile = filepath.Join(dir, "seen-deletes.json")
	if err := os.Mkdir(filepath.Join(dir, KeptRemoveDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, KeptRemoveDir, id.UID), []byte("remove\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var lines []string
	g.a.Log = func(f string, args ...any) { lines = append(lines, fmt.Sprintf(f, args...)) }
	g.a.takeKeptRemovals()
	got := strings.Join(lines, "\n")
	if !strings.Contains(got, "for good") || !strings.Contains(got, "the volumes on "+kplugintest.ClassShare+" stay") {
		t.Fatalf("log:\n%s", got)
	}
	if strings.Contains(got, "only this host's copy") {
		t.Fatalf("a copy whose disks could not be listed was said to delete only the copy:\n%s", got)
	}
}

func TestRemovingAKeptCopyOfATravellingDiskLeavesTheVolumes(t *testing.T) {
	g := newGuardRig(t, nil, nil)
	g.create(travellingSilo("web", ""), "hv2", "")
	g.cacheIs(g.stored("web"))
	id := idOf(g.stored("web"))
	g.a.keptNoted.Store(id.UID, keptCopy{runtime: "cloud-hypervisor", id: id, name: keptName(id, `cloud-hypervisor, stopped`)})
	dir := t.TempDir()
	g.a.DeletesFile = filepath.Join(dir, "seen-deletes.json")
	if err := os.Mkdir(filepath.Join(dir, KeptRemoveDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, KeptRemoveDir, id.UID), []byte("remove\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var lines []string
	g.a.Log = func(f string, args ...any) { lines = append(lines, fmt.Sprintf(f, args...)) }
	g.a.writeKeptFile()
	var list []KeptEntry
	if err := json.Unmarshal(mustReadFile(t, filepath.Join(dir, KeptFile)), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Shared != kplugintest.ClassShare {
		t.Fatalf("kept list: %+v", list)
	}
	g.a.takeKeptRemovals()
	got := strings.Join(lines, "\n")
	if !strings.Contains(got, "only this host's copy") || !strings.Contains(got, "the volumes on "+kplugintest.ClassShare+" stay") {
		t.Fatalf("log:\n%s", got)
	}
	if strings.Contains(got, "its disk and volumes go") {
		t.Fatalf("the log says the travelling volumes go:\n%s", got)
	}
}

func mustReadFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mixedSilo(name string) *v1.Silo {
	return guardSilo(name, func(s *v1.Silo) {
		s.Spec.Runtime = "cloud-hypervisor"
		s.Spec.Container = nil
		s.Spec.VM = &v1.VMSource{Image: "ubuntu-24.04"}
		s.Spec.Disk = v1.Disk{Size: "20Gi"}
		s.Spec.Volumes = []v1.Volume{
			{Name: "data", MountPath: "/data"},
			{Name: "home", Class: kplugintest.ClassShare, Size: "5Gi", MountPath: "/home"},
		}
	})
}

// failOnceStatus refuses the first status PUT and lets the rest through.
type failOnceStatus struct {
	base http.RoundTripper
	n    atomic.Int32
}

func (f *failOnceStatus) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/status") && f.n.Add(1) == 1 {
		return nil, errors.New("status write refused once")
	}
	return f.base.RoundTrip(r)
}

// A silo with a service is placed elsewhere. The old host's away write records the volume
// unmounted and leaves routing as it was stored. A write that does not land leaves the copy,
// so the next look records the mount and then forgets it.
func TestAnAwayWriteClearsTheMountAndKeepsRouting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory(0)
	srv, err := apiserver.NewWithAuth(st, clock.Real{}, &apiserver.Auth{CA: ca, Tokens: &jointoken.Issuer{Store: st, Clock: clock.Real{}}})
	if err != nil {
		t.Fatal(err)
	}
	as := httptest.NewUnstartedServer(srv)
	as.Config = srv.HTTPServer(true)
	as.Start()
	defer as.Close()
	admin := client.New(as.URL)
	host, closeHost := srv.InProcessAs(pki.Identity{Type: "host", Name: "hv1", Role: "worker"})
	defer closeHost()
	host.HTTP.Transport = &failOnceStatus{base: host.HTTP.Transport}

	if err := admin.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}}); err != nil {
		t.Fatal(err)
	}
	s := travellingSilo("web", "")
	s.Spec.Ports = []v1.SiloPort{{Name: "web", Port: 8080}}
	s.Spec.Service = &v1.SiloService{RouteWhen: v1.RouteWhenRunning, Ports: []v1.ServicePort{{Port: "web"}}}
	s.Spec.Volumes = []v1.Volume{{Name: "home", Class: kplugintest.ClassShare, Size: "5Gi", MountPath: "/home"}}
	if err := admin.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	var cur v1.Silo
	if err := admin.Get(ctx, "Silo", "dev", "web", &cur); err != nil {
		t.Fatal(err)
	}
	cur.Status.Host, cur.Status.Phase, cur.Status.SiloIP = "hv1", "Running", "10.64.0.2"
	cur.Status.Volumes = []v1.VolumeStatus{{
		Name: "home", Class: kplugintest.ClassShare, Handle: "home-1", AttachedTo: "hv1", Mounted: true,
	}}
	cur.Status.Routing = routing.Silo(cur.Spec, cur.Status)
	if cur.Status.Routing == nil || !cur.Status.Routing.Routed {
		t.Fatalf("running routing: %+v", cur.Status.Routing)
	}
	if err := admin.UpdateStatus(ctx, &cur); err != nil {
		t.Fatal(err)
	}
	if err := admin.Get(ctx, "Silo", "dev", "web", &cur); err != nil {
		t.Fatal(err)
	}
	want := *cur.Status.Routing
	cur.Status.Host, cur.Status.Phase, cur.Status.SiloIP, cur.Status.MovingFrom = "hv2", "Scheduled", "", ""
	if err := admin.UpdateStatus(ctx, &cur); err != nil {
		t.Fatal(err)
	}
	if err := admin.Get(ctx, "Silo", "dev", "web", &cur); err != nil {
		t.Fatal(err)
	}
	if cur.Status.Routing == nil || *cur.Status.Routing != want {
		t.Fatalf("the placement rewrote routing: %+v", cur.Status.Routing)
	}

	inner := fake.New()
	rt := &diskRT{Runtime: inner}
	a := &Agent{Client: host, HostName: "hv1", Runtimes: map[string]kri.Runtime{"cloud-hypervisor": rt}, Clock: clock.Real{}, Log: t.Logf, runCtx: ctx}
	a.silos, a.secrets, a.grants = informer.New(host, "Silo"), informer.New(host, "Secret"), informer.New(host, "Grant")
	a.silos.Seed([]meta.Object{&cur})
	a.secrets.Seed(nil)
	a.grants.Seed(nil)
	if err := inner.Create(ctx, kri.Spec{ID: idOf(&cur), Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Reconcile(ctx, engine.Key{Kind: "Silo", Namespace: "dev", Name: "web"}); err == nil {
		t.Fatal("the first away write was accepted")
	}
	if ids, _ := inner.List(ctx); len(ids) != 1 {
		t.Fatalf("the copy was forgotten before the mount was recorded: %v", ids)
	}
	if _, err := a.Reconcile(ctx, engine.Key{Kind: "Silo", Namespace: "dev", Name: "web"}); err != nil {
		t.Fatal(err)
	}
	var got v1.Silo
	if err := admin.Get(ctx, "Silo", "dev", "web", &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Status.Volumes) != 1 || got.Status.Volumes[0].Mounted {
		t.Fatalf("mount: %+v", got.Status.Volumes)
	}
	if got.Status.Routing == nil || !reflect.DeepEqual(*got.Status.Routing, want) {
		t.Fatalf("routing %+v, want %+v", got.Status.Routing, want)
	}
	if ids, _ := inner.List(ctx); len(ids) != 0 {
		t.Fatalf("the copy stayed after the mount was recorded: %v", ids)
	}
}

func hostLocalVM(name string) *v1.Silo {
	return guardSilo(name, func(s *v1.Silo) {
		s.Spec.Runtime = "cloud-hypervisor"
		s.Spec.Container = nil
		s.Spec.VM = &v1.VMSource{Image: "ubuntu-24.04"}
		s.Spec.Disk = v1.Disk{Size: "20Gi"}
	})
}

func travellingSilo(name, localVolume string) *v1.Silo {
	return guardSilo(name, func(s *v1.Silo) {
		s.Spec.Runtime = "cloud-hypervisor"
		s.Spec.Container = nil
		s.Spec.VM = &v1.VMSource{Image: "ubuntu-24.04"}
		s.Spec.Disk = v1.Disk{Class: kplugintest.ClassShare, Size: "20Gi"}
		if localVolume != "" {
			s.Spec.Volumes = []v1.Volume{{Name: localVolume, MountPath: "/data"}}
		}
	})
}

func (g *guardRig) setGuestKey(s *v1.Silo, key, handle string) {
	g.t.Helper()
	for {
		cur := g.stored(s.Name)
		cur.Status.GuestHostKey = key
		if handle != "" {
			cur.Status.Volumes = []v1.VolumeStatus{{
				Name: v1.RootDiskVolume, Class: kplugintest.ClassShare, Handle: handle,
				AttachedTo: "hv1", Mounted: true,
			}}
		}
		err := g.c.UpdateStatus(g.ctx, cur)
		if err == nil {
			return
		}
		if !client.IsConflict(err) {
			g.t.Fatal(err)
		}
	}
}
