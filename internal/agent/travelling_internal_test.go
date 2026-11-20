package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/plugins"
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
}

func (d *diskRT) HasHostStorage(context.Context, kri.ID) (bool, error) {
	return d.lv != "", nil
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
