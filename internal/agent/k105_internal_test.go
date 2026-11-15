package agent

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// namesUnreadable is the fake as a runtime with a state file it can't read.
type namesUnreadable struct{ *fake.Runtime }

func (namesUnreadable) Unreadable(context.Context) []string {
	return []string{"/var/lib/kevaso/containers/abc123/state.json"}
}

// K-105: what a runtime can't read, and so doesn't list, is named on the Host (KeptSilos): the
// silo behind it may run, and nothing that may run here is invisible.
func TestAStateARuntimeCantReadIsListedOnTheHost(t *testing.T) {
	g := newGuardRig(t, namesUnreadable{fake.New()}, nil)
	if err := g.c.Create(g.ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv1"},
		Spec: v1.HostSpec{InternalIP: "10.0.0.1", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
		t.Fatal(err)
	}
	g.a.reportKept(g.ctx, "")
	var h v1.Host
	if err := g.c.Get(g.ctx, "Host", "", "hv1", &h); err != nil {
		t.Fatal(err)
	}
	c := meta.FindCondition(h.Status.Conditions, ConditionKeptSilos)
	if c == nil || !strings.Contains(c.Message, "abc123/state.json") {
		t.Fatalf("a state file the runtime can't read isn't named on the Host: %+v", c)
	}
}

// hidesFrom is the fake as a runtime whose List no longer names a silo (its state file can't be
// read), which Status still finds by its name.
type hidesFrom struct {
	*fake.Runtime
	uid string
}

func (h hidesFrom) List(ctx context.Context) ([]kri.ID, error) {
	ids, err := h.Runtime.List(ctx)
	return slices.DeleteFunc(ids, func(id kri.ID) bool { return id.UID == h.uid }), err
}

// K-105, the fence record: a silo gone from the API whose runtime no longer lists it, but which
// still runs, stays in the record, so the fence watcher still stops it. Only a clean "absent",
// asked by its name, drops it.
func TestTheFenceRecordKeepsASiloItsRuntimeDoesntListWhileItRuns(t *testing.T) {
	old := goneEvery
	goneEvery = 0
	defer func() { goneEvery = old }()
	id := kri.ID{Namespace: "dev", Name: "db", UID: "u-db"}
	f := fake.New()
	g := newGuardRig(t, hidesFrom{f, id.UID}, nil)
	if err := f.Create(g.ctx, kri.Spec{ID: id, Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	if err := f.Start(g.ctx, id); err != nil {
		t.Fatal(err)
	}
	g.a.FenceDir = t.TempDir()
	g.a.silosSynced.Store(true)
	g.a.fencePrev.Silos = []fence.Silo{{ID: id, Runtime: "docker", StopAfter: time.Minute}}
	inRecord := func() bool {
		for _, s := range g.a.fenceRecord(g.ctx).Silos {
			if s.ID.UID == id.UID {
				return true
			}
		}
		return false
	}
	if !inRecord() {
		t.Fatal("a silo that still runs, which its runtime doesn't list, left the fence record: the watcher would no longer stop it")
	}
	if err := f.Delete(g.ctx, id); err != nil {
		t.Fatal(err)
	}
	if inRecord() {
		t.Fatal("a silo its runtime says is absent stays in the fence record")
	}
}
