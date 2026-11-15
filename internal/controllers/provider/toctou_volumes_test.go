package provider_test

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	hostctl "kevaso.com/core/internal/controllers/host"
	"kevaso.com/core/internal/controllers/provider"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

// afterRead is a transport that runs fn once, right after the first GET of path has been
// answered: what other writers do between a controller's read and what it does next.
type afterRead struct {
	base http.RoundTripper
	path string
	once sync.Once
	fn   func()
}

func (a *afterRead) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := a.base.RoundTrip(r)
	if err == nil && r.Method == http.MethodGet && r.URL.Path == a.path && !strings.Contains(r.URL.RawQuery, "watch") {
		a.once.Do(a.fn)
	}
	return resp, err
}

// Review (check-then-act) item 1: the volumes controller decides to remove a volume from the
// silo as it read it (not in the spec, unmounted). Between that read and the plugin calls, the
// user puts the volume back and the host mounts it. The controller must not detach or delete a
// disk that is wanted and mounted: the removal is made a conditional write first, which then
// conflicts, and nothing destructive is done.
func TestARemovalDecidedFromAReadDoesNotDeleteAVolumePutBackAndMounted(t *testing.T) {
	x := newK037(t)
	s := x.silo("db", "w1")
	handle := s.Status.Volumes[0].Handle
	// The user removes the volume from the spec.
	s.Spec.Volumes = nil
	x.must(x.c.Update(x.ctx, s))
	hooked := &afterRead{base: http.DefaultTransport, path: "/apis/kevaso/v1/namespaces/d/silos/db", fn: func() {
		// …and puts it back; the host (w1, attached) mounts it and says so.
		cur := x.get("db")
		cur.Spec.Volumes = []v1.Volume{{Name: "data", Class: kplugintest.ClassBlock, Size: "1Gi", MountPath: "/data"}}
		x.must(x.c.Update(x.ctx, cur))
		cur = x.get("db")
		cur.Status.Volumes[0].Mounted = true
		x.must(x.c.UpdateStatus(x.ctx, cur))
	}}
	ctl := x.volumes()
	ctl.Client = &client.Client{BaseURL: x.c.BaseURL, HTTP: &http.Client{Transport: hooked}}
	mark := len(x.fake.CallLog())
	_, _ = ctl.Reconcile(x.ctx, engine.Key{Kind: "Silo", Namespace: "d", Name: "db"})
	if calls := x.callsOn(mark, handle); len(calls) > 0 {
		t.Fatalf("plugin calls on a volume put back and mounted: %v", calls)
	}
	_, vols, _ := x.fake.Snapshot()
	if v, ok := vols[handle]; !ok || v.AttachedTo != "1" {
		t.Fatalf("the volume put back and mounted was detached or deleted: %+v %v", v, ok)
	}
	// Decided again on what is stored now: kept, mounted.
	x.reconcile("db")
	if got := x.get("db"); len(got.Status.Volumes) != 1 || !got.Status.Volumes[0].Mounted {
		t.Fatalf("after deciding again: %+v", got.Status.Volumes)
	}
	_ = provider.FinalizerVolumes
}

// Review (check-then-act) item 1, the forced release: a volume still mounted on a host that was
// lost (its silo fenced and moved) is detached anyway; but only if that host is lost now. A host
// cache that still says lost after the host came back must not detach a disk its guest has open.
func TestAForcedReleaseReadsTheHostFresh(t *testing.T) {
	x := newK037(t)
	s := x.silo("db", "w1")
	handle := s.Status.Volumes[0].Handle
	s.Status.Volumes[0].Mounted = true
	x.must(x.c.UpdateStatus(x.ctx, s))
	setReady := func(name string, lost bool) {
		var h v1.Host
		x.must(x.c.Get(x.ctx, "Host", "", name, &h))
		h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionTrue, LastTransitionTime: time.Now().UTC().Truncate(time.Second)}}
		if lost {
			h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionUnknown, Reason: hostctl.ReasonLost, LastTransitionTime: time.Now().UTC().Truncate(time.Second)}}
		}
		x.must(x.c.UpdateStatus(x.ctx, &h))
	}
	setReady("w1", true)
	// A person moved it, confirming w1 fenced: placed on w2, no handoff.
	s = x.get("db")
	s.Status.Host = "w2"
	x.must(x.c.UpdateStatus(x.ctx, s))
	ctl := x.volumes()    // its host cache: w1 lost
	setReady("w1", false) // w1 is back, the disk still open there
	mark := len(x.fake.CallLog())
	if _, err := ctl.Reconcile(x.ctx, engine.Key{Kind: "Silo", Namespace: "d", Name: "db"}); err != nil {
		t.Fatal(err)
	}
	if calls := x.callsOn(mark, handle); len(calls) > 0 {
		t.Fatalf("detached from w1, which is back, on a cache that said lost: %v", calls)
	}
	// Lost now, fresh: forced off, as before.
	setReady("w1", true)
	if _, err := x.volumes().Reconcile(x.ctx, engine.Key{Kind: "Silo", Namespace: "d", Name: "db"}); err != nil {
		t.Fatal(err)
	}
	if calls := x.callsOn(mark, handle); len(calls) == 0 || !strings.HasPrefix(calls[0], "detach") {
		t.Fatalf("not forced off a host lost now: %v", calls)
	}
}
