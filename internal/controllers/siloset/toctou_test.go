package siloset_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/controllers/siloset"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/store"
)

type setEnv struct {
	ctx context.Context
	t   *testing.T
	c   *client.Client
}

func newSetEnv(t *testing.T) *setEnv {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	srv, err := apiserver.New(store.NewMemory(0), clock.NewFake(t0))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	e := &setEnv{ctx: ctx, t: t, c: client.New(ts.URL)}
	e.must(e.c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "web3"}}))
	return e
}

func (e *setEnv) must(err error) {
	e.t.Helper()
	if err != nil {
		e.t.Fatal(err)
	}
}

// ctl is the controller on caches listed now, that hear nothing more.
func (e *setEnv) ctl() *siloset.Controller {
	frozen := func(kind string) *informer.Informer {
		ictx, stop := context.WithCancel(e.ctx)
		inf := informer.New(e.c, kind)
		go inf.Run(ictx)
		if !inf.WaitSynced(e.ctx) {
			e.t.Fatalf("%s never synced", kind)
		}
		stop()
		return inf
	}
	return &siloset.Controller{Client: e.c, Sets: frozen("SiloSet"), Silos: frozen("Silo"), Clock: clock.NewFake(t0)}
}

func (e *setEnv) reconcile(c *siloset.Controller) {
	e.t.Helper()
	_, _ = c.Reconcile(e.ctx, engine.Key{Kind: "SiloSet", Namespace: "web3", Name: "rpc"})
}

func (e *setEnv) silos() []v1.Silo {
	l, err := e.c.List(e.ctx, "Silo", "web3")
	e.must(err)
	var out []v1.Silo
	for _, raw := range l.Items {
		o, _, err := v1.Decode(raw)
		e.must(err)
		if s := o.(*v1.Silo); s.DeletionTimestamp == nil {
			out = append(out, *s)
		}
	}
	return out
}

func (e *setEnv) setInstances(n int) {
	var s v1.SiloSet
	e.must(e.c.Get(e.ctx, "SiloSet", "web3", "rpc", &s))
	s.Spec.Instances = n
	e.must(e.c.Update(e.ctx, &s))
}

// two makes the set with two instances, as the controller makes them.
func (e *setEnv) two() {
	set := newSet(2)
	set.TypeMeta = meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "SiloSet"}
	set.UID, set.Generation = "", 0
	e.must(e.c.Create(e.ctx, set))
	for range 5 {
		if len(e.silos()) == 2 {
			return
		}
		e.reconcile(e.ctl())
	}
	e.t.Fatalf("instances: %d", len(e.silos()))
}

// Review (check-then-act) item 6: a scale-in decided from a cached set (instances 1) must not
// delete an instance once the set says 2 again: the decision is committed by a write at the
// set's version it was read at, which then conflicts.
func TestAScaleInRaisedAgainAfterTheReadDeletesNothing(t *testing.T) {
	e := newSetEnv(t)
	e.two()
	e.setInstances(1)
	stale := e.ctl() // the set as it was: one instance
	e.setInstances(2)
	e.reconcile(stale)
	if n := len(e.silos()); n != 2 {
		t.Fatalf("an instance was deleted on a scale-in raised back after the read: %d left", n)
	}
}

// …and one protected after the read is not deleted (its delete carries the version decided on,
// and the protection is checked on a fresh read).
func TestAnInstanceProtectedAfterTheReadIsNotDeleted(t *testing.T) {
	e := newSetEnv(t)
	e.two()
	e.setInstances(1)
	stale := e.ctl()
	for _, s := range e.silos() {
		s.Labels = map[string]string{v1.LabelProtected: "true"}
		e.must(e.c.Update(e.ctx, &s))
	}
	e.reconcile(stale)
	if n := len(e.silos()); n != 2 {
		t.Fatalf("an instance protected after the read was deleted: %d left", n)
	}
}
