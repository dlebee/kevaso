package agent

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// These tests drive the agent's reconcile by hand, against a real API server and the fake
// runtime, with the agent's silo cache filled by the test (Seed) so that "the cache is from before
// the control plane changed the silo" is a state the test sets, not a race it hopes for. Nothing
// sleeps, and nothing waits for a clock. Each guard has its own test because the guards overlap
// (a stale cache is caught by mayStartHere, then again by claimStart, then by the status write):
// removing one of them must still fail something (T-01, hack/mutate).

type guardRig struct {
	t   *testing.T
	ctx context.Context
	c   *client.Client
	a   *Agent
	rt  *fake.Runtime
	ts  *httptest.Server
}

func newGuardRig(t *testing.T, rt kri.Runtime, tweak func(*Agent)) *guardRig {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { cancel(); ts.Close() })
	c := client.New(ts.URL)
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}}); err != nil {
		t.Fatal(err)
	}
	g := &guardRig{t: t, ctx: ctx, c: c, ts: ts}
	if rt == nil {
		g.rt = fake.New()
		rt = g.rt
	}
	g.a = &Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{}, Log: t.Logf}
	g.a.silos = informer.New(c, "Silo")
	g.a.secrets, g.a.grants = informer.New(c, "Secret"), informer.New(c, "Grant")
	g.a.runCtx = ctx
	g.a.started, g.a.startedBoot = time.Now(), 0
	g.a.silos.Seed(nil)
	g.a.secrets.Seed(nil)
	g.a.grants.Seed(nil)
	if tweak != nil {
		tweak(g.a)
	}
	return g
}

func guardSilo(name string, mutate func(*v1.Silo)) *v1.Silo {
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"}}}
	if mutate != nil {
		mutate(s)
	}
	return s
}

// create stores a silo with the status the control plane would have given it.
func (g *guardRig) create(s *v1.Silo, host, movingFrom string) *v1.Silo {
	g.t.Helper()
	if err := g.c.Create(g.ctx, s); err != nil {
		g.t.Fatal(err)
	}
	g.setPlacement(s, host, movingFrom)
	return g.stored(s.Name)
}

// setPlacement is the control plane's write: where the silo is placed now.
func (g *guardRig) setPlacement(s *v1.Silo, host, movingFrom string) {
	g.t.Helper()
	for {
		var cur v1.Silo
		if err := g.c.Get(g.ctx, "Silo", s.Namespace, s.Name, &cur); err != nil {
			g.t.Fatal(err)
		}
		cur.Status.Host, cur.Status.MovingFrom, cur.Status.Phase = host, movingFrom, "Scheduled"
		err := g.c.UpdateStatus(g.ctx, &cur)
		if err == nil {
			return
		}
		if !client.IsConflict(err) {
			g.t.Fatal(err)
		}
	}
}

func (g *guardRig) stored(name string) *v1.Silo {
	g.t.Helper()
	var cur v1.Silo
	if err := g.c.Get(g.ctx, "Silo", "dev", name, &cur); err != nil {
		g.t.Fatal(err)
	}
	return &cur
}

// cacheIs fills the agent's silo cache with s as it is now: a later change in the store is not seen.
func (g *guardRig) cacheIs(s *v1.Silo) { g.a.silos.Seed([]meta.Object{s}) }

func (g *guardRig) reconcile(name string) (engine.Result, error) {
	return g.a.Reconcile(g.ctx, engine.Key{Kind: "Silo", Namespace: "dev", Name: name})
}

func (g *guardRig) calls(prefix string) []string {
	var out []string
	for _, c := range g.rt.Calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// until reconciles until the runtime has seen op (a start, a create), at most 12 times.
func (g *guardRig) until(name, op string) {
	g.t.Helper()
	for range 12 {
		g.cacheIs(g.stored(name))
		if _, err := g.reconcile(name); err != nil {
			g.t.Fatal(err)
		}
		if len(g.calls(op)) > 0 {
			return
		}
	}
	g.t.Fatalf("12 reconciles and the runtime never saw %q: %v", op, g.rt.Calls)
}

// T-01: a silo moving here (movingFrom says another host still has it) starts nothing here until
// the other host has let go. The pure moves.MayStart is tabled; this is its caller.
func TestAMoveToThisHostStartsNothingUntilTheSourceLetsGo(t *testing.T) {
	g := newGuardRig(t, nil, nil)
	s := g.create(guardSilo("web", nil), "hv1", "hv0")
	g.cacheIs(s)
	for range 3 { // however often it is looked at
		res, err := g.reconcile("web")
		if err != nil {
			t.Fatal(err)
		}
		if res.RequeueAfter == 0 {
			t.Fatal("a silo waiting for the source host is not looked at again")
		}
	}
	if len(g.rt.Calls) != 0 {
		t.Fatalf("this host touched a silo that hv0 still has: %v", g.rt.Calls)
	}
	got := g.stored("web")
	if c := meta.FindCondition(got.Status.Conditions, "Ready"); c == nil || c.Reason != "Moving" || !strings.Contains(c.Message, "hv0") {
		t.Fatalf("it does not say it waits for hv0: %+v", got.Status.Conditions)
	}
	// hv0 lets go (status.movingFrom cleared): now it starts, create before start.
	g.setPlacement(got, "hv1", "")
	g.until("web", "start")
	if c, s := g.calls("create"), g.calls("start"); len(c) != 1 || len(s) != 1 || slices.Index(g.rt.Calls, c[0]) > slices.Index(g.rt.Calls, s[0]) {
		t.Fatalf("calls %v", g.rt.Calls)
	}
}

// movingFrom the host itself (a move that came back, or ended here) does not hold the start.
func TestAMoveThatEndedOnThisHostDoesNotHoldTheStart(t *testing.T) {
	g := newGuardRig(t, nil, nil)
	s := g.create(guardSilo("web", nil), "hv1", "hv1")
	g.cacheIs(s)
	g.until("web", "start")
}

// A host does not run a silo placed on another host, nor one the cache has no placement for.
func TestASiloPlacedElsewhereIsNeverCreatedHere(t *testing.T) {
	for name, host := range map[string]string{"another host": "hv2", "no host yet": ""} {
		t.Run(name, func(t *testing.T) {
			g := newGuardRig(t, nil, nil)
			s := g.create(guardSilo("web", nil), host, "")
			g.cacheIs(s)
			if _, err := g.reconcile("web"); err != nil {
				t.Fatal(err)
			}
			if got := g.calls("create"); len(got) != 0 {
				t.Fatalf("created a silo placed on %q: %v", host, g.rt.Calls)
			}
			if got := g.calls("start"); len(got) != 0 {
				t.Fatalf("started a silo placed on %q: %v", host, g.rt.Calls)
			}
		})
	}
}

// K-015: the cache says "free to start here", the stored silo says another host still has it
// (a handoff began since). Whichever state the runtime copy is in, nothing is created or started.
// Each of the three states has its own call site of the check.
func TestAStaleCacheNeverCreatesOrStartsWhatTheStoreHoldsBack(t *testing.T) {
	type state struct {
		name  string
		setup func(g *guardRig, s *v1.Silo) // the runtime copy, before the reconcile
		calls []string                      // what must not be seen
	}
	states := []state{
		{"absent", func(*guardRig, *v1.Silo) {}, []string{"create", "start"}},
		{"stopped", func(g *guardRig, s *v1.Silo) { g.runtimeCopy(s, kri.Stopped) }, []string{"start"}},
		{"created", func(g *guardRig, s *v1.Silo) { g.runtimeCopy(s, kri.Created) }, []string{"start"}},
	}
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			g := newGuardRig(t, nil, nil)
			s := g.create(guardSilo("web", nil), "hv1", "")
			g.cacheIs(s) // free to start here
			st.setup(g, s)
			g.rt.Calls = nil
			g.setPlacement(s, "hv1", "hv0") // the control plane hands it to hv1 from hv0 since
			before := g.stored("web").ResourceVersion
			if _, err := g.reconcile("web"); err != nil {
				t.Fatal(err)
			}
			for _, op := range st.calls {
				if got := g.calls(op); len(got) != 0 {
					t.Fatalf("%s: the stored silo is held by hv0, and this host did %v", st.name, g.rt.Calls)
				}
			}
			if g.stored("web").ResourceVersion != before {
				t.Fatalf("%s: this host wrote to a silo it may not start", st.name)
			}
		})
	}
}

// failedRuntime reports every silo it has as Failed (a VMM that exited, a dead container).
type failedRuntime struct{ *fake.Runtime }

func (r failedRuntime) Status(ctx context.Context, id kri.ID) (kri.Status, error) {
	st, err := r.Runtime.Status(ctx, id)
	if err == nil && st.State != kri.Absent {
		st.State, st.Message = kri.Failed, "the VMM exited"
	}
	return st, err
}

func TestAStaleCacheNeverRestartsAFailedSiloThatTheStoreHoldsBack(t *testing.T) {
	inner := fake.New()
	g := newGuardRig(t, failedRuntime{inner}, nil)
	g.rt = inner
	s := g.create(guardSilo("web", nil), "hv1", "")
	g.cacheIs(s)
	g.runtimeCopy(s, kri.Created)
	g.rt.Calls = nil
	g.setPlacement(s, "hv1", "hv0")
	before := g.stored("web").ResourceVersion
	if _, err := g.reconcile("web"); err != nil {
		t.Fatal(err)
	}
	if got := g.calls("start"); len(got) != 0 {
		t.Fatalf("restarted a failed silo that hv0 still holds: %v", g.rt.Calls)
	}
	if g.stored("web").ResourceVersion != before {
		t.Fatal("wrote to a silo it may not start")
	}
}

func (g *guardRig) runtimeCopy(s *v1.Silo, want kri.State) {
	g.t.Helper()
	id := idOf(s)
	if err := g.rt.Create(g.ctx, kri.Spec{ID: id, Image: "ubuntu-24.04"}); err != nil {
		g.t.Fatal(err)
	}
	if want == kri.Stopped {
		if err := g.rt.Start(g.ctx, id); err != nil {
			g.t.Fatal(err)
		}
		if err := g.rt.Stop(g.ctx, id); err != nil {
			g.t.Fatal(err)
		}
	}
}

// claimStart and mayStartHere read the stored silo, never the cache, and refuse anything that is
// not the same silo, at the same generation, placed here and free to start, and not being deleted.
func TestTheStartClaimAndTheStartCheckRefuseAnySiloThatChanged(t *testing.T) {
	cases := []struct {
		name  string
		store func(g *guardRig, s *v1.Silo) // what the control plane did after the cache was filled
	}{
		{"placed on another host", func(g *guardRig, s *v1.Silo) { g.setPlacement(s, "hv2", "") }},
		{"handed over from another host", func(g *guardRig, s *v1.Silo) { g.setPlacement(s, "hv1", "hv0") }},
		{"its spec changed (another generation)", func(g *guardRig, s *v1.Silo) {
			cur := g.stored(s.Name)
			cur.Spec.Resources.Memory = "512Mi"
			if err := g.c.Update(g.ctx, cur); err != nil {
				g.t.Fatal(err)
			}
		}},
		{"deleted and created again (another uid)", func(g *guardRig, s *v1.Silo) {
			if err := g.c.Delete(g.ctx, "Silo", s.Namespace, s.Name); err != nil {
				g.t.Fatal(err)
			}
			again := g.create(guardSilo(s.Name, nil), "hv1", "")
			if again.UID == s.UID {
				g.t.Fatal("same uid")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newGuardRig(t, nil, nil)
			s := g.create(guardSilo("web", nil), "hv1", "")
			tc.store(g, s)
			if err := g.a.claimStart(g.ctx, s); !errors.Is(err, errPlacedElsewhere) {
				t.Fatalf("claimStart on a stale copy: %v, want errPlacedElsewhere", err)
			}
			if wait, err := g.a.mayStartHere(g.ctx, s); !wait || err != nil {
				t.Fatalf("mayStartHere on a stale copy: wait %v err %v, want to wait", wait, err)
			}
		})
	}
}

func TestTheStartClaimIsWrittenOnTheStoredSiloAndNamesTheHost(t *testing.T) {
	g := newGuardRig(t, nil, nil)
	s := g.create(guardSilo("web", nil), "hv1", "")
	if wait, err := g.a.mayStartHere(g.ctx, s); wait || err != nil {
		t.Fatalf("the silo is free to start here: wait %v err %v", wait, err)
	}
	if err := g.a.claimStart(g.ctx, s); err != nil {
		t.Fatal(err)
	}
	c := meta.FindCondition(g.stored("web").Status.Conditions, ConditionStartClaim)
	if c == nil || c.Status != meta.ConditionTrue || !strings.HasPrefix(c.Message, "starting on hv1 at ") {
		t.Fatalf("no start claim naming hv1: %+v", c)
	}
}

// A claim is a compare-and-swap on the version this host read: a write that lands between the
// read and the claim (the control plane placing the silo elsewhere) makes the claim a conflict,
// and a conflict means "not ours": the start is abandoned as placed elsewhere, not retried as an error.
func TestAClaimThatLosesTheRaceIsAnAbandonedStart(t *testing.T) {
	g := newGuardRig(t, nil, nil)
	s := g.create(guardSilo("web", nil), "hv1", "")
	var raced bool
	g.a.Client = client.New(g.ts.URL)
	g.a.Client.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/status") && !raced {
			raced = true
			g.setPlacement(s, "hv2", "") // the control plane's write, just before ours
		}
		return http.DefaultTransport.RoundTrip(r)
	})}
	err := g.a.claimStart(g.ctx, s)
	if !raced {
		t.Fatal("the race never happened: the test proves nothing")
	}
	if !errors.Is(err, errPlacedElsewhere) {
		t.Fatalf("claimStart that lost the race: %v, want errPlacedElsewhere", err)
	}
	if h := g.stored("web").Status.Host; h != "hv2" {
		t.Fatalf("our claim overwrote the placement: host %q", h)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A store read that fails is not a yes: nothing starts on a guess.
func TestAnUnreadableStoreIsNotAYesToStarting(t *testing.T) {
	g := newGuardRig(t, nil, nil)
	s := g.create(guardSilo("web", nil), "hv1", "")
	g.ts.Close()
	wait, err := g.a.mayStartHere(g.ctx, s)
	if !wait || err == nil {
		t.Fatalf("with the API unreachable: wait %v err %v, want to wait with the error", wait, err)
	}
	if err := g.a.claimStart(g.ctx, s); err == nil {
		t.Fatal("a claim was made with the API unreachable")
	}
}

// §0.7: while the control plane is held (a rolled-back or foreign history), the agent changes
// nothing: no create, no start, no removal.
func TestAHeldControlPlaneStopsEveryReconcile(t *testing.T) {
	g := newGuardRig(t, nil, func(a *Agent) {
		a.Watermark = OpenWatermark("", t.Logf)
		a.Watermark.mu.Lock()
		a.Watermark.kept.Held = true
		a.Watermark.mu.Unlock()
	})
	s := g.create(guardSilo("web", nil), "hv1", "")
	g.cacheIs(s)
	res, err := g.reconcile("web")
	if err != nil || res.RequeueAfter == 0 {
		t.Fatalf("held: %+v %v", res, err)
	}
	if len(g.rt.Calls) != 0 {
		t.Fatalf("a held worker acted: %v", g.rt.Calls)
	}
}

// The fence record is on disk before a silo that asked to stop on control-plane loss is created
// or started: a fence that does not know the silo cannot stop it. Checked at the moment of each
// runtime call, not afterwards.
func TestTheFenceRecordKnowsASiloBeforeItIsCreatedOrStarted(t *testing.T) {
	dir := t.TempDir()
	inner := fake.New()
	rt := &recordCheckingRuntime{Runtime: inner, dir: dir, t: t}
	g := newGuardRig(t, rt, func(a *Agent) { a.FenceDir = dir })
	g.rt = inner
	s := g.create(guardSilo("web", func(s *v1.Silo) {
		s.Spec.Availability = v1.Availability{OnControlPlaneLoss: v1.OnControlPlaneLossStop, OnHostLoss: v1.OnHostLossRecreate}
	}), "hv1", "")
	rt.uid = s.UID
	g.until("web", "start")
	if rt.createdKnown == 0 || rt.startedKnown == 0 {
		t.Fatalf("create seen %d times, start %d times: the checks never ran", rt.createdKnown, rt.startedKnown)
	}
}

// recordCheckingRuntime fails the test when Create or Start is called before the fence record
// holds the silo.
type recordCheckingRuntime struct {
	*fake.Runtime
	dir                        string
	t                          *testing.T
	uid                        string
	createdKnown, startedKnown int
}

func (r *recordCheckingRuntime) known() bool {
	rec, err := fence.Read(r.dir)
	if err != nil {
		return false
	}
	for _, s := range rec.Silos {
		if s.ID.UID == r.uid && s.StopAfter > 0 {
			return true
		}
	}
	return false
}

func (r *recordCheckingRuntime) Create(ctx context.Context, spec kri.Spec) error {
	if !r.known() {
		r.t.Errorf("Create before the fence record holds %s", spec.ID)
	} else {
		r.createdKnown++
	}
	return r.Runtime.Create(ctx, spec)
}

func (r *recordCheckingRuntime) Start(ctx context.Context, id kri.ID) error {
	if !r.known() {
		r.t.Errorf("Start before the fence record holds %s", id)
	} else {
		r.startedKnown++
	}
	return r.Runtime.Start(ctx, id)
}

// initHook is a container runtime (it has init containers) that does something in the middle of
// an init step: the gap between the agent's last check and its claim to start.
type initHook struct {
	*fake.Box
	during func()
}

func (r *initHook) RunInit(ctx context.Context, id kri.ID, step kri.InitStep, out io.Writer) (int, error) {
	if r.during != nil {
		r.during()
	}
	return r.Box.RunInit(ctx, id, step, out)
}

func initSilo(name string) *v1.Silo {
	return guardSilo(name, func(s *v1.Silo) {
		s.Spec.Init = &v1.Init{Steps: []v1.InitStep{{Name: "setup", Run: "true"}}}
	})
}

func (g *guardRig) boxCopy(s *v1.Silo, b *fake.Box) {
	g.t.Helper()
	if err := b.Create(g.ctx, kri.Spec{ID: idOf(s), Image: "ubuntu-24.04"}); err != nil {
		g.t.Fatal(err)
	}
}

func boxCalls(b *fake.Box, prefix string) []string {
	var out []string
	for _, c := range b.Calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// The start check comes before an existing copy's init steps and deliveries, not only before the
// claim: those steps run in the silo's containers, and a silo another host still holds must not
// have them run here (K-015). The stored silo is held by hv0; the cache is from before.
func TestAStaleCacheRunsNoInitStepsOnACopyTheStoreHoldsBack(t *testing.T) {
	box := fake.NewBox()
	g := newGuardRig(t, box, nil)
	s := g.create(initSilo("web"), "hv1", "")
	g.cacheIs(s)
	g.boxCopy(s, box)
	g.setPlacement(s, "hv1", "hv0")
	before := g.stored("web").ResourceVersion
	if _, err := g.reconcile("web"); err != nil {
		t.Fatal(err)
	}
	if got := boxCalls(box, "init"); len(got) != 0 {
		t.Fatalf("init steps ran on a silo hv0 still holds: %v", box.Calls)
	}
	if len(boxCalls(box, "start")) != 0 || g.stored("web").ResourceVersion != before {
		t.Fatalf("started or wrote on a silo hv0 still holds: %v", box.Calls)
	}
}

// The claim is the last word: if the control plane hands the silo over in the gap between the
// agent's check and its start (here, during an init step), nothing is started.
func TestAHandoffThatBeginsAfterTheCheckStillStopsTheStart(t *testing.T) {
	box := fake.NewBox()
	hook := &initHook{Box: box}
	g := newGuardRig(t, hook, nil)
	s := g.create(initSilo("web"), "hv1", "")
	g.boxCopy(s, box)
	hook.during = func() { g.setPlacement(s, "hv1", "hv0") } // placement stays hv1: the status writes still pass
	g.cacheIs(g.stored("web"))
	if _, err := g.reconcile("web"); err != nil {
		t.Fatal(err)
	}
	if len(boxCalls(box, "init")) == 0 {
		t.Fatal("the init step never ran: the test proves nothing")
	}
	if got := boxCalls(box, "start"); len(got) != 0 {
		t.Fatalf("started after a handoff began: %v", box.Calls)
	}
}

// The same gap in a restart of a failed silo: between the check and the start there is the
// restart's own status write; a handoff that lands right after it stops the start.
func TestAHandoffThatBeginsDuringARestartStopsIt(t *testing.T) {
	inner := fake.New()
	g := newGuardRig(t, failedRuntime{inner}, nil)
	g.rt = inner
	s := g.create(guardSilo("web", nil), "hv1", "")
	g.runtimeCopy(s, kri.Created)
	g.rt.Calls = nil
	var flipped bool
	g.a.Client = client.New(g.ts.URL)
	g.a.Client.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err == nil && !flipped && r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/status") {
			flipped = true
			g.setPlacement(s, "hv1", "hv0") // right after the agent's "restarting" write
		}
		return resp, err
	})}
	g.cacheIs(g.stored("web"))
	if _, err := g.reconcile("web"); err != nil {
		t.Fatal(err)
	}
	if !flipped {
		t.Fatal("the restart wrote no status: the test proves nothing")
	}
	if got := g.calls("start"); len(got) != 0 {
		t.Fatalf("restarted after a handoff began: %v", g.rt.Calls)
	}
}

// A silo that asked to stop on control-plane loss is in the fence record before an existing
// copy is started again too (the record may be missing: a new boot, an upgrade, a restore).
func TestTheFenceRecordKnowsASiloBeforeAnExistingCopyIsStarted(t *testing.T) {
	dir := t.TempDir()
	inner := fake.New()
	rt := &recordCheckingRuntime{Runtime: inner, dir: dir, t: t}
	g := newGuardRig(t, rt, func(a *Agent) { a.FenceDir = dir })
	g.rt = inner
	s := g.create(guardSilo("web", func(s *v1.Silo) {
		s.Spec.Availability = v1.Availability{OnControlPlaneLoss: v1.OnControlPlaneLossStop, OnHostLoss: v1.OnHostLossRecreate}
	}), "hv1", "")
	rt.uid = s.UID
	g.runtimeCopy(s, kri.Stopped) // there already, stopped; nothing is in the record
	g.until("web", "start")
	if rt.startedKnown == 0 {
		t.Fatal("never started")
	}
}

// A silo placed on another host, with a copy still here (it moved away), has that copy stopped
// and removed by this host, and only this host's own copy: the first branch of reconcile.
func TestACopyOfASiloPlacedElsewhereIsRemovedFromThisHost(t *testing.T) {
	g := newGuardRig(t, nil, nil)
	s := g.create(guardSilo("web", nil), "hv1", "")
	g.runtimeCopy(s, kri.Stopped)
	g.setPlacement(s, "hv2", "")
	g.cacheIs(g.stored("web"))
	g.rt.Calls = nil
	if _, err := g.reconcile("web"); err != nil {
		t.Fatal(err)
	}
	if got := g.calls("delete"); len(got) != 1 {
		t.Fatalf("the copy of a silo placed on hv2 was not removed from hv1: %v", g.rt.Calls)
	}
	if ids, _ := g.rt.List(g.ctx); len(ids) != 0 {
		t.Fatalf("still here: %v", ids)
	}
}

func silentFor(silence time.Duration) *Agent {
	base := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	a := &Agent{Clock: clock.NewFake(base.Add(silence)), LastContact: func() time.Time { return base }}
	a.started = base.Add(-time.Hour)
	return a
}

func stopAfter(after string) *v1.Silo {
	return guardSilo("web", func(s *v1.Silo) {
		s.Spec.Availability = v1.Availability{OnControlPlaneLoss: v1.OnControlPlaneLossStop, After: after}
	})
}

// §0.7: a silo is stopped for lack of the control plane only if it asked to be (Stop), and only
// once the silence is longer than its own `after`.
func TestMustStopOnlyASiloThatAskedAndOnlyAfterItsAfter(t *testing.T) {
	cases := []struct {
		name    string
		silo    *v1.Silo
		silence time.Duration
		want    bool
	}{
		{"never asked, silent for a day", guardSilo("web", nil), 24 * time.Hour, false},
		{"asked to continue, silent for a day", guardSilo("web", func(s *v1.Silo) {
			s.Spec.Availability.OnControlPlaneLoss = v1.OnControlPlaneLossContinue
		}), 24 * time.Hour, false},
		{"asked to stop after 2m, silent 1m59s", stopAfter("2m"), 2*time.Minute - time.Second, false},
		{"asked to stop after 2m, silent exactly 2m", stopAfter("2m"), 2 * time.Minute, false},
		{"asked to stop after 2m, silent 2m1s", stopAfter("2m"), 2*time.Minute + time.Second, true},
		{"asked to stop after 1h, silent 2m", stopAfter("1h"), 2 * time.Minute, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := silentFor(tc.silence).mustStop(tc.silo); got != tc.want {
				t.Fatalf("mustStop = %v, want %v", got, tc.want)
			}
		})
	}
}

// Contact counts as back only when it really is: a silence past fence.DefaultAfter is not
// contact, or the fence would start the silos it just stopped, while still cut off.
func TestInContactMeansTheSilenceIsWithinTheShortestAfter(t *testing.T) {
	for silence, want := range map[time.Duration]bool{0: true, 5 * time.Second: true, fence.DefaultAfter: true, fence.DefaultAfter + time.Second: false, time.Hour: false} {
		if got := silentFor(silence).inContact(); got != want {
			t.Errorf("silent for %s: inContact = %v, want %v", silence, got, want)
		}
	}
}
