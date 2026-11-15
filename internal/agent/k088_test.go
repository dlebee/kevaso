package agent_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// claimHook serves the API and lets a test act just before the agent's start claim reaches the
// store (a status write that carries the StartClaim condition).
type claimHook struct {
	h       http.Handler
	onClaim func() // called once, before the first claim is served
	once    sync.Once
	claims  atomic.Int32
}

func (c *claimHook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/status") {
		b, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(b))
		if bytes.Contains(b, []byte(`"`+agent.ConditionStartClaim+`"`)) {
			c.claims.Add(1)
			if c.onClaim != nil {
				c.once.Do(c.onClaim)
			}
		}
	}
	c.h.ServeHTTP(w, r)
}

// refresh is how often the tests' agents renew a start claim.
const refresh = 100 * time.Millisecond

type k088 struct {
	t   *testing.T
	ctx context.Context
	c   *client.Client
	rt  *fake.Strict
	w   *fake.World
	a   *agent.Agent
	s   *v1.Silo
	id  kri.ID
}

// newK088 serves the API (through hook, if set), with namespace dev and an agent on hv1 whose only
// runtime is a strict container fake. The silo isn't made yet (place does it).
func newK088(t *testing.T, hook *claimHook) *k088 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	var h http.Handler = srv
	if hook != nil {
		hook.h = srv
		h = hook
	}
	ts := httptest.NewServer(h)
	t.Cleanup(func() { cancel(); ts.Close() })
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	w := fake.NewWorld()
	rt := fake.NewStrict("hv1", w)
	a := &agent.Agent{Client: client.New(ts.URL), HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{}, Log: t.Logf}
	return &k088{t: t, ctx: ctx, c: c, rt: rt, w: w, a: a}
}

// place makes silo dev/single (container, init steps as given) and places it on hv1.
func (k *k088) place(steps ...v1.InitStep) {
	k.t.Helper()
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "single", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"}}}
	if len(steps) > 0 {
		s.Spec.Init = &v1.Init{Steps: steps}
	}
	if err := k.c.Create(k.ctx, s); err != nil {
		k.t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := k.c.UpdateStatus(k.ctx, s); err != nil {
		k.t.Fatal(err)
	}
	k.s, k.id = s, kri.ID{Namespace: "dev", Name: "single", UID: s.UID}
}

func (k *k088) get() *v1.Silo {
	var cur v1.Silo
	if err := k.c.Get(k.ctx, "Silo", "dev", "single", &cur); err != nil {
		k.t.Fatal(err)
	}
	return &cur
}

// moveTo places the stored silo on host (what a restart elsewhere, or a person's
// --confirm-fenced move, writes).
func (k *k088) moveTo(host string) {
	for {
		cur := k.get()
		cur.Status.Host, cur.Status.Phase = host, "Scheduled"
		err := k.c.UpdateStatus(k.ctx, cur)
		if err == nil {
			return
		}
		if !client.IsConflict(err) {
			k.t.Error(err)
			return
		}
	}
}

func (k *k088) waitFor(what string, ok func() bool) {
	k.t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !ok(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			k.t.Fatalf("never: %s", what)
		}
	}
}

// claimOf is the stored silo's StartClaim ("" if none) and the host it names.
func claimOf(s *v1.Silo) string {
	if c := meta.FindCondition(s.Status.Conditions, agent.ConditionStartClaim); c != nil && c.Status == meta.ConditionTrue {
		return c.Message
	}
	return ""
}

// K-088 (a): nothing of a container silo runs on a host before that host's start claim applied:
// not an init step (in an init container, with the silo's image, volumes and secrets), not the
// main process. Each time code of the silo begins to run, the stored silo must carry hv1's claim.
func TestNoCodeOfASiloRunsBeforeItsHostsStartClaim(t *testing.T) {
	k := newK088(t, nil)
	var bad []string
	var mu sync.Mutex
	var ran atomic.Int32
	k.rt.OnRun = func(what string, id kri.ID) {
		ran.Add(1)
		var cur v1.Silo
		if err := k.c.Get(k.ctx, "Silo", id.Namespace, id.Name, &cur); err != nil {
			t.Error(err)
			return
		}
		if c := claimOf(&cur); !strings.HasPrefix(c, "starting on hv1 ") {
			mu.Lock()
			bad = append(bad, what+" began with no start claim of hv1 stored (claim: "+c+")")
			mu.Unlock()
		}
	}
	agent.RunForTest(t, k.ctx, k.a)
	k.place(v1.InitStep{Name: "migrate", Run: "true"}, v1.InitStep{Name: "seed", Run: "true"})
	k.waitFor("the silo ran", func() bool {
		st, _ := k.rt.Status(k.ctx, k.id)
		return st.State == kri.Running && k.rt.RunningInit(k.id) == ""
	})
	mu.Lock()
	defer mu.Unlock()
	if ran.Load() != 3 {
		t.Fatalf("ran %d pieces, want 2 init steps and the main process", ran.Load())
	}
	for _, b := range bad {
		t.Error(b)
	}
}

// K-088 (a), the window: the silo is placed elsewhere after the agent's last read and just before
// its claim reaches the store. The claim conflicts, and nothing of the silo runs on hv1: no init
// step, no main process.
func TestAPlacementJustBeforeTheClaimRunsNoInitStep(t *testing.T) {
	hook := &claimHook{}
	k := newK088(t, hook)
	hook.onClaim = func() { k.moveTo("hv2") }
	agent.RunForTest(t, k.ctx, k.a)
	k.place(v1.InitStep{Name: "migrate", Run: "sleep 5"})
	k.waitFor("the claim was sent", func() bool { return hook.claims.Load() > 0 })
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if k.w.RunsOn(k.id.UID, "hv1") {
			t.Fatalf("code of the silo runs on hv1 after it was placed on hv2: %v", k.rt.CallLog())
		}
	}
	for _, c := range k.rt.CallLog() {
		if strings.HasPrefix(c, "init ") || strings.HasPrefix(c, "start ") || strings.HasPrefix(c, "set-secrets ") {
			t.Fatalf("%q on hv1 after the claim lost: %v", c, k.rt.CallLog())
		}
	}
	if h := k.get().Status.Host; h != "hv2" {
		t.Fatalf("hv1 wrote over hv2's placement: %s", h)
	}
}

// K-088 (b): a slow init step keeps its host's claim fresh, so the control plane (which counts a
// claim as standing for StartClaimFresh from when it first sees it) sees a standing claim for as
// long as the step runs: the claim is written anew, each a new claim, more often than that.
func TestASlowInitStepKeepsItsStartClaimFresh(t *testing.T) {
	k := newK088(t, nil)
	k.a.ClaimRefresh = refresh
	release := make(chan struct{})
	k.rt.HoldInit = func(kri.ID, kri.InitStep) <-chan struct{} { return release }
	agent.RunForTest(t, k.ctx, k.a)
	k.place(v1.InitStep{Name: "slow", Run: "sleep 600"})
	k.waitFor("the init step runs", func() bool { return k.rt.RunningInit(k.id) == "slow" })
	seen := map[string]bool{}
	k.waitFor("the claim was written anew three times while the step ran", func() bool {
		if c := claimOf(k.get()); c != "" {
			seen[c] = true
		}
		return len(seen) >= 4
	})
	for c := range seen {
		if !strings.HasPrefix(c, "starting on hv1 at ") {
			t.Fatalf("a claim that isn't hv1's: %q", c)
		}
	}
	close(release)
	k.waitFor("the main process runs", func() bool {
		st, _ := k.rt.Status(k.ctx, k.id)
		return st.State == kri.Running && k.rt.RunningInit(k.id) == ""
	})
	// Running: the claim is no longer renewed (the heartbeat speaks for the host now).
	time.Sleep(100 * time.Millisecond) // a refresh already in flight lands
	last := claimOf(k.get())
	time.Sleep(5 * refresh)
	if now := claimOf(k.get()); now != last {
		t.Fatalf("the claim is still renewed once the silo runs: %q then %q", last, now)
	}
}

// K-088 (b): a renewal that finds the silo placed elsewhere ends the init step at once (it is
// killed, not left to run beside the new copy), and nothing more of the silo starts here. The step
// isn't recorded as failed: it was stopped, it didn't fail.
func TestAPlacementElsewhereDuringAnInitStepEndsIt(t *testing.T) {
	k := newK088(t, nil)
	k.a.ClaimRefresh = refresh
	k.rt.HoldInit = func(kri.ID, kri.InitStep) <-chan struct{} { return make(chan struct{}) } // never ends by itself
	agent.RunForTest(t, k.ctx, k.a)
	k.place(v1.InitStep{Name: "slow", Run: "sleep 600"})
	k.waitFor("the init step runs", func() bool { return k.rt.RunningInit(k.id) == "slow" })
	k.moveTo("hv2") // a person's --confirm-fenced move: the claim is a host's, not the control plane's restart
	k.waitFor("the init step ended on hv1", func() bool { return !k.w.RunsOn(k.id.UID, "hv1") })
	time.Sleep(10 * refresh)
	if k.w.RunsOn(k.id.UID, "hv1") {
		t.Fatalf("code of the silo runs on hv1 again: %v", k.rt.CallLog())
	}
	for _, c := range k.rt.CallLog() {
		if strings.HasPrefix(c, "start ") {
			t.Fatalf("started on hv1 after it was placed elsewhere: %v", k.rt.CallLog())
		}
	}
	s := k.get()
	for _, st := range s.Status.Init {
		if st.State == "Failed" {
			t.Fatalf("a stopped step recorded as failed: %+v", s.Status.Init)
		}
	}
}

// K-088 (c, d): the agent's own fence stops an opted-in silo cut off from the control plane while
// its init step runs: the step ends (the runtime's Kill covers it), the fence counts it stopped
// only once Status says nothing runs, and the step isn't recorded as failed: when contact is back
// it runs again, then the silo starts.
func TestTheFenceStopsAnInitStepAndItRunsAgainOnContact(t *testing.T) {
	k := newK088(t, nil)
	var cut atomic.Bool
	k.a.LastContact = func() time.Time {
		if cut.Load() {
			return time.Now().Add(-time.Hour)
		}
		return time.Now()
	}
	k.a.StopsOnLoss = func(*v1.Silo) (bool, time.Duration) { return true, 2 * time.Second }
	var held atomic.Int32
	release := make(chan struct{})
	k.rt.HoldInit = func(kri.ID, kri.InitStep) <-chan struct{} {
		if held.Add(1) == 1 {
			return make(chan struct{}) // the first run: until killed
		}
		return release
	}
	agent.RunForTest(t, k.ctx, k.a)
	k.place(v1.InitStep{Name: "slow", Run: "sleep 600"})
	k.waitFor("the init step runs", func() bool { return k.rt.RunningInit(k.id) == "slow" })
	cut.Store(true)
	k.waitFor("the fence ended the init step", func() bool { return !k.w.RunsOn(k.id.UID, "hv1") })
	time.Sleep(2 * time.Second) // more fence passes, and the agent's next reconciles
	if k.w.RunsOn(k.id.UID, "hv1") {
		t.Fatalf("started again while cut off: %v", k.rt.CallLog())
	}
	s := k.get()
	for _, st := range s.Status.Init {
		if st.State == "Failed" {
			t.Fatalf("a step the fence stopped recorded as failed: %+v", s.Status.Init)
		}
	}
	if c := meta.FindCondition(s.Status.Conditions, "InitFailed"); c != nil && c.Status == meta.ConditionTrue {
		t.Fatalf("InitFailed after a fence: %+v", c)
	}
	cut.Store(false)
	k.waitFor("the init step runs again on contact", func() bool { return held.Load() >= 2 })
	close(release)
	k.waitFor("the silo runs", func() bool {
		st, _ := k.rt.Status(k.ctx, k.id)
		return st.State == kri.Running && k.rt.RunningInit(k.id) == ""
	})
}

// K-088 (c): an init step left running by an earlier run of the agent (kevasod killed while it
// ran: nobody waits for it, its result can never be recorded) is stopped, not taken for the
// running silo; then the steps run again and the silo starts.
func TestAnInitStepNobodyWaitsForIsStopped(t *testing.T) {
	k := newK088(t, nil)
	k.place(v1.InitStep{Name: "slow", Run: "sleep 600"})
	// What an earlier run left: the silo made, its init step running, its main process not.
	if err := k.rt.Create(k.ctx, kri.Spec{ID: k.id, Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	orphan := make(chan struct{})
	var runs atomic.Int32
	k.rt.HoldInit = func(kri.ID, kri.InitStep) <-chan struct{} {
		if runs.Add(1) == 1 {
			return orphan // the earlier run's: until stopped
		}
		return nil
	}
	octx, ocancel := context.WithCancel(context.Background())
	defer ocancel()
	go func() { _, _ = k.rt.RunInit(octx, k.id, kri.InitStep{Name: "slow", Run: "sleep 600"}, io.Discard) }()
	k.waitFor("the orphan runs", func() bool { return k.rt.RunningInit(k.id) == "slow" })
	agent.RunForTest(t, k.ctx, k.a)
	k.waitFor("the silo runs, its steps done", func() bool {
		st, _ := k.rt.Status(k.ctx, k.id)
		s := k.get()
		return st.State == kri.Running && len(s.Status.Init) == 1 && s.Status.Init[0].State == "Done" && k.rt.RunningInit(k.id) == ""
	})
	n := 0
	for _, c := range k.rt.CallLog() {
		if c == "init slow dev/single" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("the step ran %d times, want the orphan and one run by this agent: %v", n, k.rt.CallLog())
	}
	if len(k.w.Twice()) > 0 {
		t.Fatal(k.w.Twice())
	}
}
