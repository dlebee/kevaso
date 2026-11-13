package leader_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/leader"
	"kevaso.com/core/internal/store"
)

var (
	t0   = time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	opts = leader.Options{Lease: 15 * time.Second, RenewDeadline: 10 * time.Second, RetryPeriod: 2 * time.Second}
)

func TestDecide(t *testing.T) {
	held := func(holder string, term, rev int64) leader.View {
		return leader.View{Exists: true, Record: leader.Record{Holder: holder, Term: term}, Revision: rev}
	}
	cases := []struct {
		name   string
		me     leader.Self
		view   leader.View
		seen   leader.Seen
		now    time.Time
		action leader.Action
		exp    int64
		term   int64
	}{
		{"no lease: create it", leader.Self{ID: "a"}, leader.View{}, leader.Seen{}, t0, leader.Acquire, 0, 1},
		{"someone leads, first look", leader.Self{ID: "b"}, held("a", 3, 10), leader.Seen{}, t0, leader.Follow, 0, 0},
		{"someone leads, renewed since", leader.Self{ID: "b"}, held("a", 3, 12), leader.Seen{Revision: 10, At: t0}, t0.Add(20 * time.Second), leader.Follow, 0, 0},
		{"silent, not for a whole lease yet", leader.Self{ID: "b"}, held("a", 3, 10), leader.Seen{Revision: 10, At: t0}, t0.Add(14 * time.Second), leader.Follow, 0, 0},
		{"takeover: silent a whole lease", leader.Self{ID: "b"}, held("a", 3, 10), leader.Seen{Revision: 10, At: t0}, t0.Add(15 * time.Second), leader.Acquire, 10, 4},
		{"released: take it at once", leader.Self{ID: "b"}, held("", 3, 11), leader.Seen{Revision: 10, At: t0}, t0.Add(time.Second), leader.Acquire, 11, 4},
		{"leader renews", leader.Self{ID: "a", Leading: true, RenewedAt: t0}, held("a", 3, 10), leader.Seen{Revision: 10, At: t0}, t0.Add(2 * time.Second), leader.Renew, 10, 3},
		{"stale leader: renew deadline passed", leader.Self{ID: "a", Leading: true, RenewedAt: t0}, held("a", 3, 10), leader.Seen{Revision: 10, At: t0}, t0.Add(11 * time.Second), leader.StepDown, 0, 0},
		{"stale leader: someone took over", leader.Self{ID: "a", Leading: true, RenewedAt: t0}, held("b", 4, 13), leader.Seen{Revision: 10, At: t0}, t0.Add(3 * time.Second), leader.StepDown, 0, 0},
		{"named but not leading (restarted): new term", leader.Self{ID: "a"}, held("a", 3, 10), leader.Seen{}, t0, leader.Acquire, 10, 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := leader.Decide(c.me, c.view, c.seen, c.now, opts)
			if d.Action != c.action {
				t.Fatalf("action %s (%s), want %s", d.Action, d.Reason, c.action)
			}
			if c.action == leader.Acquire || c.action == leader.Renew {
				if d.Expected != c.exp || d.Next.Term != c.term || d.Next.Holder != c.me.ID {
					t.Fatalf("got expected=%d next=%+v, want expected=%d term=%d holder=%s", d.Expected, d.Next, c.exp, c.term, c.me.ID)
				}
			}
		})
	}
	// A follower's memory restarts whenever the revision moves: a renewing leader is never taken over.
	seen := leader.Seen{}
	for i := int64(1); i <= 20; i++ {
		d := leader.Decide(leader.Self{ID: "b"}, held("a", 1, i), seen, t0.Add(time.Duration(i)*10*time.Second), opts)
		if d.Action != leader.Follow {
			t.Fatalf("round %d: %s", i, d.Action)
		}
		seen = d.Seen
	}
	if !leader.Lost(leader.Self{Leading: true, RenewedAt: t0}, t0.Add(11*time.Second), opts) || leader.Lost(leader.Self{Leading: true, RenewedAt: t0}, t0.Add(9*time.Second), opts) {
		t.Fatal("Lost: wrong side of the renew deadline")
	}
}

func TestOptionsDefaults(t *testing.T) {
	o := leader.Options{Lease: 9 * time.Second, RenewDeadline: 20 * time.Second}.WithDefaults()
	if o.RenewDeadline >= o.Lease || o.RetryPeriod >= o.RenewDeadline {
		t.Fatalf("%+v", o)
	}
}

// Two candidates that both decide to take over the same revision: the store lets exactly one write.
func TestNoTwoWinnersOfOneRevision(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory(0)
	data, _ := json.Marshal(leader.Record{Holder: "a", Term: 1})
	obj, err := st.Create(ctx, leader.ControllersKey, data)
	if err != nil {
		t.Fatal(err)
	}
	seen := leader.Seen{Revision: obj.Revision, At: t0}
	view := leader.View{Exists: true, Record: leader.Record{Holder: "a", Term: 1}, Revision: obj.Revision}
	wins := 0
	for _, id := range []string{"b", "c"} {
		d := leader.Decide(leader.Self{ID: id}, view, seen, t0.Add(time.Minute), opts)
		if d.Action != leader.Acquire {
			t.Fatalf("%s: %s", id, d.Action)
		}
		b, _ := json.Marshal(d.Next)
		if _, err := st.Update(ctx, leader.ControllersKey, b, d.Expected); err == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("%d candidates won revision %d", wins, obj.Revision)
	}
}

// cutStore fails every call while cut: a candidate cut off from the store.
type cutStore struct {
	store.Store
	cut *atomic.Bool
}

var errCut = fmt.Errorf("store unreachable")

func (c cutStore) Get(ctx context.Context, k store.Key) (store.Object, error) {
	if c.cut.Load() {
		return store.Object{}, errCut
	}
	return c.Store.Get(ctx, k)
}

func (c cutStore) Create(ctx context.Context, k store.Key, d []byte) (store.Object, error) {
	if c.cut.Load() {
		return store.Object{}, errCut
	}
	return c.Store.Create(ctx, k, d)
}

func (c cutStore) Update(ctx context.Context, k store.Key, d []byte, rev int64) (store.Object, error) {
	if c.cut.Load() {
		return store.Object{}, errCut
	}
	return c.Store.Update(ctx, k, d, rev)
}

type fleet struct {
	clk  *clock.Fake
	els  []*leader.Elector
	cut  []*atomic.Bool
	now  atomic.Int32 // terms whose work is running
	most atomic.Int32
}

func newFleet(n int) *fleet {
	f := &fleet{clk: clock.NewFake(t0)}
	st := store.NewMemory(0)
	for i := 0; i < n; i++ {
		c := &atomic.Bool{}
		f.cut = append(f.cut, c)
		f.els = append(f.els, &leader.Elector{Store: cutStore{st, c}, Key: leader.ControllersKey, ID: fmt.Sprintf("cp%d", i), Clock: f.clk, Options: opts})
	}
	return f
}

// leaders are the candidates that consider themselves leading at this instant.
func (f *fleet) leaders() []string {
	var out []string
	for _, e := range f.els {
		if ok, _ := e.Leading(); ok {
			out = append(out, e.ID)
		}
	}
	return out
}

func (f *fleet) step(ctx context.Context, i int) {
	f.els[i].Step(ctx, func(ctx context.Context) {
		if c := f.now.Add(1); c > f.most.Load() {
			f.most.Store(c)
		}
		<-ctx.Done()
		f.now.Add(-1)
	})
}

func TestElectionTakeoverAndStaleLeader(t *testing.T) {
	ctx := context.Background()
	f := newFleet(3)
	round := func() {
		for i := range f.els {
			f.step(ctx, i)
		}
		if l := f.leaders(); len(l) > 1 {
			t.Fatalf("two leaders at %v: %v", f.clk.Now(), l)
		}
		f.clk.Step(opts.RetryPeriod)
	}
	round()
	if l := f.leaders(); len(l) != 1 || l[0] != "cp0" {
		t.Fatalf("first leader: %v", l)
	}
	_, term1 := f.els[0].Leading()
	for i := 0; i < 10; i++ { // steady: cp0 renews, nobody takes over
		round()
	}
	if l := f.leaders(); len(l) != 1 || l[0] != "cp0" {
		t.Fatalf("steady state: %v", l)
	}
	// cp0 is cut off from the store: it must stop before anyone else starts.
	f.cut[0].Store(true)
	var stoppedAt, tookOverAt time.Time
	for i := 0; i < 20 && tookOverAt.IsZero(); i++ {
		round()
		if ok, _ := f.els[0].Leading(); !ok && stoppedAt.IsZero() {
			stoppedAt = f.clk.Now()
		}
		for _, l := range f.leaders() {
			if l != "cp0" && tookOverAt.IsZero() {
				tookOverAt = f.clk.Now()
			}
		}
	}
	if stoppedAt.IsZero() || tookOverAt.IsZero() || !stoppedAt.Before(tookOverAt) {
		t.Fatalf("stale leader stopped at %v, takeover at %v: want the stop strictly first", stoppedAt, tookOverAt)
	}
	l := f.leaders()
	if len(l) != 1 || l[0] == "cp0" {
		t.Fatalf("after takeover: %v", l)
	}
	var newTerm int64
	for _, e := range f.els {
		if ok, term := e.Leading(); ok {
			newTerm = term
		}
	}
	if newTerm <= term1 {
		t.Fatalf("takeover term %d not after %d", newTerm, term1)
	}
	// cp0 comes back: it follows, and never acts in its old term again.
	f.cut[0].Store(false)
	for i := 0; i < 5; i++ {
		round()
	}
	if l := f.leaders(); len(l) != 1 || l[0] == "cp0" {
		t.Fatalf("after cp0 came back: %v", l)
	}
	if f.most.Load() > 1 {
		waitFor(t, func() bool { return f.now.Load() <= 1 })
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("condition never held")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Many candidates, rounds in random orders, random cuts and pauses, the clock moving: at no
// instant do two consider themselves leading, and every term is won once, by one candidate.
func TestElectionNeverTwoLeaders(t *testing.T) {
	ctx := context.Background()
	r := rand.New(rand.NewSource(1))
	f := newFleet(5)
	terms := map[int64]string{}
	for step := 0; step < 5000; step++ {
		i := r.Intn(len(f.els))
		switch r.Intn(20) {
		case 0:
			f.cut[i].Store(!f.cut[i].Load())
		case 1, 2, 3: // a pause: no round for anyone, time passes
			f.clk.Step(time.Duration(r.Intn(4000)) * time.Millisecond)
		default:
			f.step(ctx, i)
		}
		for _, e := range f.els {
			if ok, term := e.Leading(); ok {
				if h, seen := terms[term]; seen && h != e.ID {
					t.Fatalf("term %d held by %s and %s", term, h, e.ID)
				}
				terms[term] = e.ID
			}
		}
		if l := f.leaders(); len(l) > 1 {
			t.Fatalf("step %d at %v: %v lead at once", step, f.clk.Now(), l)
		}
		f.clk.Step(time.Duration(r.Intn(700)) * time.Millisecond)
	}
	if len(terms) < 3 {
		t.Fatalf("only %d terms: the test never forced takeovers", len(terms))
	}
}

func TestRunReleasesOnStop(t *testing.T) {
	st := store.NewMemory(0)
	e := &leader.Elector{Store: st, Key: leader.ControllersKey, ID: "a", Clock: clock.Real{}, Options: leader.Options{Lease: 300 * time.Millisecond}}
	ctx, cancel := context.WithCancel(context.Background())
	led := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.Run(ctx, func(ctx context.Context) { close(led); <-ctx.Done() })
	}()
	select {
	case <-led:
	case <-time.After(5 * time.Second):
		t.Fatal("never led")
	}
	cancel()
	<-done
	obj, err := st.Get(context.Background(), leader.ControllersKey)
	if err != nil {
		t.Fatal(err)
	}
	var r leader.Record
	_ = json.Unmarshal(obj.Data, &r)
	if r.Holder != "" {
		t.Fatalf("lease still held by %q after stopping", r.Holder)
	}
}
