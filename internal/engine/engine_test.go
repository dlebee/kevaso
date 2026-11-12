package engine

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/internal/clock"
)

// fake is a controller whose behaviour each test scripts.
type fake struct {
	kind string
	mu   sync.Mutex
	runs map[Key]int
	fn   func(k Key, attempt int) (Result, error)
	mapf func(Key) []Key

	running atomic.Int32
	maxPar  atomic.Int32
	block   chan struct{} // if set, Reconcile waits on it
	started chan Key      // if set, Reconcile reports it started
}

func newFake(kind string) *fake { return &fake{kind: kind, runs: map[Key]int{}} }

func (f *fake) Name() string { return "fake-" + f.kind }
func (f *fake) Kind() string { return f.kind }
func (f *fake) Map(k Key) []Key {
	if f.mapf == nil {
		return nil
	}
	return f.mapf(k)
}
func (f *fake) Reconcile(_ context.Context, k Key) (Result, error) {
	n := f.running.Add(1)
	defer f.running.Add(-1)
	for {
		m := f.maxPar.Load()
		if n <= m || f.maxPar.CompareAndSwap(m, n) {
			break
		}
	}
	if f.started != nil {
		f.started <- k
	}
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	f.runs[k]++
	attempt := f.runs[k]
	fn := f.fn
	f.mu.Unlock()
	if fn != nil {
		return fn(k, attempt)
	}
	return Result{}, nil
}

func (f *fake) setFn(fn func(Key, int) (Result, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fn = fn
}
func (f *fake) count(k Key) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs[k]
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for: %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func run(t *testing.T, e *Engine) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("engine didn't stop")
		}
	})
}

var silo = Key{Kind: "Silo", Namespace: "dev", Name: "a"}

func TestBurstOfChangesIsOneReconcile(t *testing.T) {
	f := newFake("Silo")
	f.block = make(chan struct{})
	f.started = make(chan Key, 10)
	e := New(clock.NewFake(time.Now()))
	e.Register(f, Options{})
	other := Key{Kind: "Silo", Namespace: "dev", Name: "b"}
	e.Changed(other) // occupies the single worker, so silo stays queued
	run(t, e)
	<-f.started
	for i := 0; i < 5; i++ {
		e.Changed(silo)
	}
	close(f.block)
	eventually(t, "silo reconciled", func() bool { return f.count(silo) == 1 })
	time.Sleep(20 * time.Millisecond)
	if n := f.count(silo); n != 1 {
		t.Fatalf("5 queued changes ran %d reconciles, want 1", n)
	}
}

func TestChangeDuringReconcileRunsOnceMoreAfter(t *testing.T) {
	f := newFake("Silo")
	f.block = make(chan struct{})
	f.started = make(chan Key, 10)
	e := New(clock.NewFake(time.Now()))
	e.Register(f, Options{Workers: 4})
	run(t, e)
	e.Changed(silo)
	<-f.started           // first reconcile is running
	e.Changed(silo)       // changes arrive meanwhile...
	e.Changed(silo)       // ...twice
	f.block <- struct{}{} // finish the first
	<-f.started           // exactly one more starts
	close(f.block)
	eventually(t, "second run", func() bool { return f.count(silo) == 2 })
	time.Sleep(20 * time.Millisecond)
	if n := f.count(silo); n != 2 {
		t.Fatalf("ran %d times, want 2 (one, plus one for the changes during it)", n)
	}
	if p := f.maxPar.Load(); p != 1 {
		t.Fatalf("the same key ran %d times at once", p)
	}
}

func TestDifferentKeysRunInParallel(t *testing.T) {
	f := newFake("Silo")
	f.block = make(chan struct{})
	f.started = make(chan Key, 10)
	e := New(clock.NewFake(time.Now()))
	e.Register(f, Options{Workers: 3})
	run(t, e)
	for _, n := range []string{"a", "b", "c"} {
		e.Changed(Key{Kind: "Silo", Namespace: "dev", Name: n})
	}
	for i := 0; i < 3; i++ {
		<-f.started
	}
	if p := f.maxPar.Load(); p != 3 {
		t.Fatalf("parallel reconciles = %d, want 3", p)
	}
	close(f.block)
}

func TestFailuresBackOffExponentiallyAndResetOnSuccess(t *testing.T) {
	clk := clock.NewFake(time.Now())
	f := newFake("Silo")
	f.fn = func(_ Key, attempt int) (Result, error) {
		if attempt <= 3 {
			return Result{}, errors.New("boom")
		}
		return Result{}, nil
	}
	var mu sync.Mutex
	var delays []time.Duration
	e := New(clk)
	e.OnError = func(_ string, _ Key, _ error, d time.Duration) { mu.Lock(); delays = append(delays, d); mu.Unlock() }
	e.Register(f, Options{Backoff: Backoff{Base: time.Second, Max: time.Minute}})
	run(t, e)
	e.Changed(silo)
	eventually(t, "first failure", func() bool { return f.count(silo) == 1 && clk.Pending() == 1 })
	// Not before the backoff: 999ms later nothing has run.
	clk.Step(999 * time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	if f.count(silo) != 1 {
		t.Fatal("retried before its backoff")
	}
	clk.Step(time.Millisecond) // 1s: attempt 2
	eventually(t, "attempt 2", func() bool { return f.count(silo) == 2 && clk.Pending() == 1 })
	clk.Step(2 * time.Second) // 2s: attempt 3
	eventually(t, "attempt 3", func() bool { return f.count(silo) == 3 && clk.Pending() == 1 })
	clk.Step(4 * time.Second) // 4s: attempt 4 succeeds
	eventually(t, "attempt 4", func() bool { return f.count(silo) == 4 })
	mu.Lock()
	got := append([]time.Duration(nil), delays...)
	mu.Unlock()
	if len(got) != 3 || got[0] != time.Second || got[1] != 2*time.Second || got[2] != 4*time.Second {
		t.Fatalf("backoff delays %v, want [1s 2s 4s]", got)
	}
	// After the success, a new failure starts from the base again.
	f.setFn(func(Key, int) (Result, error) { return Result{}, errors.New("again") })
	e.Changed(silo)
	eventually(t, "new failure", func() bool { return f.count(silo) == 5 })
	eventually(t, "delay recorded", func() bool { mu.Lock(); defer mu.Unlock(); return len(delays) == 4 })
	mu.Lock()
	defer mu.Unlock()
	if delays[3] != time.Second {
		t.Fatalf("backoff after a success restarted at %v, want 1s", delays[3])
	}
}

func TestFailingKeyDoesNotBlockOthers(t *testing.T) {
	clk := clock.NewFake(time.Now())
	f := newFake("Silo")
	bad := Key{Kind: "Silo", Namespace: "dev", Name: "bad"}
	f.fn = func(k Key, _ int) (Result, error) {
		if k == bad {
			return Result{}, errors.New("always")
		}
		return Result{}, nil
	}
	e := New(clk)
	e.Register(f, Options{})
	run(t, e)
	e.Changed(bad)
	e.Changed(silo)
	eventually(t, "good key reconciled while bad one backs off", func() bool { return f.count(silo) == 1 })
}

func TestRequeueAfter(t *testing.T) {
	clk := clock.NewFake(time.Now())
	f := newFake("Silo")
	f.fn = func(Key, int) (Result, error) { return Result{RequeueAfter: 30 * time.Second}, nil }
	e := New(clk)
	e.Register(f, Options{})
	run(t, e)
	e.Changed(silo)
	eventually(t, "first run", func() bool { return f.count(silo) == 1 && clk.Pending() == 1 })
	clk.Step(29 * time.Second)
	time.Sleep(20 * time.Millisecond)
	if f.count(silo) != 1 {
		t.Fatal("requeued early")
	}
	clk.Step(time.Second)
	eventually(t, "requeued run", func() bool { return f.count(silo) == 2 })
}

func TestChangeBeatsPendingBackoff(t *testing.T) {
	clk := clock.NewFake(time.Now())
	f := newFake("Silo")
	f.fn = func(_ Key, attempt int) (Result, error) {
		if attempt == 1 {
			return Result{}, errors.New("boom")
		}
		return Result{}, nil
	}
	e := New(clk)
	e.Register(f, Options{Backoff: Backoff{Base: time.Hour, Max: time.Hour}})
	run(t, e)
	e.Changed(silo)
	eventually(t, "failure", func() bool { return f.count(silo) == 1 && clk.Pending() == 1 })
	e.Changed(silo) // a real change shouldn't wait an hour
	eventually(t, "reconciled right away", func() bool { return f.count(silo) == 2 })
}

func TestMapperWakesOtherKinds(t *testing.T) {
	silos := newFake("Silo")
	host := Key{Kind: "Host", Name: "hv1"}
	onHost := []Key{{Kind: "Silo", Namespace: "dev", Name: "a"}, {Kind: "Silo", Namespace: "prod", Name: "b"}}
	silos.mapf = func(k Key) []Key {
		if k.Kind == "Host" {
			return onHost
		}
		return nil
	}
	e := New(clock.NewFake(time.Now()))
	e.Register(silos, Options{Workers: 2})
	run(t, e)
	e.Changed(host)
	eventually(t, "both silos on the host reconciled", func() bool {
		return silos.count(onHost[0]) == 1 && silos.count(onHost[1]) == 1
	})
	if silos.count(host) != 0 {
		t.Fatal("the silo controller reconciled a Host key")
	}
}

func TestPanicBecomesRetry(t *testing.T) {
	clk := clock.NewFake(time.Now())
	f := newFake("Silo")
	f.fn = func(_ Key, attempt int) (Result, error) {
		if attempt == 1 {
			panic("bad object")
		}
		return Result{}, nil
	}
	var gotErr atomic.Value
	e := New(clk)
	e.OnError = func(_ string, _ Key, err error, _ time.Duration) { gotErr.Store(err.Error()) }
	e.Register(f, Options{Backoff: Backoff{Base: time.Second, Max: time.Second}})
	run(t, e)
	e.Changed(silo)
	eventually(t, "panic reported", func() bool { return gotErr.Load() != nil && clk.Pending() == 1 })
	clk.Step(time.Second)
	eventually(t, "retried after the panic", func() bool { return f.count(silo) == 2 })
}

func TestBackoffDelay(t *testing.T) {
	b := Backoff{Base: 100 * time.Millisecond, Max: time.Second}
	for failures, want := range map[int]time.Duration{
		1: 100 * time.Millisecond, 2: 200 * time.Millisecond, 3: 400 * time.Millisecond,
		4: 800 * time.Millisecond, 5: time.Second, 50: time.Second,
	} {
		if got := b.Delay(failures); got != want {
			t.Errorf("Delay(%d) = %v, want %v", failures, got, want)
		}
	}
}
