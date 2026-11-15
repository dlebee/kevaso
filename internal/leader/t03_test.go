package leader_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/leader"
	"kevaso.com/core/internal/store"
)

// stuckStore is a store that can stop answering (every call blocks until released) or be slow to
// write (each write moves the fake clock on by slow before it lands).
type stuckStore struct {
	store.Store
	clock *clock.Fake
	mu    sync.Mutex
	hang  chan struct{} // non-nil: calls block until it is closed
	slow  time.Duration
}

func (s *stuckStore) wait(ctx context.Context) error {
	s.mu.Lock()
	h := s.hang
	s.mu.Unlock()
	if h == nil {
		return nil
	}
	select {
	case <-h:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *stuckStore) Get(ctx context.Context, k store.Key) (store.Object, error) {
	if err := s.wait(ctx); err != nil {
		return store.Object{}, err
	}
	return s.Store.Get(ctx, k)
}

func (s *stuckStore) write() {
	s.mu.Lock()
	d := s.slow
	s.mu.Unlock()
	if d > 0 {
		s.clock.Step(d)
	}
}

func (s *stuckStore) Create(ctx context.Context, k store.Key, data []byte) (store.Object, error) {
	if err := s.wait(ctx); err != nil {
		return store.Object{}, err
	}
	s.write()
	return s.Store.Create(ctx, k, data)
}

func (s *stuckStore) Update(ctx context.Context, k store.Key, data []byte, expected int64) (store.Object, error) {
	if err := s.wait(ctx); err != nil {
		return store.Object{}, err
	}
	s.write()
	return s.Store.Update(ctx, k, data, expected)
}

// Real-time rounds short enough for a test; the election's own times are on the fake clock.
var t03 = leader.Options{Lease: 3 * time.Second, RenewDeadline: 2 * time.Second, RetryPeriod: 20 * time.Millisecond}

// T-03: the watchdog is the only thing that ends a leader's work while its store doesn't answer
// (a round stuck in Get never gets to decide). Once the renew deadline has passed on its clock,
// the term's context ends, though no round has returned.
func TestT03TheWatchdogEndsATermWhoseStoreHangs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fc := clock.NewFake(time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC))
	st := &stuckStore{Store: store.NewMemory(0), clock: fc}
	e := &leader.Elector{Store: st, Key: leader.ControllersKey, ID: "cp-1", Clock: fc, Options: t03}
	term := make(chan context.Context, 1)
	if d := e.Step(ctx, func(tctx context.Context) { term <- tctx; <-tctx.Done() }); d.Action != leader.Acquire {
		t.Fatalf("first round: %+v", d)
	}
	tctx := <-term
	// The store stops answering; a round starts and hangs in it.
	hang := make(chan struct{})
	st.mu.Lock()
	st.hang = hang
	st.mu.Unlock()
	defer close(hang)
	go e.Step(ctx, nil)
	// Within the deadline the term goes on.
	fc.Step(t03.RenewDeadline - time.Millisecond)
	select {
	case <-tctx.Done():
		t.Fatal("the term ended before its renew deadline")
	case <-time.After(5 * t03.RetryPeriod):
	}
	// Past it: the watchdog ends the term while the round is still stuck.
	fc.Step(2 * time.Millisecond)
	select {
	case <-tctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("a leader whose store hangs kept acting past its renew deadline: nothing but the watchdog can end its term")
	}
	if ok, _ := e.Leading(); ok {
		t.Fatal("Leading after the renew deadline")
	}
}

// T-03: a renewal counts from when its write started, never from when it landed: the store may
// have been slow, and every other candidate judges the lease by the write it saw, so the leader's
// own deadline must not run later than theirs.
func TestT03ARenewalCountsFromWhenItsWriteStarted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fc := clock.NewFake(time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC))
	st := &stuckStore{Store: store.NewMemory(0), clock: fc}
	e := &leader.Elector{Store: st, Key: leader.ControllersKey, ID: "cp-1", Clock: fc, Options: t03}
	if d := e.Step(ctx, func(tctx context.Context) { <-tctx.Done() }); d.Action != leader.Acquire {
		t.Fatalf("first round: %+v", d)
	}
	if ok, _ := e.Leading(); !ok {
		t.Fatal("not leading after acquiring: the acquire's renewal wasn't stamped")
	}
	// A renewal whose write takes 1.5 s to land.
	fc.Step(500 * time.Millisecond)
	start := fc.Now()
	st.mu.Lock()
	st.slow = 1500 * time.Millisecond
	st.mu.Unlock()
	if d := e.Step(ctx, nil); d.Action != leader.Renew {
		t.Fatalf("second round: %+v", d)
	}
	st.mu.Lock()
	st.slow = 0
	st.mu.Unlock()
	if ok, _ := e.Leading(); !ok {
		t.Fatal("not leading right after a renewal")
	}
	// Just before start+RenewDeadline: leading. Just after: not, though the write landed only
	// 1.5 s after it started.
	fc.Step(start.Add(t03.RenewDeadline).Sub(fc.Now()) - time.Millisecond)
	if ok, _ := e.Leading(); !ok {
		t.Fatal("not leading before the renewal's deadline")
	}
	fc.Step(2 * time.Millisecond)
	if ok, _ := e.Leading(); ok {
		t.Fatalf("still leading %v after the renewal's write started: its deadline counted from when the write landed", fc.Now().Sub(start))
	}
}
