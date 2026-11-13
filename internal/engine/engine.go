// Package engine runs controllers the Kubernetes way: each controller gets its own work queue and
// workers; it's told which object to look at, never what changed (level-triggered), and always
// reconciles from current state. A failing key backs off on its own without slowing other keys or
// other controllers.
package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"kevaso.com/core/internal/clock"
)

// Key names one object: kind, namespace (empty for cluster-scoped) and name.
type Key struct {
	Kind      string
	Namespace string
	Name      string
}

func (k Key) String() string {
	if k.Namespace == "" {
		return k.Kind + "/" + k.Name
	}
	return k.Kind + "/" + k.Namespace + "/" + k.Name
}

// Result tells the engine what to do after a successful reconcile.
type Result struct {
	// RequeueAfter > 0 reconciles the key again after that long (heartbeats, polling).
	RequeueAfter time.Duration
}

// Controller reconciles one kind. Reconcile must be idempotent: it may run any number of times.
type Controller interface {
	Name() string
	Kind() string
	Reconcile(ctx context.Context, key Key) (Result, error)
}

// Mapper is optional: a controller that also cares about other kinds maps their changes onto its
// own keys (a Host change wakes the silos placed on it).
type Mapper interface {
	Map(changed Key) []Key
}

// Options tune one controller.
type Options struct {
	Workers int     // concurrent reconciles (of different keys); default 1
	Backoff Backoff // default DefaultBackoff
}

// Cache is a local copy that controllers read (an informer): until it has its first list, not
// seeing an object in it says nothing about whether the object exists.
type Cache interface {
	Kind() string
	WaitSynced(ctx context.Context) bool
}

// Engine routes changes to controllers and runs them.
type Engine struct {
	clock  clock.Clock
	mu     sync.Mutex
	ctrls  []*registered
	caches []Cache
	// OnWait, if set, is told which caches Run is waiting for before any controller runs.
	OnWait func(kinds []string)
	// OnError, if set, is told about every failed reconcile (logging, metrics).
	OnError func(controller string, key Key, err error, retryIn time.Duration)
}

type registered struct {
	c    Controller
	opts Options
	q    *queue
}

// New returns an engine using the given clock (clock.Real{} in production).
func New(c clock.Clock) *Engine { return &Engine{clock: c} }

// Register adds a controller. Call before Run.
func (e *Engine) Register(c Controller, opts Options) {
	if opts.Workers <= 0 {
		opts.Workers = 1
	}
	if opts.Backoff == (Backoff{}) {
		opts.Backoff = DefaultBackoff
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ctrls = append(e.ctrls, &registered{c: c, opts: opts, q: newQueue(e.clock, opts.Backoff)})
}

// WaitFor makes Run hold every controller until each of caches has loaded its first list: a
// controller acting on a cache that is still empty would take "I do not see it" for "it does not
// exist", and unbind, release or delete what is in use. Changes that come meanwhile stay queued.
// Call before Run.
func (e *Engine) WaitFor(caches ...Cache) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.caches = append(e.caches, caches...)
}

// Changed tells the engine an object changed: its kind's controllers get the key, and every Mapper
// gets a chance to map it onto its own keys.
func (e *Engine) Changed(k Key) {
	e.mu.Lock()
	ctrls := append([]*registered(nil), e.ctrls...)
	e.mu.Unlock()
	for _, r := range ctrls {
		if r.c.Kind() == k.Kind {
			r.q.add(k)
		}
		if m, ok := r.c.(Mapper); ok {
			for _, mk := range m.Map(k) {
				if mk.Kind != r.c.Kind() {
					panic(fmt.Sprintf("controller %s mapped %s onto kind %s, not its own", r.c.Name(), k, mk.Kind))
				}
				r.q.add(mk)
			}
		}
	}
}

// Run runs every controller's workers until ctx ends, then waits for in-flight reconciles. With
// caches to wait for (WaitFor), no worker starts before all of them have synced.
func (e *Engine) Run(ctx context.Context) {
	e.mu.Lock()
	ctrls := append([]*registered(nil), e.ctrls...)
	caches := append([]Cache(nil), e.caches...)
	e.mu.Unlock()
	if len(caches) > 0 {
		if e.OnWait != nil {
			kinds := make([]string, len(caches))
			for i, c := range caches {
				kinds[i] = c.Kind()
			}
			e.OnWait(kinds)
		}
		for _, c := range caches {
			if !c.WaitSynced(ctx) {
				for _, r := range ctrls {
					r.q.shutDown()
				}
				return
			}
		}
	}
	var wg sync.WaitGroup
	for _, r := range ctrls {
		for i := 0; i < r.opts.Workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				e.work(ctx, r)
			}()
		}
	}
	<-ctx.Done()
	for _, r := range ctrls {
		r.q.shutDown()
	}
	wg.Wait()
}

func (e *Engine) work(ctx context.Context, r *registered) {
	for {
		k, ok := r.q.get()
		if !ok {
			return
		}
		res, err := e.reconcile(ctx, r.c, k)
		switch {
		case err != nil:
			d := r.q.retry(k)
			if e.OnError != nil {
				e.OnError(r.c.Name(), k, err, d)
			}
		default:
			r.q.forget(k)
			if res.RequeueAfter > 0 {
				r.q.addAfter(k, res.RequeueAfter)
			}
		}
		r.q.done(k)
	}
}

// reconcile turns a panic into an error, so one bad object can't take the control plane down.
func (e *Engine) reconcile(ctx context.Context, c Controller, k Key) (res Result, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic in %s reconciling %s: %v", c.Name(), k, p)
		}
	}()
	return c.Reconcile(ctx, k)
}
