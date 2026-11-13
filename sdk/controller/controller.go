// Package controller is the controller runtime for plugins (design §4.3): a plugin that defines a
// kind runs a controller for it with this, against the public API only. It watches one kind
// through an informer, puts the keys of changed objects in a work queue (one entry per key, however
// often it changed), and reconciles each from current state, level-triggered, retrying failures
// with backoff.
//
//	inf := informer.New(c, "databases.acme.dev")
//	ctl := &controller.Controller{Name: "databases", Informer: inf, Reconcile: r.reconcile}
//	ctl.Run(ctx)
package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	"kevaso.com/core/api/informer"
)

// Result tells the controller what to do after a successful reconcile.
type Result struct {
	RequeueAfter time.Duration // > 0: look at this key again after that long
}

// Reconciler brings the world in line with one object (which may be gone: check the informer).
// It must be idempotent.
type Reconciler func(ctx context.Context, key informer.Key) (Result, error)

// Controller reconciles one kind.
type Controller struct {
	Name      string
	Informer  *informer.Informer
	Reconcile Reconciler
	Workers   int // default 1
	// Backoff after a failure: Base doubles per consecutive failure of a key, up to Max.
	// Defaults: 100ms and 1m.
	Base, Max time.Duration
	// OnError, if set, hears about every failed reconcile.
	OnError func(key informer.Key, err error, retryIn time.Duration)
	// Also lets other informers wake this controller: each maps a changed key of its kind onto
	// keys of this controller's kind.
	Also []Watch

	mu       sync.Mutex
	cond     *sync.Cond
	queue    []informer.Key
	queued   map[informer.Key]bool
	active   map[informer.Key]bool
	dirty    map[informer.Key]bool // changed while being reconciled: again after
	failures map[informer.Key]int
	stopped  bool
}

// Watch is another kind a controller cares about.
type Watch struct {
	Informer *informer.Informer
	Map      func(informer.Key) []informer.Key
}

func (c *Controller) init() {
	c.cond = sync.NewCond(&c.mu)
	c.queued, c.active, c.dirty, c.failures = map[informer.Key]bool{}, map[informer.Key]bool{}, map[informer.Key]bool{}, map[informer.Key]int{}
	if c.Workers <= 0 {
		c.Workers = 1
	}
	if c.Base <= 0 {
		c.Base = 100 * time.Millisecond
	}
	if c.Max <= 0 {
		c.Max = time.Minute
	}
}

// Add queues a key (handlers call it; so can anything else that knows a key needs a look).
func (c *Controller) Add(k informer.Key) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.stopped:
	case c.active[k]:
		c.dirty[k] = true
	case !c.queued[k]:
		c.queued[k] = true
		c.queue = append(c.queue, k)
		c.cond.Signal()
	}
}

func (c *Controller) addAfter(ctx context.Context, k informer.Key, d time.Duration) {
	t := time.NewTimer(d)
	go func() {
		defer t.Stop()
		select {
		case <-t.C:
			c.Add(k)
		case <-ctx.Done():
		}
	}()
}

func (c *Controller) next() (informer.Key, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.queue) == 0 && !c.stopped {
		c.cond.Wait()
	}
	if c.stopped {
		return informer.Key{}, false
	}
	k := c.queue[0]
	c.queue = c.queue[1:]
	delete(c.queued, k)
	c.active[k] = true
	return k, true
}

func (c *Controller) done(k informer.Key) {
	c.mu.Lock()
	delete(c.active, k)
	again := c.dirty[k]
	delete(c.dirty, k)
	c.mu.Unlock()
	if again {
		c.Add(k)
	}
}

// Run starts the informers, waits for the first list, and reconciles until ctx ends.
func (c *Controller) Run(ctx context.Context) {
	c.init()
	c.Informer.AddHandler(c.Add)
	for _, w := range c.Also {
		w.Informer.AddHandler(func(k informer.Key) {
			for _, mk := range w.Map(k) {
				c.Add(mk)
			}
		})
	}
	var wg sync.WaitGroup
	for _, inf := range append([]*informer.Informer{c.Informer}, informers(c.Also)...) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			inf.Run(ctx)
		}()
	}
	for i := 0; i < c.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.work(ctx)
		}()
	}
	<-ctx.Done()
	c.mu.Lock()
	c.stopped = true
	c.cond.Broadcast()
	c.mu.Unlock()
	wg.Wait()
}

func informers(ws []Watch) []*informer.Informer {
	out := make([]*informer.Informer, len(ws))
	for i, w := range ws {
		out[i] = w.Informer
	}
	return out
}

func (c *Controller) work(ctx context.Context) {
	if !c.Informer.WaitSynced(ctx) {
		return
	}
	for {
		k, ok := c.next()
		if !ok {
			return
		}
		res, err := c.reconcile(ctx, k)
		c.mu.Lock()
		if err != nil {
			c.failures[k]++
			d := c.Base << min(c.failures[k]-1, 20)
			if d > c.Max || d <= 0 {
				d = c.Max
			}
			c.mu.Unlock()
			if c.OnError != nil {
				c.OnError(k, err, d)
			}
			c.addAfter(ctx, k, d)
		} else {
			delete(c.failures, k)
			c.mu.Unlock()
			if res.RequeueAfter > 0 {
				c.addAfter(ctx, k, res.RequeueAfter)
			}
		}
		c.done(k)
	}
}

// reconcile turns a panic into an error: one bad object can't stop the controller.
func (c *Controller) reconcile(ctx context.Context, k informer.Key) (res Result, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = &panicError{p}
		}
	}()
	return c.Reconcile(ctx, k)
}

type panicError struct{ v any }

func (p *panicError) Error() string { return fmt.Sprint("panic in reconcile: ", p.v) }
