package plugins

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"kevaso.com/core/sdk/kplugin"
)

// Limits bound what one plugin can take from core (K-041). Every call core makes to a plugin goes
// through its registry's guard, whoever makes it (the control plane's controllers, a worker's
// agent for node sides):
//   - each call has a deadline by its kind: Quick for questions (Info, DescribeHosts), Work for
//     everything that changes something; the contract already says long work answers
//     ErrInProgress instead of holding the call;
//   - at most InFlight calls wait on one plugin; a further one waits Wait for a slot, then fails;
//   - a plugin that let a call run out its deadline is not called (but for Info, which is how the
//     registry sees it) for Pause, doubling up to MaxPause while it keeps not answering, and
//     back to normal after one answer.
//
// So a hung plugin holds a shared worker (one controller's, the agent's) for at most one deadline
// per pause, and the calls it refuses meanwhile fail at once with an error that names it, which
// the caller reports on the object it was for and retries with its usual backoff. That is the
// smallest change that frees the workers: the queues stay as they are (one per controller, shared
// by every class), since separating them per plugin means changing every controller.
type Limits struct {
	Quick    time.Duration // default 10s
	Work     time.Duration // default 1m
	InFlight int           // default 3: below the agent's 4 workers, above what a burst of mounts needs
	Wait     time.Duration // default 5s
	Pause    time.Duration // default 30s
	MaxPause time.Duration // default 5m
}

func (l Limits) withDefaults() Limits {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&l.Quick, 10*time.Second)
	def(&l.Work, time.Minute)
	def(&l.Wait, 5*time.Second)
	def(&l.Pause, 30*time.Second)
	def(&l.MaxPause, 5*time.Minute)
	if l.InFlight <= 0 {
		l.InFlight = 3
	}
	return l
}

// ErrUnresponsive: the plugin did not answer in time, or is not being called for a while because
// it did not; or it has as many calls waiting as it may.
var ErrUnresponsive = errors.New("plugin unresponsive")

// ErrBadAnswer: the plugin answered something core refuses to act on (a device path that isn't
// one).
var ErrBadAnswer = errors.New("plugin answer refused")

// guarded is a plugin's connection behind its Limits.
type guarded struct {
	name   string
	conn   Conn
	limits Limits
	slots  chan struct{}

	mu        sync.Mutex
	until     time.Time     // not called before this (but Info)
	pause     time.Duration // the next pause
	lastStuck string        // the call that ran out its deadline
	lastD     time.Duration // and that deadline
}

func guard(name string, c Conn, l Limits) *guarded {
	if g, ok := c.(*guarded); ok {
		if g.name == name {
			return g
		}
		c = g.conn // restarted as another plugin: a guard of its own
	}
	l = l.withDefaults()
	return &guarded{name: name, conn: c, limits: l, slots: make(chan struct{}, l.InFlight)}
}

func (g *guarded) Close() error {
	if cl, ok := g.conn.(interface{ Close() error }); ok {
		return cl.Close()
	}
	return nil
}

func (g *guarded) paused(call string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if left := time.Until(g.until); left > 0 {
		return fmt.Errorf("plugin %s: %s not called: its %s had no answer within %s; next try in %s: %w",
			g.name, call, g.lastStuck, g.lastD, left.Round(time.Second), ErrUnresponsive)
	}
	return nil
}

func (g *guarded) stuck(call string, d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pause <= 0 {
		g.pause = g.limits.Pause
	}
	g.until, g.lastStuck, g.lastD = time.Now().Add(g.pause), call, d
	g.pause = min(2*g.pause, g.limits.MaxPause)
}

func (g *guarded) answered() {
	g.mu.Lock()
	g.pause, g.until = 0, time.Time{}
	g.mu.Unlock()
}

// do runs one call within the plugin's limits. quick: a question (its deadline is Quick); info:
// the registry's own probe, which neither waits for a slot nor is paused.
func do[T any](ctx context.Context, g *guarded, call string, quick, info bool, f func(context.Context) (T, error)) (T, error) {
	var zero T
	d := g.limits.Work
	if quick {
		d = g.limits.Quick
	}
	if !info {
		if err := g.paused(call); err != nil {
			return zero, err
		}
		select {
		case g.slots <- struct{}{}:
		default:
			t := time.NewTimer(g.limits.Wait)
			select {
			case g.slots <- struct{}{}:
				t.Stop()
			case <-t.C:
				return zero, fmt.Errorf("plugin %s: %s not called: %d calls already waiting on it: %w", g.name, call, g.limits.InFlight, ErrUnresponsive)
			case <-ctx.Done():
				t.Stop()
				return zero, ctx.Err()
			}
		}
	}
	cctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	// The call runs on its own: one that ignores its context (a plugin in core's process) keeps
	// its slot until it returns, never the caller.
	go func() {
		if !info {
			defer func() { <-g.slots }()
		}
		v, err := f(cctx)
		done <- result{v, err}
	}()
	select {
	case r := <-done:
		if r.err != nil && errors.Is(cctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			break // ran out its deadline: as below
		}
		if !info { // an Info answer says nothing of the calls that hang
			g.answered()
		}
		return r.v, r.err
	case <-cctx.Done():
		if ctx.Err() != nil {
			return zero, ctx.Err()
		}
	}
	if !info {
		g.stuck(call, d)
	}
	return zero, fmt.Errorf("plugin %s: %s: no answer within %s: %w", g.name, call, d, ErrUnresponsive)
}

func (g *guarded) Info(ctx context.Context) (kplugin.Info, error) {
	return do(ctx, g, "Info", true, true, g.conn.Info)
}

func (g *guarded) DescribeHosts(ctx context.Context, hosts []kplugin.Host) ([]kplugin.HostInfo, error) {
	return do(ctx, g, "DescribeHosts", true, false, func(ctx context.Context) ([]kplugin.HostInfo, error) { return g.conn.DescribeHosts(ctx, hosts) })
}

func (g *guarded) EnsureLoadBalancer(ctx context.Context, lb kplugin.LoadBalancer) (kplugin.LoadBalancerStatus, error) {
	return do(ctx, g, "EnsureLoadBalancer", false, false, func(ctx context.Context) (kplugin.LoadBalancerStatus, error) {
		return g.conn.EnsureLoadBalancer(ctx, lb)
	})
}

func (g *guarded) DeleteLoadBalancer(ctx context.Context, ref kplugin.LoadBalancerRef) error {
	return none(ctx, g, "DeleteLoadBalancer", func(ctx context.Context) error { return g.conn.DeleteLoadBalancer(ctx, ref) })
}

func (g *guarded) ReserveAddress(ctx context.Context, r kplugin.AddressReservation) (kplugin.AddressStatus, error) {
	return do(ctx, g, "ReserveAddress", false, false, func(ctx context.Context) (kplugin.AddressStatus, error) { return g.conn.ReserveAddress(ctx, r) })
}

func (g *guarded) ReleaseAddress(ctx context.Context, ref kplugin.AddressRef) error {
	return none(ctx, g, "ReleaseAddress", func(ctx context.Context) error { return g.conn.ReleaseAddress(ctx, ref) })
}

func (g *guarded) EnsureVolume(ctx context.Context, v kplugin.Volume) (kplugin.VolumeStatus, error) {
	return do(ctx, g, "EnsureVolume", false, false, func(ctx context.Context) (kplugin.VolumeStatus, error) { return g.conn.EnsureVolume(ctx, v) })
}

// AttachVolume refuses a device that isn't a clean device path (K-038): it is formatted and
// mounted as root on the host, so a plugin's answer is checked before it reaches the silo's status.
func (g *guarded) AttachVolume(ctx context.Context, a kplugin.Attachment) (kplugin.AttachmentStatus, error) {
	st, err := do(ctx, g, "AttachVolume", false, false, func(ctx context.Context) (kplugin.AttachmentStatus, error) { return g.conn.AttachVolume(ctx, a) })
	if err != nil {
		return st, err
	}
	if perr := kplugin.DevicePathProblem(st.Device); perr != nil {
		return kplugin.AttachmentStatus{}, fmt.Errorf("plugin %s: AttachVolume %s: refused its answer: %w: %w", g.name, a.Handle, perr, ErrBadAnswer)
	}
	return st, nil
}

func (g *guarded) DetachVolume(ctx context.Context, a kplugin.Attachment) error {
	return none(ctx, g, "DetachVolume", func(ctx context.Context) error { return g.conn.DetachVolume(ctx, a) })
}

func (g *guarded) DeleteVolume(ctx context.Context, ref kplugin.VolumeRef) error {
	return none(ctx, g, "DeleteVolume", func(ctx context.Context) error { return g.conn.DeleteVolume(ctx, ref) })
}

func (g *guarded) EnsureRecord(ctx context.Context, r kplugin.Record) error {
	return none(ctx, g, "EnsureRecord", func(ctx context.Context) error { return g.conn.EnsureRecord(ctx, r) })
}

func (g *guarded) DeleteRecord(ctx context.Context, r kplugin.Record) error {
	return none(ctx, g, "DeleteRecord", func(ctx context.Context) error { return g.conn.DeleteRecord(ctx, r) })
}

func (g *guarded) MountVolume(ctx context.Context, m kplugin.NodeMount) error {
	return none(ctx, g, "MountVolume", func(ctx context.Context) error { return g.conn.MountVolume(ctx, m) })
}

func (g *guarded) UnmountVolume(ctx context.Context, m kplugin.NodeMount) error {
	return none(ctx, g, "UnmountVolume", func(ctx context.Context) error { return g.conn.UnmountVolume(ctx, m) })
}

func none(ctx context.Context, g *guarded, call string, f func(context.Context) error) error {
	_, err := do(ctx, g, call, false, false, func(ctx context.Context) (struct{}, error) { return struct{}{}, f(ctx) })
	return err
}
