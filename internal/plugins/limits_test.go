package plugins

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/sdk/kplugin"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

// hung is a plugin whose volume calls never return, not even when their context ends (the worst
// a plugin in core's process can do; over gRPC the call ends with its context).
type hung struct {
	Conn
	name  string
	only  string // serve only this storage class ("": the fake's)
	calls atomic.Int32
}

func (h *hung) Info(ctx context.Context) (kplugin.Info, error) {
	i, err := h.Conn.Info(ctx)
	i.Name = h.name
	if h.only != "" { // a second plugin in one registry serves classes of its own (K-042)
		i.Storage, i.LoadBalancers, i.DNS = []kplugin.Class{{Name: h.only}}, nil, nil
	}
	return i, err
}

func (h *hung) EnsureVolume(context.Context, kplugin.Volume) (kplugin.VolumeStatus, error) {
	h.calls.Add(1)
	select {}
}

func (h *hung) MountVolume(ctx context.Context, _ kplugin.NodeMount) error {
	h.calls.Add(1)
	<-ctx.Done() // a gRPC call: it ends with its context
	return ctx.Err()
}

var fast = Limits{Quick: 50 * time.Millisecond, Work: 100 * time.Millisecond, Wait: 20 * time.Millisecond, Pause: time.Hour}

func plugin(t *testing.T, r *Registry, name string) *Plugin {
	t.Helper()
	for _, p := range r.All() {
		if p.Info.Name == name {
			return p
		}
	}
	t.Fatalf("no plugin %s", name)
	return nil
}

// K-041: a call to a plugin that never answers ends at its deadline with an error naming the
// plugin and the call; the next calls fail at once while it is paused; Info still goes through.
func TestHungPluginCallsEnd(t *testing.T) {
	r := &Registry{Limits: fast}
	h := &hung{Conn: kplugintest.New(), name: "stuck"}
	if err := r.Add(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	p := plugin(t, r, "stuck")
	start := time.Now()
	_, err := p.Conn.EnsureVolume(context.Background(), kplugin.Volume{})
	if !errors.Is(err, ErrUnresponsive) || !strings.Contains(err.Error(), "plugin stuck: EnsureVolume: no answer within 100ms") {
		t.Fatalf("hung call: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("hung call took %s", d)
	}
	start = time.Now()
	err = p.Conn.MountVolume(context.Background(), kplugin.NodeMount{})
	if !errors.Is(err, ErrUnresponsive) || !strings.Contains(err.Error(), "not called") || time.Since(start) > 50*time.Millisecond {
		t.Fatalf("paused plugin, next call: %v after %s", err, time.Since(start))
	}
	if n := h.calls.Load(); n != 1 {
		t.Errorf("a paused plugin was called: %d calls", n)
	}
	if _, err := p.Conn.Info(context.Background()); err != nil {
		t.Errorf("Info on a paused plugin: %v", err)
	}
}

// Every kind of call has a deadline (no call left without one), quick ones the shorter.
func TestEveryCallHasADeadline(t *testing.T) {
	g := guard("p", deadlines{}, Limits{Quick: 10 * time.Second, Work: time.Minute})
	ctx := context.Background()
	checks := map[string]func() error{
		"Info":               func() error { _, err := g.Info(ctx); return err },
		"DescribeHosts":      func() error { _, err := g.DescribeHosts(ctx, nil); return err },
		"EnsureLoadBalancer": func() error { _, err := g.EnsureLoadBalancer(ctx, kplugin.LoadBalancer{}); return err },
		"DeleteLoadBalancer": func() error { return g.DeleteLoadBalancer(ctx, kplugin.LoadBalancerRef{}) },
		"ReserveAddress":     func() error { _, err := g.ReserveAddress(ctx, kplugin.AddressReservation{}); return err },
		"ReleaseAddress":     func() error { return g.ReleaseAddress(ctx, kplugin.AddressRef{}) },
		"EnsureVolume":       func() error { _, err := g.EnsureVolume(ctx, kplugin.Volume{}); return err },
		"AttachVolume":       func() error { _, err := g.AttachVolume(ctx, kplugin.Attachment{}); return err },
		"DetachVolume":       func() error { return g.DetachVolume(ctx, kplugin.Attachment{}) },
		"DeleteVolume":       func() error { return g.DeleteVolume(ctx, kplugin.VolumeRef{}) },
		"EnsureRecord":       func() error { return g.EnsureRecord(ctx, kplugin.Record{}) },
		"DeleteRecord":       func() error { return g.DeleteRecord(ctx, kplugin.Record{}) },
		"MountVolume":        func() error { return g.MountVolume(ctx, kplugin.NodeMount{}) },
		"UnmountVolume":      func() error { return g.UnmountVolume(ctx, kplugin.NodeMount{}) },
	}
	for call, f := range checks {
		err := f()
		var d deadline
		if !errors.As(err, &d) {
			t.Errorf("%s: no deadline (%v)", call, err)
			continue
		}
		want := time.Minute
		if call == "Info" || call == "DescribeHosts" {
			want = 10 * time.Second
		}
		if d.left > want || d.left < want-5*time.Second {
			t.Errorf("%s: deadline in %s, want %s", call, d.left, want)
		}
	}
}

// deadline is what deadlines answers: how long the call had left.
type deadline struct{ left time.Duration }

func (deadline) Error() string { return "deadline" }

type deadlines struct{ Conn }

func left(ctx context.Context) error {
	d, ok := ctx.Deadline()
	if !ok {
		return errors.New("no deadline")
	}
	return deadline{time.Until(d)}
}

func (deadlines) Info(ctx context.Context) (kplugin.Info, error) { return kplugin.Info{}, left(ctx) }
func (deadlines) DescribeHosts(ctx context.Context, _ []kplugin.Host) ([]kplugin.HostInfo, error) {
	return nil, left(ctx)
}
func (deadlines) EnsureLoadBalancer(ctx context.Context, _ kplugin.LoadBalancer) (kplugin.LoadBalancerStatus, error) {
	return kplugin.LoadBalancerStatus{}, left(ctx)
}
func (deadlines) DeleteLoadBalancer(ctx context.Context, _ kplugin.LoadBalancerRef) error {
	return left(ctx)
}
func (deadlines) ReserveAddress(ctx context.Context, _ kplugin.AddressReservation) (kplugin.AddressStatus, error) {
	return kplugin.AddressStatus{}, left(ctx)
}
func (deadlines) ReleaseAddress(ctx context.Context, _ kplugin.AddressRef) error { return left(ctx) }
func (deadlines) EnsureVolume(ctx context.Context, _ kplugin.Volume) (kplugin.VolumeStatus, error) {
	return kplugin.VolumeStatus{}, left(ctx)
}
func (deadlines) AttachVolume(ctx context.Context, _ kplugin.Attachment) (kplugin.AttachmentStatus, error) {
	return kplugin.AttachmentStatus{}, left(ctx)
}
func (deadlines) DetachVolume(ctx context.Context, _ kplugin.Attachment) error { return left(ctx) }
func (deadlines) DeleteVolume(ctx context.Context, _ kplugin.VolumeRef) error  { return left(ctx) }
func (deadlines) EnsureRecord(ctx context.Context, _ kplugin.Record) error     { return left(ctx) }
func (deadlines) DeleteRecord(ctx context.Context, _ kplugin.Record) error     { return left(ctx) }
func (deadlines) MountVolume(ctx context.Context, _ kplugin.NodeMount) error   { return left(ctx) }
func (deadlines) UnmountVolume(ctx context.Context, _ kplugin.NodeMount) error { return left(ctx) }

// At most InFlight calls wait on one plugin: one that hangs cannot gather every caller.
func TestOnePluginsCallsInFlightAreLimited(t *testing.T) {
	l := fast
	l.Work, l.Pause, l.InFlight = time.Hour, time.Hour, 2
	r := &Registry{Limits: l}
	h := &hung{Conn: kplugintest.New(), name: "slow"}
	_ = r.Add(context.Background(), h)
	p := plugin(t, r, "slow")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); _ = p.Conn.MountVolume(ctx, kplugin.NodeMount{}) }()
	}
	for h.calls.Load() < 2 {
		time.Sleep(time.Millisecond)
	}
	start := time.Now()
	err := p.Conn.MountVolume(context.Background(), kplugin.NodeMount{})
	if !errors.Is(err, ErrUnresponsive) || !strings.Contains(err.Error(), "2 calls already waiting") || time.Since(start) > time.Second {
		t.Fatalf("third call: %v after %s", err, time.Since(start))
	}
	cancel()
	wg.Wait()
}

// The shape K-041 is about: one controller, one worker (the IP controller's), keys for a plugin
// that hangs and for one that answers. The hung plugin's keys used to hold the worker for good;
// now the other plugin's key is done within one deadline.
func TestHungPluginDoesNotHoldSharedWorkers(t *testing.T) {
	r := &Registry{Limits: fast}
	_ = r.Add(context.Background(), &hung{Conn: kplugintest.New(), name: "stuck"})
	_ = r.Add(context.Background(), &hung{Conn: kplugintest.New(), name: "fine", only: "fine-block"})
	fine := plugin(t, r, "fine")
	done := make(chan struct{})
	ctl := &oneWorker{reg: r, done: done, fine: fine}
	e := engine.New(clock.Real{})
	e.Register(ctl, engine.Options{Workers: 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	for _, n := range []string{"stuck-1", "stuck-2", "stuck-3", "stuck-4", "fine"} {
		e.Changed(engine.Key{Kind: "Volume", Name: n})
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the answering plugin's key never ran: the hung plugin holds the only worker")
	}
}

type oneWorker struct {
	reg  *Registry
	fine *Plugin
	done chan struct{}
	once sync.Once
}

func (*oneWorker) Name() string { return "volumes" }
func (*oneWorker) Kind() string { return "Volume" }
func (c *oneWorker) Reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	if k.Name == "fine" {
		err := c.fine.Conn.DeleteVolume(ctx, kplugin.VolumeRef{Class: kplugintest.ClassBlock, Handle: "none"})
		if err != nil && !errors.Is(err, kplugin.ErrNotFound) {
			return engine.Result{}, err
		}
		c.once.Do(func() { close(c.done) })
		return engine.Result{}, nil
	}
	for _, p := range c.reg.All() {
		if p.Info.Name == "stuck" {
			_, err := p.Conn.EnsureVolume(ctx, kplugin.Volume{})
			return engine.Result{}, err
		}
	}
	return engine.Result{}, nil
}
