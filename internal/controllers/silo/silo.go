// Package silo is the control plane's silo controller. It schedules: a new silo gets a host (or an
// Unschedulable condition explaining why each host was excluded), and stays on that host: silos
// are stateful, so moving one is never a side effect. The host's agent takes it from Scheduled to
// Running.
//
// When its host is lost (design §0.3), the silo's onHostLoss policy decides: Wait keeps it there
// (Unknown until the host is back); Recreate starts a fresh instance elsewhere, but only after
// RecreateAfter, by which time the lost host's agent has fenced it (stopped it, if it's alive but
// cut off), so two copies never run.
package silo

import (
	"context"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	hostctl "kevaso.com/core/internal/controllers/host"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/scheduler"
)

// Phases a silo goes through.
const (
	PhasePending   = "Pending"   // waiting for a host that fits
	PhaseScheduled = "Scheduled" // a host was chosen; its agent will create the silo
	PhaseUnknown   = "Unknown"   // its host is lost
)

// RecreateAfter is how long after its host is lost a Recreate silo is started elsewhere. The lost
// host's agent fences well before (agent.FenceAfter < host lease), so this is the safety margin.
var RecreateAfter = 30 * time.Second

// Decide returns the status the silo should have, whether it differs from the current one, and
// when to look again (0: only on changes). Pure.
func Decide(s *v1.Silo, hosts []*v1.Host, silos []*v1.Silo, now time.Time, pools ...*v1.IPPool) (v1.SiloStatus, bool, time.Duration, error) {
	return DecideIn(s, hosts, silos, now, scheduler.Env{Pools: pools})
}

// DecideIn is Decide with plugins' classes.
func DecideIn(s *v1.Silo, hosts []*v1.Host, silos []*v1.Silo, now time.Time, env scheduler.Env) (v1.SiloStatus, bool, time.Duration, error) {
	st := s.Status
	st.Conditions = append([]meta.Condition(nil), st.Conditions...)
	if s.DeletionTimestamp != nil {
		return st, false, 0, nil
	}
	var again time.Duration
	movableChanged := false
	if m := moves.Summary(s, moves.Of(s, env.Classes)); m != st.Movable {
		st.Movable, movableChanged = m, true
	}
	// The image: resolved when the silo is new, and again only when spec.image changes (an Image's
	// versions never change, so a resolved one stays right). Unresolvable: a new silo waits; a
	// placed one keeps running what it has.
	imgCond := meta.Condition{Type: "Image", ObservedGeneration: s.Generation}
	imageChanged := false
	if st.Image == nil || st.Image.From != s.Spec.Image {
		var images []*v1.Image
		for _, i := range env.Images {
			if i.Namespace == s.Namespace {
				images = append(images, i)
			}
		}
		ref, err := v1.ResolveImage(s.Spec.Image, s.Spec.Runtime, images)
		if err != nil {
			imgCond.Status, imgCond.Reason, imgCond.Message = meta.ConditionFalse, "ImageMissing", err.Error()
			changed := meta.SetCondition(&st.Conditions, imgCond, now)
			if st.Host == "" {
				st.Phase = PhasePending
				changed = meta.SetCondition(&st.Conditions, meta.Condition{Type: "Scheduled", Status: meta.ConditionFalse,
					Reason: "ImageMissing", Message: err.Error(), ObservedGeneration: s.Generation}, now) || changed
				return st, changed || st.Phase != s.Status.Phase, 0, nil
			}
		} else {
			next := &v1.SiloImage{From: s.Spec.Image, Ref: ref}
			if st.Image != nil {
				next.Running, next.Reset = st.Image.Running, st.Image.Reset
			}
			st.Image = next
			imgCond.Status, imgCond.Reason, imgCond.Message = meta.ConditionTrue, "Resolved", s.Spec.Image+" → "+ref
			meta.SetCondition(&st.Conditions, imgCond, now)
			imageChanged = true
		}
	}
	if st.Host != "" {
		var h *v1.Host
		for _, x := range hosts {
			if x.Name == st.Host {
				h = x
			}
		}
		lost, since := false, time.Time{}
		if h != nil {
			lost, since = hostctl.Lost(h)
		}
		cond := meta.Condition{Type: "HostLost", ObservedGeneration: s.Generation}
		switch {
		case !lost:
			// Placed, and its host is fine: the agent owns it. Only the service's addresses may need
			// saying (its exposure changed, or it was placed before it had them).
			changed := false
			if h != nil {
				if svc, err := scheduler.ServiceStatus(s, h, silos, env); err == nil && !svc.Equal(st.Service) {
					st.Service, changed = svc, true
				}
			}
			if c := meta.FindCondition(st.Conditions, "HostLost"); c != nil && c.Status == meta.ConditionTrue {
				cond.Status, cond.Reason, cond.Message = meta.ConditionFalse, "HostBack", st.Host+" is back"
				changed = meta.SetCondition(&st.Conditions, cond, now) || changed
			}
			return st, changed || imageChanged || movableChanged, 0, nil
		case (s.Policy() == v1.OnHostLossRecreate || s.Policy() == v1.OnHostLossMove) && now.Sub(since) < RecreateAfter:
			again = RecreateAfter - now.Sub(since)
			cond.Status, cond.Reason = meta.ConditionTrue, "Fencing"
			what := "recreating"
			if s.Policy() == v1.OnHostLossMove {
				what = "moving it with its data"
			}
			cond.Message = st.Host + " lost; " + what + " elsewhere once its agent has surely stopped it (onHostLoss: " + s.Policy() + ")"
			st.Phase = PhaseUnknown
			changed := meta.SetCondition(&st.Conditions, cond, now)
			return st, changed || imageChanged || s.Status.Phase != st.Phase, again, nil
		case s.Policy() == v1.OnHostLossMove && !moves.Of(s, env.Classes).WithData:
			// Admission refuses this; a class that stopped being movable since lands here: wait.
			cond.Status, cond.Reason = meta.ConditionTrue, "Waiting"
			cond.Message = st.Host + " lost; can't move it: " + moves.Of(s, env.Classes).Pinned
			st.Phase = PhaseUnknown
			changed := meta.SetCondition(&st.Conditions, cond, now)
			return st, changed || imageChanged || s.Status.Phase != st.Phase, 0, nil
		case s.Policy() == v1.OnHostLossMove:
			// Fenced: its agent stopped it (and the volumes are force-detached from the lost host).
			cond.Status, cond.Reason = meta.ConditionFalse, "Moved"
			cond.Message = st.Host + " was lost: moved with its data (onHostLoss: Move)"
			meta.SetCondition(&st.Conditions, cond, now)
			meta.SetCondition(&st.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionFalse, Reason: "Moving",
				Message: "moving after losing " + st.Host, ObservedGeneration: s.Generation}, now)
			st.Host, st.Address, st.MovingFrom = "", "", ""
			// …and it's scheduled right away, below (its volumes keep it in their region).
		case s.Policy() == v1.OnHostLossRecreate:
			// Not lost any more (it's being placed afresh); the condition keeps what happened.
			cond.Status, cond.Reason = meta.ConditionFalse, "Recreated"
			cond.Message = st.Host + " was lost: a fresh instance from the image went elsewhere (data on its local disk is lost, by onHostLoss: Recreate)"
			meta.SetCondition(&st.Conditions, cond, now)
			meta.SetCondition(&st.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionFalse, Reason: "Recreating",
				Message: "recreating after losing " + st.Host, ObservedGeneration: s.Generation}, now)
			st.Host, st.Address, st.Init = "", "", nil
			if st.Image != nil { // a fresh instance from the image
				st.Image.Running, st.Image.Reset = "", ""
			}
			// …and it's scheduled right away, below.
		default: // Wait
			cond.Status, cond.Reason = meta.ConditionTrue, "Waiting"
			cond.Message = st.Host + " lost; waiting for it to come back (onHostLoss: Wait)"
			st.Phase = PhaseUnknown
			changed := meta.SetCondition(&st.Conditions, cond, now)
			return st, changed || imageChanged || s.Status.Phase != st.Phase, 0, nil
		}
	}
	sched := *s
	sched.Status = st
	d, err := scheduler.ScheduleIn(&sched, hosts, silos, env)
	if err != nil {
		return st, false, 0, err
	}
	conds := st.Conditions
	cond := meta.Condition{Type: "Scheduled", ObservedGeneration: s.Generation}
	if d.Host == "" {
		st.Phase = PhasePending
		cond.Status, cond.Reason, cond.Message = meta.ConditionFalse, "Unschedulable", d.Message()
	} else {
		st.Phase, st.Host = PhaseScheduled, d.Host
		cond.Status, cond.Reason, cond.Message = meta.ConditionTrue, "Scheduled", d.Message()
		for _, h := range hosts {
			if h.Name == d.Host {
				svc, err := scheduler.ServiceStatus(&sched, h, silos, env)
				if err != nil {
					return st, false, 0, err
				}
				st.Service = svc
			}
		}
	}
	changed := meta.SetCondition(&conds, cond, now)
	st.Conditions = conds
	changed = changed || imageChanged || movableChanged || st.Phase != s.Status.Phase || st.Host != s.Status.Host
	return st, changed, again, nil
}

// Controller reconciles silos.
//
// Scheduling decisions are serialized, and each placement is "assumed" (like kube-scheduler's
// assume cache) until the informer shows it: otherwise two silos decided back to back would both
// see the host's old free capacity and over-commit it.
type Controller struct {
	Client *client.Client
	Silos  *informer.Informer
	Hosts  *informer.Informer
	Pools  *informer.Informer // IPPools; nil: none
	Images *informer.Informer // Images; nil: none
	Clock  clock.Clock
	// Classes returns the plugins' classes now (nil: none).
	Classes func() map[string]scheduler.Class

	mu      sync.Mutex
	assumed map[informer.Key]string // silo → host, written but not yet seen in the cache
}

// Name implements engine.Controller.
func (c *Controller) Name() string { return "silo-scheduler" }

// Kind implements engine.Controller.
func (c *Controller) Kind() string { return "Silo" }

// lists returns hosts and silos, with assumed placements applied. Called with c.mu held.
func (c *Controller) lists() ([]*v1.Host, []*v1.Silo) {
	var hosts []*v1.Host
	for _, o := range c.Hosts.List() {
		hosts = append(hosts, o.(*v1.Host))
	}
	var silos []*v1.Silo
	for _, o := range c.Silos.List() {
		s := o.(*v1.Silo)
		k := informer.Key{Namespace: s.Namespace, Name: s.Name}
		if h, ok := c.assumed[k]; ok {
			if s.Status.Host != "" {
				delete(c.assumed, k) // the cache caught up
			} else {
				s.Status.Host = h
			}
		}
		silos = append(silos, s)
	}
	return hosts, silos
}

// Reconcile implements engine.Controller.
func (c *Controller) Reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	o, ok := c.Silos.Get(k.Namespace, k.Name)
	if !ok {
		return engine.Result{}, nil // deleted
	}
	s := o.(*v1.Silo)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.assumed == nil {
		c.assumed = map[informer.Key]string{}
	}
	key := informer.Key{Namespace: s.Namespace, Name: s.Name}
	if _, ok := c.assumed[key]; ok {
		return engine.Result{}, nil // already placed by us; the cache just hasn't caught up
	}
	hosts, silos := c.lists()
	var pools []*v1.IPPool
	if c.Pools != nil {
		for _, o := range c.Pools.List() {
			pools = append(pools, o.(*v1.IPPool))
		}
	}
	env := scheduler.Env{Pools: pools}
	if c.Images != nil {
		for _, o := range c.Images.List() {
			env.Images = append(env.Images, o.(*v1.Image))
		}
	}
	if c.Classes != nil {
		env.Classes = c.Classes()
	}
	st, changed, again, err := DecideIn(s, hosts, silos, c.Clock.Now().UTC().Truncate(time.Second), env)
	if err != nil || !changed {
		return engine.Result{RequeueAfter: again}, err
	}
	prevHost := s.Status.Host
	s.Status = st
	// Conditional on the version we read (in s.ResourceVersion): a conflict means the cache was
	// behind; the engine retries with fresh state.
	if err := c.Client.UpdateStatus(ctx, s); err != nil {
		return engine.Result{}, err
	}
	if st.Host != "" && st.Host != prevHost {
		c.assumed[key] = st.Host
	}
	return engine.Result{RequeueAfter: again}, nil
}

// Map implements engine.Mapper: a host change (new, Ready, labels, capacity, lost) or another
// silo's change (freed capacity) may let pending silos fit now, and a host change concerns the
// silos on it.
func (c *Controller) Map(changed engine.Key) []engine.Key {
	if changed.Kind != "Host" && changed.Kind != "Silo" && changed.Kind != "IPPool" && changed.Kind != "Image" {
		return nil
	}
	var keys []engine.Key
	for _, o := range c.Silos.List() {
		s := o.(*v1.Silo)
		self := changed.Kind == "Silo" && changed.Namespace == s.Namespace && changed.Name == s.Name
		onIt := (changed.Kind == "Host" && s.Status.Host == changed.Name) || (changed.Kind == "IPPool" && scheduler.PoolOf(s) == changed.Name)
		if changed.Kind == "Image" {
			name, _ := v1.SplitImage(s.Spec.Image)
			onIt = s.Namespace == changed.Namespace && name == changed.Name
		}
		if (s.Status.Host == "" && !self) || onIt {
			keys = append(keys, engine.Key{Kind: "Silo", Namespace: s.Namespace, Name: s.Name})
		}
	}
	return keys
}

var (
	_ engine.Controller = (*Controller)(nil)
	_ engine.Mapper     = (*Controller)(nil)
)
