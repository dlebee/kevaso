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
func Decide(s *v1.Silo, hosts []*v1.Host, silos []*v1.Silo, now time.Time) (v1.SiloStatus, bool, time.Duration, error) {
	st := s.Status
	st.Conditions = append([]meta.Condition(nil), st.Conditions...)
	if s.DeletionTimestamp != nil {
		return st, false, 0, nil
	}
	var again time.Duration
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
			if c := meta.FindCondition(st.Conditions, "HostLost"); c == nil || c.Status != meta.ConditionTrue {
				return st, false, 0, nil // placed, and its host is fine: the agent owns it
			}
			cond.Status, cond.Reason, cond.Message = meta.ConditionFalse, "HostBack", st.Host+" is back"
			changed := meta.SetCondition(&st.Conditions, cond, now)
			return st, changed, 0, nil
		case s.Policy() == v1.OnHostLossRecreate && now.Sub(since) < RecreateAfter:
			again = RecreateAfter - now.Sub(since)
			cond.Status, cond.Reason = meta.ConditionTrue, "Fencing"
			cond.Message = st.Host + " lost; recreating elsewhere once its agent has surely stopped it (onHostLoss: Recreate)"
			st.Phase = PhaseUnknown
			changed := meta.SetCondition(&st.Conditions, cond, now)
			return st, changed || s.Status.Phase != st.Phase, again, nil
		case s.Policy() == v1.OnHostLossRecreate:
			// Not lost any more (it's being placed afresh); the condition keeps what happened.
			cond.Status, cond.Reason = meta.ConditionFalse, "Recreated"
			cond.Message = st.Host + " was lost: a fresh instance from the image went elsewhere (data on its local disk is lost, by onHostLoss: Recreate)"
			meta.SetCondition(&st.Conditions, cond, now)
			meta.SetCondition(&st.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionFalse, Reason: "Recreating",
				Message: "recreating after losing " + st.Host, ObservedGeneration: s.Generation}, now)
			st.Host, st.Address, st.Init = "", "", nil
			// …and it's scheduled right away, below.
		default: // Wait
			cond.Status, cond.Reason = meta.ConditionTrue, "Waiting"
			cond.Message = st.Host + " lost; waiting for it to come back (onHostLoss: Wait)"
			st.Phase = PhaseUnknown
			changed := meta.SetCondition(&st.Conditions, cond, now)
			return st, changed || s.Status.Phase != st.Phase, 0, nil
		}
	}
	sched := *s
	sched.Status = st
	d, err := scheduler.Schedule(&sched, hosts, silos)
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
	}
	changed := meta.SetCondition(&conds, cond, now)
	st.Conditions = conds
	changed = changed || st.Phase != s.Status.Phase || st.Host != s.Status.Host
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
	Clock  clock.Clock

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
	st, changed, again, err := Decide(s, hosts, silos, c.Clock.Now().UTC().Truncate(time.Second))
	if err != nil || !changed {
		return engine.Result{RequeueAfter: again}, err
	}
	s.Status = st
	// Conditional on the version we read (in s.ResourceVersion): a conflict means the cache was
	// behind; the engine retries with fresh state.
	if err := c.Client.UpdateStatus(ctx, s); err != nil {
		return engine.Result{}, err
	}
	if st.Host != "" && st.Host != s.Status.Host {
		c.assumed[key] = st.Host
	}
	return engine.Result{RequeueAfter: again}, nil
}

// Map implements engine.Mapper: a host change (new, Ready, labels, capacity, lost) or another
// silo's change (freed capacity) may let pending silos fit now, and a host change concerns the
// silos on it.
func (c *Controller) Map(changed engine.Key) []engine.Key {
	if changed.Kind != "Host" && changed.Kind != "Silo" {
		return nil
	}
	var keys []engine.Key
	for _, o := range c.Silos.List() {
		s := o.(*v1.Silo)
		self := changed.Kind == "Silo" && changed.Namespace == s.Namespace && changed.Name == s.Name
		onIt := changed.Kind == "Host" && s.Status.Host == changed.Name
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
