// Package silo is the control plane's silo controller. In M3 it schedules: a new silo gets a host
// (or an Unschedulable condition explaining why each host was excluded), and stays on that host:
// silos are stateful, so moving one is never a side effect (host loss and moves come in M5 / M14).
// The host's agent takes it from Scheduled to Running.
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
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/scheduler"
)

// Phases a silo goes through.
const (
	PhasePending   = "Pending"   // waiting for a host that fits
	PhaseScheduled = "Scheduled" // a host was chosen; its agent will create the silo
)

// Decide returns the status the silo should have, and whether it differs from the current one. Pure.
func Decide(s *v1.Silo, hosts []*v1.Host, silos []*v1.Silo, now time.Time) (v1.SiloStatus, bool, error) {
	st := s.Status
	if s.DeletionTimestamp != nil || st.Host != "" {
		return st, false, nil // being deleted, or already placed: the host's agent owns it now
	}
	d, err := scheduler.Schedule(s, hosts, silos)
	if err != nil {
		return st, false, err
	}
	conds := append([]meta.Condition(nil), st.Conditions...)
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
	return st, changed, nil
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
	st, changed, err := Decide(s, hosts, silos, c.Clock.Now().UTC().Truncate(time.Second))
	if err != nil || !changed {
		return engine.Result{}, err
	}
	s.Status = st
	// Conditional on the version we read (in s.ResourceVersion): a conflict means the cache was
	// behind; the engine retries with fresh state.
	if err := c.Client.UpdateStatus(ctx, s); err != nil {
		return engine.Result{}, err
	}
	if st.Host != "" {
		c.assumed[key] = st.Host
	}
	return engine.Result{}, nil
}

// Map implements engine.Mapper: a host change (new, Ready, labels, capacity) or another silo's
// change (freed capacity) may let pending silos fit now.
func (c *Controller) Map(changed engine.Key) []engine.Key {
	if changed.Kind != "Host" && changed.Kind != "Silo" {
		return nil
	}
	var keys []engine.Key
	for _, o := range c.Silos.List() {
		s := o.(*v1.Silo)
		self := changed.Kind == "Silo" && changed.Namespace == s.Namespace && changed.Name == s.Name
		if s.Status.Host == "" && !self {
			keys = append(keys, engine.Key{Kind: "Silo", Namespace: s.Namespace, Name: s.Name})
		}
	}
	return keys
}

var (
	_ engine.Controller = (*Controller)(nil)
	_ engine.Mapper     = (*Controller)(nil)
)
