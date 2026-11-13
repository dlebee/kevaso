// Package siloset is the SiloSet controller (design §0.2): it keeps a set's instances, each its
// own stateful Silo with a stable name (NAME-0, NAME-1, …), at the count it asks for, and rolls
// a new image or template out to them.
//
// Nothing is replaced to "heal": an instance that breaks is restarted in place by its host's
// agent. Scale-in follows the set's policy (NewestFirst or OldestFirst, the ones not Ready first)
// and never removes a protected instance (kevaso.com/protected=true). Standby instances are booted
// and idle; when the set needs more instances it takes a standby one first (a warm pool), then
// refills it.
//
// Rolling out: with upgradePolicy Rolling (or after `kvo reset siloset`) instances on an older
// revision get the current spec, which their agent applies by resetting them onto the image,
// stop-first. At most maxUnavailable fewer than `instances` are Ready meanwhile; with StartFirst
// (maxSurge) extra instances on the new revision start first, and go again when the rollout is
// done. Exclusive instances go one at a time, never with a surge.
package siloset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/engine"
)

// Finalizer keeps a SiloSet until its instances are gone.
const Finalizer = "kevaso.com/instances"

// Plan is what to do next, and the set's status.
type Plan struct {
	Create []*v1.Silo
	Update []*v1.Silo // full objects, to write as they are
	Delete []string   // instance names
	Status v1.SiloSetStatus
}

// Ready reports whether an instance is Ready on its current spec.
func Ready(s *v1.Silo) bool {
	c := meta.FindCondition(s.Status.Conditions, "Ready")
	return s.DeletionTimestamp == nil && c != nil && c.Status == meta.ConditionTrue && c.ObservedGeneration == s.Generation
}

// Owned reports whether a silo is one of set's instances.
func Owned(set *v1.SiloSet, s *v1.Silo) bool {
	for _, o := range s.OwnerReferences {
		if o.Kind == "SiloSet" && o.UID == set.UID && o.Controller {
			return true
		}
	}
	return false
}

func protected(s *v1.Silo) bool { return s.Labels[v1.LabelProtected] == "true" }
func standby(s *v1.Silo) bool   { return s.Labels[v1.LabelStandby] == "true" }

// Decide plans the set's next step from its instances (the silos it owns). Pure.
func Decide(set *v1.SiloSet, instances []*v1.Silo) Plan {
	rev := set.Revision()
	p := Plan{Status: v1.SiloSetStatus{ObservedGeneration: set.Generation, Revision: rev}}
	used := map[int]bool{}
	var active, spare []*v1.Silo
	for _, s := range instances {
		if i := v1.InstanceIndex(set.Name, s.Name); i >= 0 {
			used[i] = true
		}
		if s.DeletionTimestamp != nil {
			continue // going: not counted, but its name stays taken until it's gone
		}
		if standby(s) {
			spare = append(spare, s)
		} else {
			active = append(active, s)
		}
	}
	byIndex := func(l []*v1.Silo) {
		sort.Slice(l, func(i, j int) bool {
			return v1.InstanceIndex(set.Name, l[i].Name) < v1.InstanceIndex(set.Name, l[j].Name)
		})
	}
	byIndex(active)
	byIndex(spare)
	next := 0
	newName := func() (int, string) {
		for used[next] {
			next++
		}
		used[next] = true
		return next, v1.InstanceName(set.Name, next)
	}
	outdated := func(s *v1.Silo) bool { return s.Labels[v1.LabelRevision] != rev }
	resetDue := func(s *v1.Silo) bool { return set.Spec.Reset != "" && s.Spec.Reset != set.Spec.Reset }
	rollable := func(s *v1.Silo) bool {
		return outdated(s) && (set.Spec.UpgradePolicy == v1.UpgradeRolling || resetDue(s))
	}
	current := func(s *v1.Silo, standby bool) *v1.Silo {
		n := *s
		want := set.Instance(v1.InstanceIndex(set.Name, s.Name), standby)
		n.Spec = want.Spec
		labels := want.Labels
		if protected(s) {
			labels[v1.LabelProtected] = "true"
		}
		n.Labels = labels
		return &n
	}

	unavailable, surge := set.Limits()
	rolling := false
	for _, s := range active {
		rolling = rolling || rollable(s)
	}
	want := set.Spec.Instances
	if rolling {
		want += surge
	}

	// Short of instances: standby ones first (current ones, Ready ones first), then new ones.
	sort.SliceStable(spare, func(i, j int) bool {
		a, b := spare[i], spare[j]
		if outdated(a) != outdated(b) {
			return !outdated(a)
		}
		return Ready(a) && !Ready(b)
	})
	for len(active) < want && len(spare) > 0 {
		s := spare[0]
		spare = spare[1:]
		n := *s
		n.Labels = map[string]string{}
		for k, v := range s.Labels {
			if k != v1.LabelStandby {
				n.Labels[k] = v
			}
		}
		p.Update = append(p.Update, &n)
		active = append(active, &n)
	}
	for len(active) < want {
		i, _ := newName()
		inst := set.Instance(i, false)
		p.Create = append(p.Create, inst)
		active = append(active, inst)
	}
	for len(spare) < set.Spec.Standby {
		i, _ := newName()
		inst := set.Instance(i, true)
		p.Create = append(p.Create, inst)
		spare = append(spare, inst)
	}

	// Too many: by policy, the ones not Ready first, never protected ones.
	blocked := 0
	order := func(l []*v1.Silo) {
		sort.SliceStable(l, func(i, j int) bool {
			a, b := l[i], l[j]
			if Ready(a) != Ready(b) {
				return !Ready(a)
			}
			ta, tb := created(a), created(b)
			if !ta.Equal(tb) {
				if set.Spec.ScaleInPolicy == v1.OldestFirst {
					return ta.Before(tb)
				}
				return ta.After(tb)
			}
			ia, ib := v1.InstanceIndex(set.Name, a.Name), v1.InstanceIndex(set.Name, b.Name)
			if set.Spec.ScaleInPolicy == v1.OldestFirst {
				return ia < ib
			}
			return ia > ib
		})
	}
	trim := func(l []*v1.Silo, keep int) []*v1.Silo {
		if len(l) <= keep {
			return l
		}
		cands := append([]*v1.Silo(nil), l...)
		order(cands)
		gone := map[string]bool{}
		for _, s := range cands {
			if len(l)-len(gone) <= keep {
				break
			}
			if protected(s) {
				blocked++
				continue
			}
			gone[s.Name] = true
			p.Delete = append(p.Delete, s.Name)
		}
		var out []*v1.Silo
		for _, s := range l {
			if !gone[s.Name] {
				out = append(out, s)
			}
		}
		return out
	}
	active = trim(active, want)
	spare = trim(spare, set.Spec.Standby)

	// Rolling out: instances not Ready already can go at once; Ready ones while enough stay Ready.
	minReady := set.Spec.Instances - unavailable
	readyNow := 0
	for _, s := range active {
		if Ready(s) && !isNew(p, s) {
			readyNow++
		}
	}
	updated := map[string]bool{}
	for _, s := range p.Update {
		updated[s.Name] = true
	}
	for _, s := range active {
		if !rollable(s) || isNew(p, s) || updated[s.Name] {
			continue
		}
		if Ready(s) {
			if readyNow-1 < minReady {
				continue
			}
			readyNow--
		}
		p.Update = append(p.Update, current(s, false))
	}
	for _, s := range spare {
		if outdated(s) && !isNew(p, s) && !updated[s.Name] { // idle: no reason to wait
			p.Update = append(p.Update, current(s, true))
		}
	}

	// Status, as of now (what's being created isn't there yet).
	st := &p.Status
	for _, s := range instances {
		if s.DeletionTimestamp != nil {
			continue
		}
		st.Instances++
		if standby(s) {
			st.Standby++
			continue
		}
		if Ready(s) {
			st.Ready++
		}
		if !outdated(s) {
			st.Updated++
		}
	}
	cond := meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: "AllReady", ObservedGeneration: set.Generation,
		Message: fmt.Sprintf("%d/%d ready, all on revision %s", st.Ready, set.Spec.Instances, rev)}
	switch {
	case blocked > 0:
		cond.Status, cond.Reason = meta.ConditionFalse, "ScaleInBlocked"
		cond.Message = fmt.Sprintf("%d protected instance(s) can't be removed (kvo protect silo NAME --off)", blocked)
	case st.Ready < set.Spec.Instances:
		cond.Status, cond.Reason = meta.ConditionFalse, "NotAllReady"
		cond.Message = fmt.Sprintf("%d/%d ready", st.Ready, set.Spec.Instances)
	case st.Updated < st.Instances-st.Standby && set.Spec.UpgradePolicy != v1.UpgradeRolling && !rolling:
		cond.Reason = "UpdateAvailable"
		cond.Message = fmt.Sprintf("%d/%d ready; %d on an older revision (upgradePolicy Manual: kvo reset silo NAME, or kvo reset siloset %s --rolling)",
			st.Ready, set.Spec.Instances, st.Instances-st.Standby-st.Updated, set.Name)
	case rolling || st.Updated < st.Instances-st.Standby:
		cond.Status, cond.Reason = meta.ConditionFalse, "RollingOut"
		cond.Message = fmt.Sprintf("%d/%d ready, %d on revision %s", st.Ready, set.Spec.Instances, st.Updated, rev)
	}
	meta.SetCondition(&st.Conditions, cond, time.Time{})
	return p
}

func isNew(p Plan, s *v1.Silo) bool {
	for _, c := range p.Create {
		if c == s {
			return true
		}
	}
	return false
}

func created(s *v1.Silo) time.Time {
	if s.CreationTimestamp == nil {
		return time.Time{}
	}
	return *s.CreationTimestamp
}

// Controller runs Decide for every set and applies the plan.
type Controller struct {
	Client *client.Client
	Sets   *informer.Informer
	Silos  *informer.Informer
	Clock  clock.Clock
}

// Name implements engine.Controller.
func (c *Controller) Name() string { return "siloset" }

// Kind implements engine.Controller.
func (c *Controller) Kind() string { return "SiloSet" }

func (c *Controller) instances(set *v1.SiloSet) []*v1.Silo {
	var out []*v1.Silo
	for _, o := range c.Silos.List() {
		if s := o.(*v1.Silo); s.Namespace == set.Namespace && Owned(set, s) {
			out = append(out, s)
		}
	}
	return out
}

// Reconcile implements engine.Controller.
func (c *Controller) Reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	o, ok := c.Sets.Get(k.Namespace, k.Name)
	if !ok {
		return engine.Result{}, nil
	}
	set := o.(*v1.SiloSet)
	insts := c.instances(set)
	if set.DeletionTimestamp != nil {
		for _, s := range insts {
			if s.DeletionTimestamp == nil {
				if err := c.Client.Delete(ctx, "Silo", s.Namespace, s.Name); client.IgnoreNotFound(err) != nil {
					return engine.Result{}, err
				}
			}
		}
		if len(insts) > 0 {
			return engine.Result{RequeueAfter: 5 * time.Second}, nil // their own finalizers (volumes) first
		}
		return engine.Result{}, c.finalizer(ctx, set, false)
	}
	if !hasFinalizer(set) {
		return engine.Result{}, c.finalizer(ctx, set, true)
	}
	p := Decide(set, insts)
	var errs []error
	for _, s := range p.Create {
		if err := c.Client.Create(ctx, s); err != nil && !client.IsAlreadyExists(err) {
			errs = append(errs, fmt.Errorf("create %s: %w", s.Name, err))
		}
	}
	for _, s := range p.Update {
		if err := c.Client.Update(ctx, s); err != nil {
			errs = append(errs, fmt.Errorf("update %s: %w", s.Name, err))
		}
	}
	for _, name := range p.Delete {
		if err := c.Client.Delete(ctx, "Silo", set.Namespace, name); client.IgnoreNotFound(err) != nil {
			errs = append(errs, fmt.Errorf("delete %s: %w", name, err))
		}
	}
	if err := c.status(ctx, set, p.Status); err != nil {
		errs = append(errs, err)
	}
	return engine.Result{}, errors.Join(errs...)
}

func jsonOf(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func hasFinalizer(set *v1.SiloSet) bool {
	for _, f := range set.Finalizers {
		if f == Finalizer {
			return true
		}
	}
	return false
}

func (c *Controller) now() time.Time {
	if c.Clock == nil {
		return time.Now().UTC().Truncate(time.Second)
	}
	return c.Clock.Now().UTC().Truncate(time.Second)
}

func (c *Controller) status(ctx context.Context, set *v1.SiloSet, want v1.SiloSetStatus) error {
	for attempt := 0; attempt < 5; attempt++ {
		var cur v1.SiloSet
		if err := c.Client.Get(ctx, "SiloSet", set.Namespace, set.Name, &cur); err != nil {
			return client.IgnoreNotFound(err)
		}
		next := want
		next.Conditions = append([]meta.Condition(nil), cur.Status.Conditions...)
		for _, cond := range want.Conditions {
			meta.SetCondition(&next.Conditions, cond, c.now())
		}
		if a, b := jsonOf(next), jsonOf(cur.Status); a == b {
			return nil
		}
		cur.Status = next
		err := c.Client.UpdateStatus(ctx, &cur)
		if client.IsConflict(err) {
			continue
		}
		return err
	}
	return errors.New("siloset kept changing; will retry")
}

func (c *Controller) finalizer(ctx context.Context, set *v1.SiloSet, add bool) error {
	for attempt := 0; attempt < 5; attempt++ {
		var cur v1.SiloSet
		if err := c.Client.Get(ctx, "SiloSet", set.Namespace, set.Name, &cur); err != nil {
			return client.IgnoreNotFound(err)
		}
		var fs []string
		for _, f := range cur.Finalizers {
			if f != Finalizer {
				fs = append(fs, f)
			}
		}
		if add {
			if cur.DeletionTimestamp != nil || hasFinalizer(&cur) {
				return nil
			}
			fs = append(fs, Finalizer)
		} else if !hasFinalizer(&cur) {
			return nil
		}
		cur.Finalizers = fs
		err := c.Client.Update(ctx, &cur)
		if client.IsConflict(err) {
			continue
		}
		return client.IgnoreNotFound(err)
	}
	return errors.New("siloset kept changing; will retry")
}

// Map implements engine.Mapper: an instance's change reaches its set.
func (c *Controller) Map(changed engine.Key) []engine.Key {
	if changed.Kind != "Silo" {
		return nil
	}
	o, ok := c.Silos.Get(changed.Namespace, changed.Name)
	if ok {
		for _, r := range o.(*v1.Silo).OwnerReferences {
			if r.Kind == "SiloSet" && r.Controller {
				return []engine.Key{{Kind: "SiloSet", Namespace: changed.Namespace, Name: r.Name}}
			}
		}
		return nil
	}
	// Gone: the set named like it, if any, may need a new one.
	for _, so := range c.Sets.List() {
		if set := so.(*v1.SiloSet); set.Namespace == changed.Namespace && strings.HasPrefix(changed.Name, set.Name+"-") && v1.InstanceIndex(set.Name, changed.Name) >= 0 {
			return []engine.Key{{Kind: "SiloSet", Namespace: set.Namespace, Name: set.Name}}
		}
	}
	return nil
}

var (
	_ engine.Controller = (*Controller)(nil)
	_ engine.Mapper     = (*Controller)(nil)
)
