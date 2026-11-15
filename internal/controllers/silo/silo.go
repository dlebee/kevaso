// Package silo is the control plane's silo controller. It schedules: a new silo gets a host (or an
// Unschedulable condition explaining why each host was excluded), and stays on that host: silos
// are stateful, so moving one is never a side effect. The host's agent takes it from Scheduled to
// Running.
//
// When its host is silent (brainstorm §0.7), the silo stays there, Unknown, with a HostUnreachable
// condition saying since when: the control plane never starts another copy by itself, since a
// cut-off host still runs it. A person's `kvo move … --confirm-fenced` moves it once the old copy
// is known to be off, and onHostLoss says how (Move: with its data; Recreate: a fresh copy).
package silo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/claims"
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

// RecreateAfter no longer starts anything: the control plane never restarts a silent host's
// silos by itself (brainstorm §0.7). It stays only for internal/agent's TestFenceTiming (host
// lane), until that test moves to the onControlPlaneLoss: Stop timing. Nothing in the control
// plane reads it.
var RecreateAfter = 30 * time.Second

// CondHostUnreachable is the silo condition saying its host is silent, since when, and what a
// person can do (brainstorm §0.7).
const CondHostUnreachable = "HostUnreachable"

// UnreachableMessage is HostUnreachable's message: since when, that nothing is started elsewhere,
// and what onHostLoss makes of a confirmed move.
func UnreachableMessage(s *v1.Silo, since time.Time, m moves.Movability) string {
	host := s.Status.Host
	msg := fmt.Sprintf("%s unreachable since %s. It may still be running there, so Kevaso starts no other copy. ", host, since.UTC().Format(time.RFC3339))
	move := fmt.Sprintf("kvo move silo %s -n %s --to HOST --confirm-fenced", s.Name, s.Namespace)
	switch {
	case s.Policy() == v1.OnHostLossRecreate:
		return msg + "Once the old copy is known to be off (the host powered off, or force-stopped through its provider), " +
			move + " --recreate starts a fresh copy from its image (onHostLoss: Recreate; data on its own disk is lost)"
	case m.WithData:
		return msg + "Once the old copy is known to be off (the host powered off, or force-stopped through its provider), " +
			move + " moves it with its data (onHostLoss: " + s.Policy() + "), or wait for " + host + " to come back"
	default:
		return msg + "Waiting for " + host + " to come back (onHostLoss: " + s.Policy() + "; it can't move: " + m.Pinned + "; a fresh copy needs onHostLoss: Recreate and kvo move … --confirm-fenced --recreate)"
	}
}

// Decide returns the status the silo should have, whether it differs from the current one, and
// when to look again (0: only on changes). Pure.
func Decide(s *v1.Silo, hosts []*v1.Host, silos []*v1.Silo, now time.Time, ips ...*v1.IP) (v1.SiloStatus, bool, time.Duration, error) {
	return DecideIn(s, hosts, silos, now, scheduler.Env{IPs: ips})
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
	// The image: resolved when the silo is new, and again only when what it starts from changes
	// (container.image, vm.image, vm.disk; a VMImage's versions never change, so a resolved one
	// stays right). Unresolvable: a new silo waits; a
	// placed one keeps running what it has.
	imgCond := meta.Condition{Type: "Image", ObservedGeneration: s.Generation}
	imageChanged := false
	if st.Image == nil || st.Image.From != s.Spec.From() {
		var images []*v1.VMImage
		for _, i := range env.Images {
			if i.Namespace == s.Namespace {
				images = append(images, i)
			}
		}
		ref, err := v1.ResolveImage(s.Spec, images)
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
			next := &v1.SiloImage{From: s.Spec.From(), Ref: ref}
			if st.Image != nil {
				next.Running, next.Reset = st.Image.Running, st.Image.Reset
			}
			st.Image = next
			imgCond.Status, imgCond.Reason, imgCond.Message = meta.ConditionTrue, "Resolved", s.Spec.From()+" → "+ref
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
		cond := meta.Condition{Type: CondHostUnreachable, ObservedGeneration: s.Generation}
		if !lost {
			// Placed, and its host is fine: the agent owns it. Only the service's addresses may need
			// saying (its exposure changed, or it was placed before it had them).
			changed := false
			if h != nil {
				if svc, err := scheduler.ServiceStatus(s, h, silos, env); err == nil && !svc.Equal(st.Service) {
					st.Service, changed = svc, true
				}
			}
			if c := meta.FindCondition(st.Conditions, CondHostUnreachable); c != nil && c.Status == meta.ConditionTrue {
				cond.Status, cond.Reason, cond.Message = meta.ConditionFalse, "HostBack", st.Host+" is back"
				changed = meta.SetCondition(&st.Conditions, cond, now) || changed
			}
			return st, changed || imageChanged || movableChanged, 0, nil
		}
		if st.MovingFrom != "" && st.MovingFrom != st.Host {
			// The silent host is the destination of a handoff its source hasn't finished: it never
			// started the silo (moves.MayStart: not before the source lets go), so no copy runs
			// there and another destination is safe. The handoff stays: the next host waits for
			// the source as the silent one did (K-005).
			cond.Status, cond.Reason = meta.ConditionFalse, "NewDestination"
			cond.Message = fmt.Sprintf("%s, where it was moving, is unreachable; it never started there (%s hasn't let go): placing it elsewhere", st.Host, st.MovingFrom)
			meta.SetCondition(&st.Conditions, cond, now)
			st.Host, st.SiloIP = "", ""
			// …and it's scheduled right away, below.
		} else {
			// Its host is silent (brainstorm §0.7). Kevaso can't tell a dead host from a cut-off
			// one, and a cut-off host still runs the silo: so nothing is started elsewhere. A
			// person who knows the old copy is off moves it (kvo move … --confirm-fenced);
			// onHostLoss says how.
			cond.Status, cond.Reason = meta.ConditionTrue, "Waiting"
			cond.Message = UnreachableMessage(s, since, moves.Of(s, env.Classes))
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
		if st.MovingFrom == st.Host {
			st.MovingFrom = "" // back on the host it was moving from: nothing to hand off
		}
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
	IPs    *informer.Informer // IP objects; nil: none
	Images *informer.Informer // VMImages; nil: none
	Clock  clock.Clock
	// Classes returns the plugins' classes now (nil: none).
	Classes func() map[string]scheduler.Class
	// Claims make each node port and host port on a host one silo's, by the store (K-029).
	Claims *claims.Claims

	mu      sync.Mutex
	assumed map[informer.Key]string // silo → host, written but not yet seen in the cache
	mine    sync.Map                // POOL/VALUE → UID: claimed by this controller
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
		if s.Status.Host == "" {
			return engine.Result{}, nil // already placed by us; the cache just hasn't caught up
		}
		delete(c.assumed, key) // it has: from now on the cache is what's true (a lost host, a move)
	}
	hosts, silos := c.lists()
	env := scheduler.Env{Hosts: hosts, Suffix: v1.ClusterSuffix(hosts)}
	if c.IPs != nil {
		for _, o := range c.IPs.List() {
			env.IPs = append(env.IPs, o.(*v1.IP))
		}
	}
	if c.Images != nil {
		for _, o := range c.Images.List() {
			env.Images = append(env.Images, o.(*v1.VMImage))
		}
	}
	if c.Classes != nil {
		env.Classes = c.Classes()
	}
	now := c.Clock.Now().UTC().Truncate(time.Second)
	st, changed, again, err := DecideIn(s, hosts, silos, now, env)
	// The node ports and host ports it would have, claimed in the store before they are written
	// (K-029): one another silo holds there is avoided, and it is decided again.
	for attempt := 0; err == nil && changed && c.Claims != nil && st.Host != ""; attempt++ {
		if attempt == 8 {
			return engine.Result{}, errors.New("node or host ports kept being taken; will retry")
		}
		held, cerr := c.claim(ctx, s, st)
		if cerr != nil {
			return engine.Result{}, cerr
		}
		if held == nil {
			break
		}
		if env.Claimed == nil {
			env.Claimed = map[string]scheduler.Claimed{}
		}
		env.Claimed[st.Host] = merge(env.Claimed[st.Host], *held)
		st, changed, again, err = DecideIn(s, hosts, silos, now, env)
	}
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

// The pools a silo's values on a host are claimed in (claims.Claims), one per host.
func poolNodePort(host string) string { return "silo-node-port." + host }
func poolHostPort(host string) string { return "host-port." + host }

func hostPortValue(p scheduler.HostPort) string {
	return fmt.Sprintf("%s-%s-%d", p.Network, strings.ToLower(p.Proto), p.Port)
}

// on reports whether a stored silo is on host (placed there, or still handing off from it).
func on(obj []byte, host string) (*v1.Silo, bool) {
	var s v1.Silo
	if json.Unmarshal(obj, &s) != nil {
		return nil, false
	}
	return &s, s.Status.Host == host || s.Status.MovingFrom == host
}

func usesNodePort(host string) claims.Uses {
	return func(obj []byte, value string) bool {
		s, ok := on(obj, host)
		return ok && slices.ContainsFunc(s.Status.Service.NodePorts, func(p v1.NodePort) bool { return strconv.Itoa(p.NodePort) == value })
	}
}

func usesHostPort(host string) claims.Uses {
	return func(obj []byte, value string) bool {
		s, ok := on(obj, host)
		return ok && slices.ContainsFunc(scheduler.HostPorts(s), func(p scheduler.HostPort) bool { return hostPortValue(p) == value })
	}
}

// claim claims st's node ports and s's host ports on st.Host for s, at the version its status
// write is conditional on. held: what someone else holds there (nil: everything is s's).
func (c *Controller) claim(ctx context.Context, s *v1.Silo, st v1.SiloStatus) (*scheduler.Claimed, error) {
	h := claims.Holder{Kind: "Silo", Namespace: s.Namespace, Name: s.Name, UID: s.UID, Version: s.ResourceVersion}
	held := scheduler.Claimed{NodePorts: map[int]bool{}, HostPorts: map[scheduler.HostPort]bool{}}
	there := s.Status.Host == st.Host // what it has now, it has on this host
	take := func(pool, value string, has bool, uses claims.Uses) (bool, error) {
		// A value it already has there, claimed by this controller, is still its own (a claim is
		// only taken over once the stored silo stops having it).
		if u, ok := c.mine.Load(pool + "/" + value); has && ok && u == h.UID {
			return true, nil
		}
		ok, err := c.Claims.Take(ctx, pool, value, h, uses)
		if ok {
			c.mine.Store(pool+"/"+value, h.UID)
		}
		return ok, err
	}
	for _, p := range st.Service.NodePorts {
		has := there && slices.ContainsFunc(s.Status.Service.NodePorts, func(q v1.NodePort) bool { return q.NodePort == p.NodePort })
		ok, err := take(poolNodePort(st.Host), strconv.Itoa(p.NodePort), has, usesNodePort(st.Host))
		if err != nil {
			return nil, err
		}
		if !ok {
			held.NodePorts[p.NodePort] = true
		}
	}
	for _, p := range scheduler.HostPorts(s) {
		ok, err := take(poolHostPort(st.Host), hostPortValue(p), there, usesHostPort(st.Host))
		if err != nil {
			return nil, err
		}
		if !ok {
			held.HostPorts[p] = true
		}
	}
	if len(held.NodePorts) == 0 && len(held.HostPorts) == 0 {
		return nil, nil
	}
	return &held, nil
}

func merge(a, b scheduler.Claimed) scheduler.Claimed {
	out := scheduler.Claimed{NodePorts: maps.Clone(a.NodePorts), HostPorts: maps.Clone(a.HostPorts)}
	if out.NodePorts == nil {
		out.NodePorts = map[int]bool{}
	}
	if out.HostPorts == nil {
		out.HostPorts = map[scheduler.HostPort]bool{}
	}
	maps.Copy(out.NodePorts, b.NodePorts)
	maps.Copy(out.HostPorts, b.HostPorts)
	return out
}

func (c *Controller) classes() map[string]scheduler.Class {
	if c.Classes == nil {
		return nil
	}
	return c.Classes()
}

// Map implements engine.Mapper: a host change (new, Ready, labels, capacity, lost) or another
// silo's change (freed capacity) may let pending silos fit now, and a host change concerns the
// silos on it.
func (c *Controller) Map(changed engine.Key) []engine.Key {
	if changed.Kind != "Host" && changed.Kind != "Silo" && changed.Kind != "IP" && changed.Kind != "VMImage" {
		return nil
	}
	var keys []engine.Key
	for _, o := range c.Silos.List() {
		s := o.(*v1.Silo)
		self := changed.Kind == "Silo" && changed.Namespace == s.Namespace && changed.Name == s.Name
		onIt := (changed.Kind == "Host" && s.Status.Host == changed.Name) ||
			(changed.Kind == "IP" && s.Namespace == changed.Namespace && slices.Contains(v1.SiloIPs(s, scheduler.ExclusiveIn(c.classes())), changed.Name))
		if changed.Kind == "VMImage" {
			name, _ := v1.SplitImage(s.Spec.From())
			onIt = s.Spec.VM != nil && s.Namespace == changed.Namespace && name == changed.Name
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
