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
	"kevaso.com/core/internal/fence"
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

// CondFenceArmed is the silo condition its host's agent writes (host lane) when the host's fence
// will stop the silo without the control plane: fence.ArmedCondition and fence.Armed.
const CondFenceArmed = fence.ConditionArmed

// StopMargin is what the control plane waits beyond a silo's `after` before starting another
// copy of an onControlPlaneLoss: Stop silo whose host went silent. Both sides count durations on
// their own clocks, never comparing them (K-014), from the same heartbeat: the agent from when it
// sent it, the control plane from when it saw it, which is never earlier. So the margin covers
// only what happens after the agent's count runs out:
//
//   - the fence's own reaction: it reads its record every fence.CheckEvery (1s) and kills within
//     fence.KillWithin (5s);
//   - the control plane noticing late is on the safe side, and so is a new leader (it counts from
//     its own start);
//   - the two clocks' rates: 1000 ppm of `after` (NTP keeps rates within 500 ppm; a free-running
//     crystal is around 50 ppm);
//   - and 9s of slack on top, so it is never under 15s.
//
// The result is rounded up to a whole second.
func StopMargin(after time.Duration) time.Duration {
	m := 15*time.Second + after/1000
	return (m + time.Second - 1).Truncate(time.Second)
}

// fenceArmed: the host's agent said its fence stops this silo, there, for this very spec.
func fenceArmed(s *v1.Silo) bool { return fence.Armed(s) }

// CondStartClaim is the condition a host writes on a silo right before it starts it: its start
// claim (K-015; internal/agent's ConditionStartClaim, the host lane's), written against the exact
// version it read, so it applies only if nothing changed the silo since, and the host starts the
// silo only if it applied. Its message names the host ("starting on HOST at …").
const CondStartClaim = moves.CondStartClaim

// StartClaimFresh is how long a start claim of a silo's host keeps the silo there, whatever the
// control plane's silence count says (internal/agent's StartClaimFresh). It is counted from when
// this control plane first saw the claim, on its own clock (Env.StartClaimAge), never from the
// claim's timestamp, which is the agent's clock.
const StartClaimFresh = 30 * time.Second

// StartClaimOf returns the start claim s carries: the host that wrote it ("" when its message
// doesn't say) and the claim as written, as an id (any change to the claim is another id). ok
// false: no claim stands.
func StartClaimOf(s *v1.Silo) (host, id string, ok bool) {
	c := meta.FindCondition(s.Status.Conditions, CondStartClaim)
	if c == nil || c.Status != meta.ConditionTrue {
		return "", "", false
	}
	host, _ = moves.StartClaimHost(c.Message)
	id = strings.Join([]string{s.UID, c.Reason, c.Message, c.LastTransitionTime.UTC().Format(time.RFC3339Nano), strconv.FormatInt(c.ObservedGeneration, 10)}, "|")
	return host, id, true
}

// ownClaim reports whether s carries a start claim naming its own host, the only kind that
// counts (as a contact of that host, and as fresh).
func ownClaim(s *v1.Silo) bool {
	host, _, ok := StartClaimOf(s)
	return ok && host != "" && host == s.Status.Host
}

// ignoredClaim says why a standing claim of s doesn't count ("" when none, or it does).
func ignoredClaim(s *v1.Silo) string {
	host, _, ok := StartClaimOf(s)
	switch {
	case !ok || ownClaim(s):
		return ""
	case host == "":
		return fmt.Sprintf(" (a start claim that names no host is ignored: only %s's own counts)", s.Status.Host)
	default:
		return fmt.Sprintf(" (a start claim naming %s is ignored: only %s's own counts)", host, s.Status.Host)
	}
}

// claimKey is what the control plane's memory of a silo's start claim is kept under.
func claimKey(namespace, name string) string { return namespace + "/" + name }

// freshClaim reports whether a start claim of the silo's current host stands (K-015): the host
// is about to start it, or just did, so it is in contact and the silo is not placed elsewhere.
// Only a claim naming the silo's own host counts: a worker may write any condition on a silo
// placed on it, so one naming another host, or none, stands for nothing (ignoredClaim says so).
// left: how long it still stands by this control plane's count (0: unknown, Env.StartClaimAge
// nil, so it stands as long as it is there).
func freshClaim(s *v1.Silo, env scheduler.Env) (fresh bool, age, left time.Duration) {
	if !ownClaim(s) {
		return false, 0, 0
	}
	if env.StartClaimAge == nil {
		return true, 0, 0
	}
	if age = env.StartClaimAge(s); age < StartClaimFresh {
		return true, age, StartClaimFresh - age
	}
	return false, age, 0
}

// restartsItself says whether a silo on a silent host may be started elsewhere now, without a
// person (brainstorm §0.7: only onControlPlaneLoss: Stop), and why; or, when it may not but is
// opted in, why not yet.
func restartsItself(s *v1.Silo, env scheduler.Env) (bool, string) {
	stops, after := s.StopsOnControlPlaneLoss()
	if !stops {
		return false, ""
	}
	host := s.Status.Host
	switch {
	case s.Policy() == v1.OnHostLossWait:
		return false, fmt.Sprintf("It stops itself after %s without the control plane (onControlPlaneLoss: Stop), and onHostLoss: Wait keeps it on %s", after, host)
	case s.Policy() == v1.OnHostLossMove && !moves.Of(s, env.Classes).WithData:
		return false, ""
	case !fenceArmed(s):
		return false, fmt.Sprintf("onControlPlaneLoss: Stop, but %s never confirmed its fence stops this silo (condition %s for generation %d): not started elsewhere", host, CondFenceArmed, s.Generation)
	case env.Silence == nil:
		return false, ""
	}
	if fresh, age, left := freshClaim(s, env); fresh {
		// K-015: the host wrote its start claim (only one of that and a restart elsewhere can
		// apply; this one did): it is in contact, and the silo may be starting there.
		standing := "it stands while it is there"
		if env.StartClaimAge != nil {
			standing = fmt.Sprintf("seen %s ago by the control plane, it stands %s more", age.Round(time.Second), left.Round(time.Second))
		}
		return false, fmt.Sprintf("%s claimed its start of this silo (condition %s; %s): it is in contact, so the silo is not started elsewhere",
			host, CondStartClaim, standing)
	}
	wait := after + StopMargin(after)
	silent := env.Silence(host)
	if silent < wait {
		return false, fmt.Sprintf("It stops itself after %s without the control plane (onControlPlaneLoss: Stop): started elsewhere once the control plane has heard nothing from %s for %s (%s margin); %s so far%s",
			after, host, wait, StopMargin(after), silent.Round(time.Second), ignoredClaim(s))
	}
	how := "recreated from its image"
	if s.Policy() == v1.OnHostLossMove {
		how = "moved with its data"
	}
	return true, fmt.Sprintf("%s silent for %s by the control plane's count; this silo stops itself after %s without it (onControlPlaneLoss: Stop), %s margin: %s elsewhere (onHostLoss: %s)%s",
		host, silent.Round(time.Second), after, StopMargin(after), how, s.Policy(), ignoredClaim(s))
}

// stopWait is when to look again at an opted-in silo waiting for its margin (0: only on changes).
func stopWait(s *v1.Silo, env scheduler.Env) time.Duration {
	stops, after := s.StopsOnControlPlaneLoss()
	if !stops || s.Policy() == v1.OnHostLossWait || !fenceArmed(s) || env.Silence == nil {
		return 0
	}
	_, _, left := freshClaim(s, env)
	return max(after+StopMargin(after)-env.Silence(s.Status.Host), left, 0)
}

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
		if fresh, _, _ := freshClaim(s, env); st.MovingFrom != "" && st.MovingFrom != st.Host && !fresh {
			// The silent host is the destination of a handoff its source hasn't finished: it never
			// started the silo (moves.MayStart: not before the source lets go), so no copy runs
			// there and another destination is safe. The handoff stays: the next host waits for
			// the source as the silent one did (K-005). (A host claims its start only once it may
			// start, K-015, so a destination's claim can't stand here; were one there anyway, the
			// silo is left to the rule below.)
			cond.Status, cond.Reason = meta.ConditionFalse, "NewDestination"
			cond.Message = fmt.Sprintf("%s, where it was moving, is unreachable; it never started there (%s hasn't let go): placing it elsewhere", st.Host, st.MovingFrom)
			meta.SetCondition(&st.Conditions, cond, now)
			st.Host, st.SiloIP = "", ""
			// …and it's scheduled right away, below.
		} else if ok, why := restartsItself(s, env); ok {
			// The one opt-in (brainstorm §0.7): the silo stops itself when its host loses the
			// control plane, its host's fence said so for this spec, and this control plane has
			// heard nothing from that host for its `after` plus StopMargin, on its own clock.
			// So the old copy is stopped: onHostLoss says how it goes on elsewhere.
			cond.Status, cond.Reason, cond.Message = meta.ConditionFalse, "RestartedElsewhere", why
			meta.SetCondition(&st.Conditions, cond, now)
			if s.Policy() == v1.OnHostLossMove {
				meta.SetCondition(&st.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionFalse, Reason: "Moving",
					Message: "moving with its data after losing " + st.Host, ObservedGeneration: s.Generation}, now)
				if st.MovingFrom == st.Host {
					st.MovingFrom = ""
				}
				st.Host, st.SiloIP = "", ""
			} else { // Recreate
				meta.SetCondition(&st.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionFalse, Reason: "Recreating",
					Message: "recreating after losing " + st.Host, ObservedGeneration: s.Generation}, now)
				st.Host, st.SiloIP, st.Init = "", "", nil
				if st.Image != nil { // a fresh instance from the image
					st.Image.Running, st.Image.Reset = "", ""
				}
			}
			// …and it's scheduled right away, below.
		} else {
			// Its host is silent (brainstorm §0.7). Kevaso can't tell a dead host from a cut-off
			// one, and a cut-off host still runs the silo: so nothing is started elsewhere. A
			// person who knows the old copy is off moves it (kvo move … --confirm-fenced);
			// onHostLoss says how.
			cond.Status, cond.Reason = meta.ConditionTrue, "Waiting"
			cond.Message = UnreachableMessage(s, since, moves.Of(s, env.Classes))
			if why != "" {
				cond.Message += ". " + why
			}
			st.Phase = PhaseUnknown
			changed := meta.SetCondition(&st.Conditions, cond, now)
			return st, changed || imageChanged || s.Status.Phase != st.Phase, stopWait(s, env), nil
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
	if st.Host != s.Status.Host {
		// A claim is of the placement it was written for: placed elsewhere, it is dropped, so a
		// new leader (who would count it as just seen) never finds it standing on the new host.
		st.Conditions = dropCondition(st.Conditions, CondStartClaim)
	}
	return st, changed, again, nil
}

func dropCondition(conds []meta.Condition, typ string) []meta.Condition {
	out := conds[:0:0]
	for _, c := range conds {
		if c.Type != typ {
			out = append(out, c)
		}
	}
	return out
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
	// Contacts are how long each host has been silent by this control plane's clock (the host
	// controller keeps them). Nil: no onControlPlaneLoss: Stop silo is ever restarted by itself.
	Contacts *hostctl.Contacts

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
		c.Contacts.ForgetStartClaim(claimKey(k.Namespace, k.Name))
		return engine.Result{}, nil // deleted
	}
	s := o.(*v1.Silo)
	// Its host's start claim, if new to us, is seen now: fresh from now, and a contact (K-015).
	// Only a claim in the name of the host the silo is placed on: one naming another host (any
	// worker may write conditions on a silo placed on it) is no contact of that host.
	if host, id, ok := StartClaimOf(s); ok && ownClaim(s) {
		c.Contacts.SawStartClaim(claimKey(s.Namespace, s.Name), host, id, c.Clock.Now())
	}
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
	if c.Contacts != nil {
		env.Silence = func(host string) time.Duration { return c.Contacts.Silence(host, c.Clock.Now()) }
		env.StartClaimAge = func(x *v1.Silo) time.Duration {
			_, id, _ := StartClaimOf(x)
			return c.Contacts.StartClaimAge(claimKey(x.Namespace, x.Name), id, c.Clock.Now())
		}
	}
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
	// (K-029): one another silo holds there is avoided, and it is decided again. A silo already
	// on its host claims what it has there too, the first time this controller sees it there:
	// a silo put there by another path (kvo move, a write from before claims) holds its ports by
	// the store from then on. Its host ports there are held by another silo only if that path
	// didn't claim them first: it can't be re-placed, so the HostPorts condition says so.
	var heldHere map[scheduler.HostPort]bool
	for attempt := 0; err == nil && c.Claims != nil && st.Host != "" && s.DeletionTimestamp == nil; attempt++ {
		if attempt == 8 {
			return engine.Result{}, errors.New("node or host ports kept being taken; will retry")
		}
		held, cerr := claimPorts(ctx, c.Claims, s, st, &c.mine)
		if cerr != nil {
			return engine.Result{}, cerr
		}
		if held != nil && st.Host == s.Status.Host && len(held.HostPorts) > 0 {
			heldHere, held.HostPorts = held.HostPorts, nil
		}
		if held == nil || len(held.NodePorts) == 0 && len(held.HostPorts) == 0 {
			break
		}
		if env.Claimed == nil {
			env.Claimed = map[string]scheduler.Claimed{}
		}
		env.Claimed[st.Host] = merge(env.Claimed[st.Host], *held)
		st, changed, again, err = DecideIn(s, hosts, silos, now, env)
	}
	if err == nil && c.Claims != nil && st.Host != "" && st.Host == s.Status.Host {
		changed = hostPortsCondition(&st, s, heldHere, now) || changed
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

// ClaimPorts claims, for silo s (as read: its version is the one the status write is
// conditional on), the node ports in st and s's host ports on st.Host, in the same pools and by
// the same rules as the scheduler's placements. Every path that puts a silo on a host takes them
// before its write (K-029): the silo controller, and the API server's move handler. held: what
// another silo holds there (nil: everything is s's); such a placement must not be written.
//
// Claims are let go by being taken over: a claim whose silo is gone, or is no longer on that host
// (placed there or still handing off from it) or no longer has that value, is another's to take.
func ClaimPorts(ctx context.Context, cl *claims.Claims, s *v1.Silo, st v1.SiloStatus) (*scheduler.Claimed, error) {
	return claimPorts(ctx, cl, s, st, nil)
}

// claimPorts is ClaimPorts; mine (nil: none) remembers what this controller claimed, so a value a
// silo already has there is not claimed in the store again on each reconcile.
func claimPorts(ctx context.Context, cl *claims.Claims, s *v1.Silo, st v1.SiloStatus, mine *sync.Map) (*scheduler.Claimed, error) {
	h := claims.Holder{Kind: "Silo", Namespace: s.Namespace, Name: s.Name, UID: s.UID, Version: s.ResourceVersion}
	held := scheduler.Claimed{NodePorts: map[int]bool{}, HostPorts: map[scheduler.HostPort]bool{}}
	there := s.Status.Host == st.Host // what it has now, it has on this host
	take := func(pool, value string, has bool, uses claims.Uses) (bool, error) {
		// A value it already has there, claimed by this controller, is still its own (a claim is
		// only taken over once the stored silo stops having it).
		if mine != nil {
			if u, ok := mine.Load(pool + "/" + value); has && ok && u == h.UID {
				return true, nil
			}
		}
		ok, err := cl.Take(ctx, pool, value, h, uses)
		if ok && mine != nil {
			mine.Store(pool+"/"+value, h.UID)
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

// CondHostPorts says a silo placed on its host by a path that didn't claim (K-029) has host ports
// there that another silo holds: it is not re-placed (it may run there already); a person moves
// one of the two. Written only once that happens, and set back to True when it is over.
const CondHostPorts = "HostPorts"

func hostPortsCondition(st *v1.SiloStatus, s *v1.Silo, held map[scheduler.HostPort]bool, now time.Time) bool {
	cond := meta.Condition{Type: CondHostPorts, ObservedGeneration: s.Generation}
	if len(held) == 0 {
		if c := meta.FindCondition(st.Conditions, CondHostPorts); c == nil || c.Status == meta.ConditionTrue {
			return false
		}
		cond.Status, cond.Reason, cond.Message = meta.ConditionTrue, "Held", "its host ports on "+st.Host+" are its own"
		return meta.SetCondition(&st.Conditions, cond, now)
	}
	var ports []string
	for p := range held {
		ports = append(ports, hostPortValue(p))
	}
	slices.Sort(ports)
	cond.Status, cond.Reason = meta.ConditionFalse, "HeldByAnother"
	cond.Message = fmt.Sprintf("host ports %s on %s are held by another silo (it was put there without claiming them); move one of the two", strings.Join(ports, ", "), st.Host)
	return meta.SetCondition(&st.Conditions, cond, now)
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
