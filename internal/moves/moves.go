// Package moves decides where a silo can go and how a move happens (design §0.3). Pure.
//
// Storage decides what's possible: a silo moves with its data only if every disk and volume it
// keeps is on a class that can attach elsewhere (zone, region, global). A volume is always kept
// data: a Recreate, which leaves the old host's local disks behind, is refused while the silo has
// a host-local volume. The silo decides what's
// wanted: onHostLoss (Wait, Recreate, Move) for when its host is lost, and `kvo move` for a person.
// Either way two copies never run: a move from a live host waits for that host to stop the silo
// and let go of its volumes (status.movingFrom); a move from a lost host waits for fencing, and a
// person's move from a lost host needs --confirm-fenced.
package moves

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/sdk/kplugin"
)

// Movability is what a silo's storage allows.
type Movability struct {
	WithData bool   // every disk and volume it keeps can attach elsewhere
	Scope    string // the narrowest topology among them: host | zone | region | global
	Pinned   string // why it can't move with its data ("" when it can)
	// Local are the host-local volumes (class local, or a plugin class bound to its host): a
	// fresh copy elsewhere (Recreate) would leave them behind.
	Local []string
}

// containerRuntime: the container's own files aren't kept (volumes are), so its root isn't data.
func containerRuntime(rt string) bool {
	return rt == "docker" || rt == "podman" || rt == "openshell-container"
}

var rank = map[string]int{kplugin.TopologyHost: 0, kplugin.TopologyZone: 1, kplugin.TopologyRegion: 2, kplugin.TopologyGlobal: 3}

func topologyOf(class string, classes map[string]scheduler.Class) (string, error) {
	if class == "" || class == v1.VolumeLocal {
		return kplugin.TopologyHost, nil
	}
	c, ok := classes[class]
	if !ok {
		return "", fmt.Errorf("storage class %s: no plugin serves it", class)
	}
	if _, known := rank[c.Topology]; !known {
		return kplugin.TopologyHost, nil // a class that doesn't say is treated as host-bound
	}
	return c.Topology, nil
}

// Of works out a silo's movability from its classes (the plugins' storage classes).
func Of(s *v1.Silo, classes map[string]scheduler.Class) Movability {
	m := Movability{WithData: true, Scope: kplugin.TopologyGlobal}
	narrow := func(what, class string) {
		t, err := topologyOf(class, classes)
		if err != nil {
			m.WithData, m.Scope = false, kplugin.TopologyHost
			if m.Pinned == "" {
				m.Pinned = what + ": " + err.Error()
			}
			return
		}
		if rank[t] < rank[m.Scope] {
			m.Scope = t
		}
		if t == kplugin.TopologyHost && m.Pinned == "" {
			cl := class
			if cl == "" {
				cl = v1.VolumeLocal
			}
			where := ""
			if s.Status.Host != "" {
				where = " on " + s.Status.Host
			}
			m.WithData, m.Pinned = false, fmt.Sprintf("%s uses %s%s: not movable", what, cl, where)
		}
	}
	if !containerRuntime(s.Spec.Runtime) {
		narrow("disk root", s.Spec.Disk.Class)
	}
	vols := append([]v1.Volume(nil), s.Spec.Volumes...)
	sort.Slice(vols, func(i, j int) bool { return vols[i].Name < vols[j].Name })
	for _, v := range vols {
		if t, err := topologyOf(v.Class, classes); err == nil && t == kplugin.TopologyHost {
			m.Local = append(m.Local, v.Name)
		}
		narrow("volume "+v.Name, v.Class)
	}
	return m
}

// Summary is the MOVABLE column: where the silo could go.
func Summary(s *v1.Silo, m Movability) string {
	region := ""
	for _, v := range s.Status.Volumes {
		if v.Region != "" {
			region = v.Region
		}
	}
	switch {
	case m.WithData && m.Scope == kplugin.TopologyGlobal:
		return "Anywhere"
	case m.WithData && region != "":
		return "Region (" + region + ")"
	case m.WithData:
		return "Region"
	case s.Policy() == v1.OnHostLossRecreate:
		return "Recreate"
	case s.Status.Host != "":
		return "Pinned (" + s.Status.Host + ")"
	}
	return "Pinned"
}

// CheckPolicy is admission's rule: Move needs every disk movable, and Recreate never leaves a
// volume behind.
func CheckPolicy(s *v1.Silo, m Movability) error {
	switch s.Policy() {
	case v1.OnHostLossMove:
		if !m.WithData {
			return fmt.Errorf("onHostLoss: Move needs every disk and volume on a movable storage class: %s (use Wait, or Recreate if its image is enough)", m.Pinned)
		}
	case v1.OnHostLossRecreate:
		if len(m.Local) > 0 {
			what := "volume " + m.Local[0]
			if len(m.Local) > 1 {
				what = "volumes " + strings.Join(m.Local, ", ")
			}
			return fmt.Errorf("onHostLoss: Recreate would leave %s behind on its host (volumes are kept data): keep disposable data (a cache, scratch space) on the silo's own disk instead, put the volume on a class that travels (e.g. juicefs, linode-block), or use Wait", what)
		}
	}
	return nil
}

// Request is a person's move (`kvo move silo NAME --to HOST`).
type Request struct {
	To            string `json:"to"`
	Recreate      bool   `json:"recreate,omitempty"`      // a fresh copy from the image, not the data
	ConfirmFenced bool   `json:"confirmFenced,omitempty"` // the old copy is provably stopped
	// Insist: move although the host just claimed its start of the silo (CheckFenced), which says
	// it is alive. Only for a person who knows better.
	Insist bool `json:"insist,omitempty"`
	// HostDeleted is set by the server when the Host named by status.host is gone. That delete
	// confirmed that copy is off. It does not confirm a lost status.movingFrom, and a client
	// cannot set it.
	HostDeleted bool `json:"-"`
}

// Plan is how a move goes.
type Plan struct {
	From, To string
	WithData bool
	// Handoff: the old host is up, so it stops the silo and lets go first (status.movingFrom).
	Handoff bool
}

// Errors a move can be refused with.
var (
	ErrNotPlaced   = errors.New("the silo isn't on a host yet: nothing to move")
	ErrSameHost    = errors.New("the silo is already there")
	ErrNotMovable  = errors.New("can't move with its data")
	ErrNoRecreate  = errors.New("--recreate needs onHostLoss: Recreate (it discards the silo's own disk)")
	ErrNeedsFenced = errors.New("its host is lost: move it only once the old copy is provably stopped (host powered off, or force-stopped through the provider), then add --confirm-fenced")
	ErrMoving      = errors.New("a move is already under way")
)

// PlanMove decides a person's move: with its data, or (--recreate) a fresh copy from its image. A
// container silo never moves with its data (its own files are never kept): only --recreate.
// fromLost: the silo's current host is lost (no heartbeat);
// sourceLost: so is the host a handoff under way is waiting for (status.movingFrom). fits is why
// the target can't take it ("" when it can), from the scheduler.
//
// A handoff under way is refused, unless its source is lost and the person confirms it is fenced
// (K-013): that host never let go and never will, so the handoff ends here, to the same
// destination (which never started it) or to another one. HostDeleted confirms status.host
// only, when that Host object is gone; it does not confirm movingFrom.
func PlanMove(s *v1.Silo, m Movability, r Request, fromLost, sourceLost bool, fits string) (Plan, error) {
	p := Plan{From: s.Status.Host, To: r.To}
	ending := false
	switch {
	case s.Status.Host == "":
		return p, ErrNotPlaced
	case s.Status.MovingFrom != "" && sourceLost && !r.ConfirmFenced:
		return p, fmt.Errorf("%w (from %s, which is lost): %w", ErrMoving, s.Status.MovingFrom, ErrNeedsFenced)
	case s.Status.MovingFrom != "" && !sourceLost:
		return p, fmt.Errorf("%w (from %s)", ErrMoving, s.Status.MovingFrom)
	case s.Status.MovingFrom != "":
		ending = true
	case r.To == s.Status.Host:
		return p, ErrSameHost
	}
	if r.Recreate {
		if s.Policy() != v1.OnHostLossRecreate {
			return p, ErrNoRecreate
		}
		if err := CheckPolicy(s, m); err != nil {
			return p, err
		}
	} else {
		if !m.WithData {
			return p, fmt.Errorf("%w: %s; a fresh copy needs onHostLoss: Recreate and --recreate", ErrNotMovable, m.Pinned)
		}
		if containerRuntime(s.Spec.Runtime) && !ending {
			// A container's own files are never kept (only its volumes travel): a plain move would
			// start it fresh, init steps not run again. Said as a microVM's local disk is.
			return p, fmt.Errorf("%w: its root (a %s container's own files) is never kept: not movable; a fresh copy needs onHostLoss: Recreate and --recreate", ErrNotMovable, s.Spec.Runtime)
		}
		p.WithData = true
	}
	if fromLost && !r.ConfirmFenced && !r.HostDeleted {
		return p, ErrNeedsFenced
	}
	if fits != "" {
		return p, fmt.Errorf("%s can't take it: %s", r.To, fits)
	}
	if ending && r.To == s.Status.Host {
		p.From = s.Status.MovingFrom // the destination stays; only the lost source is let off
		return p, nil
	}
	p.Handoff = !fromLost
	return p, nil
}

// Apply is the status after a planned move: placed on the target, the old host (if up) told to
// let go first. A recreate starts from the image.
func Apply(st v1.SiloStatus, p Plan) v1.SiloStatus {
	st.Host, st.SiloIP, st.Phase = p.To, "", "Scheduled"
	st.MovingFrom = ""
	if p.Handoff {
		st.MovingFrom = p.From
	}
	if !p.WithData {
		st.Init = nil
		if st.Image != nil {
			img := *st.Image
			img.Running, img.Reset = "", ""
			st.Image = &img
		}
	}
	st.Conditions = withoutHostDeleted(st.Conditions) // a move is the way off a deleted host
	return st
}

// HandingOff reports a handoff under way: the silo waits for another host than its own to let
// go. (movingFrom naming its own host is no handoff: that host may start it, MayStart.)
func HandingOff(st v1.SiloStatus) bool { return st.MovingFrom != "" && st.MovingFrom != st.Host }

// Begin is the check before a handoff starts (kvo move, kvoadm host drain): not while one is
// under way (K-070). Whoever starts one writes at the version it checked (client.StartHandoff),
// so a handoff that begins in between makes the write conflict instead of being overwritten.
func Begin(st v1.SiloStatus) error {
	if HandingOff(st) {
		return fmt.Errorf("%w (from %s, which hasn't let go)", ErrMoving, st.MovingFrom)
	}
	return nil
}

// Replaces judges a write of a silo's status by anyone but the host it is moving from (whose
// writes HostWrite judges) and the move handler's confirmed-fenced end of a handoff (PlanMove):
// while a handoff from S is under way, movingFrom stays S, unless the silo is back on S (nothing
// to hand off). Dropping or replacing it would let another host start the silo while S still runs
// it (K-070). nil: allowed.
func Replaces(old, next v1.SiloStatus) error {
	if !HandingOff(old) || next.MovingFrom == old.MovingFrom {
		return nil
	}
	if next.MovingFrom == "" && next.Host == old.MovingFrom {
		return nil
	}
	return fmt.Errorf("%w (from %s): only %s can say it has let go of this silo", ErrMoving, old.MovingFrom, old.MovingFrom)
}

// MayStart reports whether the silo's (new) host may start it: not while another host still
// has to let go of it.
func MayStart(s *v1.Silo, host string) bool {
	if StuckOnDeletedHost(s.Status, host) {
		return false // the host was deleted: this name coming back does not start the silo
	}
	return s.Status.Host == host && (s.Status.MovingFrom == "" || s.Status.MovingFrom == host)
}

// LetGo is the status once the old host has unmounted the volumes attached to it, still handing
// off: the one other write a host the silo is moving from may make.
func LetGo(st v1.SiloStatus, host string) (v1.SiloStatus, bool) {
	if st.MovingFrom != host || st.Host == host {
		return st, false
	}
	st.Volumes = slices.Clone(st.Volumes)
	for i := range st.Volumes {
		if st.Volumes[i].AttachedTo == host {
			st.Volumes[i].Mounted = false
		}
	}
	return st, true
}

// Released is the status once the old host has stopped the silo and unmounted its volumes.
func Released(st v1.SiloStatus, host string) (v1.SiloStatus, bool) {
	st, ok := LetGo(st, host)
	if !ok {
		return st, false
	}
	st.MovingFrom = ""
	if len(st.Volumes) > 0 {
		vols := make([]v1.VolumeStatus, len(st.Volumes))
		copy(vols, st.Volumes)
		for i := range vols {
			if vols[i].AttachedTo == host {
				vols[i].Mounted = false
			}
		}
		st.Volumes = vols
	}
	return st, true
}

// ForceRelease reports whether a volume still marked mounted on a lost host can be detached
// anyway: the host is lost and the silo isn't waiting on that host's handoff (it was fenced).
func ForceRelease(s *v1.Silo, vs v1.VolumeStatus, attachedLost bool) bool {
	return vs.Mounted && attachedLost && vs.AttachedTo != s.Status.Host && s.Status.MovingFrom != vs.AttachedTo
}

// ErrHostWrite is why a host's write of a silo's status is refused (a 403).
var ErrHostWrite = errors.New("forbidden")

// HostWrite judges a host's write of a silo's status: old as stored, next as written (a stale
// write, from an older revision, is refused before this as a conflict). nil: allowed.
//
// A host writes only the status of a silo placed on it, and never where it is placed (host,
// movingFrom). Per volume, the mounted flag is the host's whose the volume is (attachedTo: the
// host it's attached to, or for a mount-reach class the one it's to be mounted on): only that
// host may change it, so the control plane never detaches a volume a host still has mounted
// because another host said it wasn't. Which volumes there are and where they're attached is
// the control plane's. During a handoff the old host may only unmount its volumes (LetGo) and
// then let go (Released); the new host may only set mounted on volumes attached to itself.
func HostWrite(old, next v1.SiloStatus, host string) error {
	if old.MovingFrom == host && old.Host != host {
		for _, step := range []func(v1.SiloStatus, string) (v1.SiloStatus, bool){LetGo, Released} {
			if want, ok := step(old, host); ok && reflect.DeepEqual(want, next) {
				return nil
			}
		}
		return fmt.Errorf("%w: %s is handing this silo off: it may only unmount its volumes and let go", ErrHostWrite, host)
	}
	if old.Host != host {
		return fmt.Errorf("%w: %s may only write the status of silos placed on it", ErrHostWrite, host)
	}
	if next.Host != old.Host {
		return fmt.Errorf("%w: %s may not place a silo (status.host)", ErrHostWrite, host)
	}
	if next.MovingFrom != old.MovingFrom {
		return fmt.Errorf("%w: only %s can say it has let go of this silo", ErrHostWrite, old.MovingFrom)
	}
	if len(next.Volumes) != len(old.Volumes) {
		return fmt.Errorf("%w: which volumes a silo has is the control plane's to write", ErrHostWrite)
	}
	for i, o := range old.Volumes {
		n := next.Volumes[i]
		switch {
		case n.Name != o.Name || n.AttachedTo != o.AttachedTo:
			return fmt.Errorf("%w: volume %s: where it is attached is the control plane's to write", ErrHostWrite, o.Name)
		case !sameButMounted(o, n):
			// K-037: the handle, class, region, device, size and message are the control plane's
			// (its volumes controller acts on them: attach, detach, delete; the agent formats and
			// mounts the device). A host that rewrote them would point those at another volume.
			return fmt.Errorf("%w: volume %s: only whether it is mounted is the host's to write", ErrHostWrite, o.Name)
		case n.Mounted != o.Mounted && o.AttachedTo != host:
			to := o.AttachedTo
			if to == "" {
				to = "no host"
			}
			return fmt.Errorf("%w: volume %s is attached to %s: only that host says whether it is mounted", ErrHostWrite, o.Name, to)
		}
	}
	if err := hostDeletedWrite(old, next); err != nil {
		return err
	}
	if err := armedWrite(old, next, host); err != nil {
		return err
	}
	if err := stoppedWrite(old, next, host); err != nil {
		return err
	}
	return claimWrite(old, next, host)
}

// hostDeletedWrite refuses a host's add, drop or change of Unschedulable/HostDeleted. The
// control plane sets it when the host is gone, and a move clears it. A host that writes the
// silo back as it read it leaves the condition as it stood.
func hostDeletedWrite(old, next v1.SiloStatus) error {
	o, okO := hostDeletedSeen(old)
	n, okN := hostDeletedSeen(next)
	if okO == okN && (!okO || o == n) {
		return nil
	}
	return fmt.Errorf("%w: Unschedulable/HostDeleted is the control plane's to write", ErrHostWrite)
}

func hostDeletedSeen(st v1.SiloStatus) (meta.Condition, bool) {
	c := meta.FindCondition(st.Conditions, CondUnschedulable)
	if c == nil || c.Reason != ReasonHostDeleted {
		return meta.Condition{}, false
	}
	return *c, true
}

// armedWrite judges a host's write of a silo's FenceArmed condition (K-082): a new or changed one
// must be in that host's own name (fence.ArmedCondition's message starts with the host). The
// control plane restarts an opted-in silo elsewhere only while its host armed it; and a handoff
// whose source is gone ends by itself only while the source's armed fence stands (K-119), so the
// destination must not write one in the source's name.
func armedWrite(old, next v1.SiloStatus, host string) error {
	n := meta.FindCondition(next.Conditions, fence.ConditionArmed)
	if n == nil || n.Status != meta.ConditionTrue {
		return nil
	}
	if o := meta.FindCondition(old.Conditions, fence.ConditionArmed); o != nil && *o == *n {
		return nil // as it stood: not this write's
	}
	if !strings.HasPrefix(n.Message, host+" stops this silo after ") {
		return fmt.Errorf("%w: %s may arm its fence only in its own name (condition %s: %q)", ErrHostWrite, host, fence.ConditionArmed, n.Message)
	}
	return nil
}

// stoppedWrite judges a host's write of a silo's FenceStopped condition: a new or changed one must
// be in that host's own name (fence.StoppedCondition's message starts with the host). The control
// plane restarts an opted-in silo elsewhere only once its host reported this, so no other host may
// report it for it.
func stoppedWrite(old, next v1.SiloStatus, host string) error {
	n := meta.FindCondition(next.Conditions, fence.ConditionStopped)
	if n == nil || n.Status != meta.ConditionTrue {
		return nil
	}
	if o := meta.FindCondition(old.Conditions, fence.ConditionStopped); o != nil && *o == *n {
		return nil // as it stood: not this write's
	}
	if !strings.HasPrefix(n.Message, fence.StoppedPrefix(host)+" ") {
		return fmt.Errorf("%w: %s may report its fence stopped a silo only in its own name (condition %s: %q)", ErrHostWrite, host, fence.ConditionStopped, n.Message)
	}
	return nil
}

// HostConditions are the silo conditions only the silo's own host writes (K-082): its start claim,
// its armed fence, and its report that its fence stopped the silo. HostWrite judges that host's
// writes of them.
var HostConditions = []string{CondStartClaim, fence.ConditionArmed, fence.ConditionStopped}

// KeepHostConditions puts back, in a status write by anyone but a host (a person, a tool, a
// controller), the HostConditions as stored: they are never added, changed or removed that way. A
// write that places the silo elsewhere (status.host changes) may drop them, as the old placement's;
// still never add or change them. It returns the conditions it put back.
func KeepHostConditions(old v1.SiloStatus, next *v1.SiloStatus) []string {
	var kept []string
	for _, typ := range HostConditions {
		o, n := meta.FindCondition(old.Conditions, typ), meta.FindCondition(next.Conditions, typ)
		switch {
		case o == nil && n == nil, o != nil && n != nil && *o == *n:
			continue
		case n == nil && next.Host != old.Host:
			continue // dropped with the old placement
		}
		conds := make([]meta.Condition, 0, len(next.Conditions)+1)
		for _, c := range next.Conditions {
			if c.Type != typ {
				conds = append(conds, c)
			}
		}
		if o != nil {
			conds = append(conds, *o)
		}
		next.Conditions = conds
		kept = append(kept, typ)
	}
	return kept
}

// sameButMounted reports whether two volume statuses differ at most in mounted.
func sameButMounted(a, b v1.VolumeStatus) bool {
	a.Mounted = b.Mounted
	return a == b
}

// CondStartClaim is the silo condition a host writes right before it starts the silo, against
// the version it read, and starts only if that write applied (K-015; internal/agent's
// ConditionStartClaim). Its message names the host: "starting on HOST at TIME".
const CondStartClaim = "StartClaim"

// StartClaimHost is the host a start claim's message names (false: it names none).
func StartClaimHost(message string) (string, bool) {
	rest, found := strings.CutPrefix(message, "starting on ")
	if !found {
		return "", false
	}
	h, _, found := strings.Cut(rest, " at ")
	return h, found && h != ""
}

// claimWrite judges a host's write of a silo's start claim: a new or changed claim must be in
// that host's own name (the control plane counts a claim as a contact of the host it names).
func claimWrite(old, next v1.SiloStatus, host string) error {
	n := meta.FindCondition(next.Conditions, CondStartClaim)
	if n == nil || n.Status != meta.ConditionTrue {
		return nil
	}
	if o := meta.FindCondition(old.Conditions, CondStartClaim); o != nil && *o == *n {
		return nil // as it stood: not this write's
	}
	if h, ok := StartClaimHost(n.Message); !ok || h != host {
		return fmt.Errorf("%w: %s may claim a start only in its own name (condition %s: %q)", ErrHostWrite, host, CondStartClaim, n.Message)
	}
	return nil
}

// StartClaimFresh is how long a start claim stands as evidence that its host is alive and may be
// starting the silo (internal/agent's StartClaimFresh; the silo controller's too).
const StartClaimFresh = 30 * time.Second

// ErrClaimStands: a confirm-fenced move while the host just claimed its start (CheckFenced).
var ErrClaimStands = errors.New("its host just claimed its start of this silo")

// StampClaim sets a new or changed start claim's time to now, when the API received it: the
// claim's age is judged by the control plane's clock (CheckFenced), never the agent's. A claim
// sent again as it stood keeps its time.
func StampClaim(old v1.SiloStatus, next *v1.SiloStatus, now time.Time) {
	n := meta.FindCondition(next.Conditions, CondStartClaim)
	if n == nil {
		return
	}
	if o := meta.FindCondition(old.Conditions, CondStartClaim); o != nil && o.Status == n.Status && o.Reason == n.Reason &&
		o.Message == n.Message && o.ObservedGeneration == n.ObservedGeneration {
		n.LastTransitionTime = o.LastTransitionTime
		return
	}
	n.LastTransitionTime = now.UTC()
}

// CheckFenced judges a person's confirm-fenced move of a silo whose host is lost (by its stamps):
// a start claim of that host received less than StartClaimFresh ago says the host is alive, and
// may be inside Start (review of the start claim, item 1). Refused then, saying when, unless the
// person insists. now: the API server's clock, the one StampClaim stamped with.
func CheckFenced(s *v1.Silo, r Request, now time.Time) error {
	if !r.ConfirmFenced || r.Insist {
		return nil
	}
	c := meta.FindCondition(s.Status.Conditions, CondStartClaim)
	if c == nil || c.Status != meta.ConditionTrue {
		return nil
	}
	if h, ok := StartClaimHost(c.Message); !ok || h != s.Status.Host {
		return nil // not this placement's
	}
	age := now.Sub(c.LastTransitionTime)
	if age >= StartClaimFresh {
		return nil
	}
	return fmt.Errorf("%w: %s claimed its start %s ago, so it answered then and may be starting it now: it is not provably stopped. Wait %s, or add --insist if you know the old copy is off",
		ErrClaimStands, s.Status.Host, max(age, 0).Round(time.Second), (StartClaimFresh - age).Round(time.Second))
}
