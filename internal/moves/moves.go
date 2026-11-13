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

	v1 "kevaso.com/core/api/v1"
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

// PlanMove decides a person's move. fromLost: the silo's current host is lost (no heartbeat).
// fits is why the target can't take it ("" when it can), from the scheduler.
func PlanMove(s *v1.Silo, m Movability, r Request, fromLost bool, fits string) (Plan, error) {
	p := Plan{From: s.Status.Host, To: r.To}
	switch {
	case s.Status.Host == "":
		return p, ErrNotPlaced
	case r.To == s.Status.Host:
		return p, ErrSameHost
	case s.Status.MovingFrom != "":
		return p, fmt.Errorf("%w (from %s)", ErrMoving, s.Status.MovingFrom)
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
		p.WithData = true
	}
	if fromLost && !r.ConfirmFenced {
		return p, ErrNeedsFenced
	}
	if fits != "" {
		return p, fmt.Errorf("%s can't take it: %s", r.To, fits)
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
	return st
}

// MayStart reports whether the silo's (new) host may start it: not while another host still
// has to let go of it.
func MayStart(s *v1.Silo, host string) bool {
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
		case n.Mounted != o.Mounted && o.AttachedTo != host:
			to := o.AttachedTo
			if to == "" {
				to = "no host"
			}
			return fmt.Errorf("%w: volume %s is attached to %s: only that host says whether it is mounted", ErrHostWrite, o.Name, to)
		}
	}
	return nil
}
