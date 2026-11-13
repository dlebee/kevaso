// Package moves decides where a silo can go and how a move happens (design §0.3). Pure.
//
// Storage decides what's possible: a silo moves with its data only if every disk and volume it
// keeps is on a class that can attach elsewhere (zone, region, global). The silo decides what's
// wanted: onHostLoss (Wait, Recreate, Move) for when its host is lost, and `kvo move` for a person.
// Either way two copies never run: a move from a live host waits for that host to stop the silo
// and let go of its volumes (status.movingFrom); a move from a lost host waits for fencing, and a
// person's move from a lost host needs --confirm-fenced.
package moves

import (
	"errors"
	"fmt"
	"slices"
	"sort"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/sdk/kplugin"
)

// Movability is what a silo's storage allows.
type Movability struct {
	WithData bool   // every disk and volume it keeps can attach elsewhere
	Scope    string // the narrowest topology among them: host | zone | region | global
	Pinned   string // why it can't move with its data ("" when it can)
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

// CheckPolicy is admission's rule: Move needs every disk movable, and Recreate never leaves an
// important volume behind.
func CheckPolicy(s *v1.Silo, m Movability) error {
	switch s.Policy() {
	case v1.OnHostLossMove:
		if !m.WithData {
			return fmt.Errorf("onHostLoss: Move needs every disk and volume on a movable storage class: %s (use Wait, or Recreate if its image is enough)", m.Pinned)
		}
	case v1.OnHostLossRecreate:
		for _, v := range s.Spec.Volumes {
			t := v.Class
			if v.Important && (t == "" || t == v1.VolumeLocal) {
				return fmt.Errorf("onHostLoss: Recreate would leave important volume %s behind (it's local): use Wait, or put it on a movable class", v.Name)
			}
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
	st.Host, st.Address, st.Phase = p.To, "", "Scheduled"
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
	return st, true
}

// ForceRelease reports whether a volume still marked mounted on a lost host can be detached
// anyway: the host is lost and the silo isn't waiting on that host's handoff (it was fenced).
func ForceRelease(s *v1.Silo, vs v1.VolumeStatus, attachedLost bool) bool {
	return vs.Mounted && attachedLost && vs.AttachedTo != s.Status.Host && s.Status.MovingFrom != vs.AttachedTo
}
