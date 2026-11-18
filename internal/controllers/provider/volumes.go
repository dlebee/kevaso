package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	v1 "kevaso.com/core/api/v1"
	hostctl "kevaso.com/core/internal/controllers/host"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kplugin"
)

// Volumes creates a silo's volumes on a plugin's storage class and attaches them to its host; the
// host's agent formats each once and mounts it. One taken out of the spec is detached once the
// host has unmounted it and kept until the silo is deleted. Deleting the silo detaches it (polled:
// a detach can take minutes, E032) and deletes it.
//
// A mount-reach class (juicefs) attaches nothing: the volume is created once, and status says
// which host should mount it (attachedTo); that host's agent asks the plugin's node side to mount
// it. When the silo moves, the old host unmounts it first, then attachedTo moves on.
type Volumes struct {
	Client  *client.Client
	Silos   *informer.Informer
	Hosts   *informer.Informer
	Plugins *plugins.Registry
	// Records is the store the controller keeps its own record of each volume in (K-037): what
	// it acts on, whatever a silo's status says. Nil: status is trusted (tests only).
	Records store.Store
	// Providers are the hosts' provider details as the plugins said (K-037); nil: their status.
	Providers *Providers
	// Poll is how soon to look again while something is in progress (default 5s).
	Poll time.Duration

	mu        sync.Mutex
	hostsSeen map[string]string
}

// Name implements engine.Controller.
func (c *Volumes) Name() string { return "volumes" }

// Kind implements engine.Controller.
func (c *Volumes) Kind() string { return "Silo" }

func (c *Volumes) poll() time.Duration {
	if c.Poll > 0 {
		return c.Poll
	}
	return 5 * time.Second
}

func hasFinalizer(s *v1.Silo, f string) bool {
	for _, x := range s.Finalizers {
		if x == f {
			return true
		}
	}
	return false
}

// VolumeID is the plugin's stable ID for a silo's volume.
func VolumeID(s *v1.Silo, name string) string { return s.UID + "/" + name }

// LabelLimit is how long kvo-NAMESPACE-SILO-VOLUME may be in a provider's label: 32 characters
// (letters, digits, -) less -UID[:5].
const LabelLimit = 26

// ErrLabelTooLong: a volume's names don't fit a provider's label.
var ErrLabelTooLong = errors.New("too long for a provider's label")

// VolumeLabel is a human label for a volume on the provider's side: kvo-NAMESPACE-SILO-VOLUME,
// then -UID[:5] (at most 32 characters). Names that don't fit are refused, never cut (brainstorm
// §0.8, audit K-035): a cut gave two volumes one label, and a provider that finds volumes by
// label would hand one the other's disk. Admission asks this function too, and refuses first.
func VolumeLabel(s *v1.Silo, name string) (string, error) {
	l := "kvo-" + s.Namespace + "-" + s.Name + "-" + name
	if len(l) > LabelLimit {
		return "", fmt.Errorf("volume %s: %s is %d characters, and a provider's label keeps %d before -UID (not cut: two volumes would share one): shorten the namespace, the silo's or the volume's name by %d: %w",
			name, l, len(l), LabelLimit, len(l)-LabelLimit, ErrLabelTooLong)
	}
	uid := s.UID
	if len(uid) > 5 {
		uid = uid[:5]
	}
	return l + "-" + uid, nil
}

// Reconcile implements engine.Controller.
func (c *Volumes) Reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	o, ok := c.Silos.Get(k.Namespace, k.Name)
	if !ok {
		return engine.Result{}, nil
	}
	s := o.(*v1.Silo)
	// Decide from the silo as it is, not as the cache has it (K-033): a cache that is behind
	// would detach and attach again a volume that has moved since, and is mounted there.
	if len(v1.PluginVolumes(s)) > 0 || len(s.Status.Volumes) > 0 || hasFinalizer(s, FinalizerVolumes) {
		var fresh v1.Silo
		if err := c.Client.Get(ctx, "Silo", k.Namespace, k.Name, &fresh); err != nil {
			return engine.Result{}, client.IgnoreNotFound(err)
		}
		if fresh.UID != s.UID {
			return engine.Result{}, nil
		}
		s = &fresh
	}
	want := map[string]v1.Volume{}
	if s.DeletionTimestamp == nil {
		for _, v := range v1.PluginVolumes(s) {
			want[v.Name] = v
		}
	}
	if len(want) == 0 && len(s.Status.Volumes) == 0 && !c.removalsUnderWay(ctx, s) {
		if hasFinalizer(s, FinalizerVolumes) {
			return engine.Result{}, setFinalizers(ctx, c.Client, s, FinalizerVolumes, "")
		}
		return engine.Result{}, nil
	}
	if len(want) > 0 && !hasFinalizer(s, FinalizerVolumes) {
		return engine.Result{}, setFinalizers(ctx, c.Client, s, "", FinalizerVolumes)
	}
	var host *v1.Host
	if s.Status.Host != "" {
		if ho, ok := c.Hosts.Get("", s.Status.Host); ok {
			host = ho.(*v1.Host)
		}
	}
	// Status entries: one per wanted volume, plus the ones being removed.
	vols := append([]v1.VolumeStatus(nil), s.Status.Volumes...)
	for _, v := range v1.PluginVolumes(s) {
		if _, ok := want[v.Name]; ok && find(vols, v.Name) < 0 {
			vols = append(vols, v1.VolumeStatus{Name: v.Name, Class: v.Class})
		}
	}
	// What the plugin is asked about is what this controller recorded, never what status says
	// (K-037): a worker, or anyone allowed to write silos/status, may have rewritten it.
	var have map[string]store.Object
	untrusted := map[string]bool{}
	pending := map[string]bool{} // removals under way: the records do them, not the status
	var again time.Duration
	var errs []error
	if c.Records != nil {
		var err error
		if have, err = c.records(ctx, s); err != nil {
			return engine.Result{}, err
		}
		// A record whose status entry is gone without being marked removing is put back (a
		// status write lost, or an entry dropped by someone else).
		for name, o := range have {
			if r, derr := decodeRecord(o); derr == nil && !r.Removing && find(vols, name) < 0 {
				r.Message = "put back from the control plane's record"
				vols = append(vols, r.VolumeStatus)
			}
		}
		var w time.Duration
		if pending, w, err = c.removals(ctx, s, have); err != nil {
			errs = append(errs, err)
		}
		again = w
		for i, vs := range vols {
			var rec *store.Object
			if o, ok := have[vs.Name]; ok {
				rec = &o
			}
			_, wanted := want[vs.Name]
			tv, ok, err := trusted(vs, rec, wanted)
			if err != nil {
				return engine.Result{}, fmt.Errorf("volume %s: its record: %w", vs.Name, err)
			}
			vols[i], untrusted[vs.Name] = tv, !ok
		}
	}
	keep := vols[:0]
	var dropping []string // removals to start: dropped from the status first, conditionally
	var letting []string  // taken out of the spec: detach after the status write confirms it
	for _, vs := range vols {
		spec, wanted := want[vs.Name]
		var (
			next v1.VolumeStatus
			done bool
			wait time.Duration
			err  error
		)
		switch {
		case untrusted[vs.Name]:
			next, wait = vs, time.Minute // a person's to sort out; nothing is asked of the plugin
		case wanted && pending[vs.Name]:
			next, wait = v1.VolumeStatus{Name: vs.Name, Class: vs.Class, Message: "waiting for the volume of this name being deleted to be gone"}, c.poll()
		case !wanted && s.DeletionTimestamp == nil: // taken out of the spec: kept until the silo is deleted
			next, wait, err = c.retain(vs)
			if !vs.Mounted && vs.AttachedTo != "" {
				letting = append(letting, vs.Name)
			}
		case !wanted && c.Records != nil && vs.Mounted:
			next, wait = vs, c.poll()
			next.Message = "waiting for " + vs.AttachedTo + " to unmount it"
		case !wanted && c.Records != nil:
			// Unmounted and not wanted, as read: dropped from the status by the write below, which
			// applies only if that is still so (the detach and delete follow from the record).
			done = true
			if unknown(recorded(vs)) {
				dropping = append(dropping, vs.Name)
			}
		case wanted:
			next, wait, err = c.ensure(ctx, s, host, spec, vs)
		default:
			next, done, wait, err = c.remove(ctx, s, vs)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("volume %s: %w", vs.Name, err))
			if next.Message == "" {
				next.Message = err.Error()
			}
		}
		if wait > 0 && (again == 0 || wait < again) {
			again = wait
		}
		if !done {
			keep = append(keep, next)
		}
	}
	if c.Records != nil {
		// Recorded before status says so: a status write that fails leaves a record ahead of it,
		// which the next look puts back on the status.
		if err := c.keepRecords(ctx, s, have, keep); err != nil {
			return engine.Result{}, err
		}
	}
	decided, stale := placesOf(s.Status.Volumes), false
	if err := updateSiloStatus(ctx, c.Client, s, func(cur *v1.Silo) {
		st := &cur.Status
		if placesOf(st.Volumes) != decided {
			stale = true // changed while the plugin was asked: decide again from that
			return
		}
		// A removal applies only on the silo as this write finds it: still not wanted, still
		// unmounted (the write is conditional on that copy's version).
		for _, name := range append(append([]string{}, dropping...), letting...) {
			j := find(st.Volumes, name)
			_, wantedNow := want[name]
			for _, v := range v1.PluginVolumes(cur) {
				wantedNow = wantedNow || (v.Name == name && cur.DeletionTimestamp == nil)
			}
			if wantedNow || (j >= 0 && st.Volumes[j].Mounted) {
				stale = true
				return
			}
		}
		// The agent owns Mounted: keep what it says now.
		for i := range keep {
			if j := find(st.Volumes, keep[i].Name); j >= 0 {
				keep[i].Mounted = st.Volumes[j].Mounted
			}
		}
		st.Volumes = keep
		if len(st.Volumes) == 0 {
			st.Volumes = nil
		}
	}); err != nil {
		return engine.Result{}, err
	}
	if stale {
		return engine.Result{RequeueAfter: time.Second}, errors.Join(errs...)
	}
	if w, err := c.detachKept(ctx, s, letting); err != nil {
		return engine.Result{}, err
	} else if w > 0 && (again == 0 || w < again) {
		again = w
	}
	if c.Records != nil {
		removing := map[string]bool{}
		for _, name := range dropping {
			if err := c.markRemoving(ctx, s, name); err != nil {
				return engine.Result{}, err
			}
			removing[name] = true
		}
		for name := range pending {
			removing[name] = true
		}
		if err := c.dropRecords(ctx, have, keep, removing); err != nil {
			return engine.Result{}, err
		}
		if len(dropping) > 0 {
			return engine.Result{RequeueAfter: time.Millisecond}, errors.Join(errs...) // the removals, from their records
		}
		if len(pending) > 0 {
			return engine.Result{RequeueAfter: max(again, time.Millisecond)}, errors.Join(errs...)
		}
	}
	if len(keep) == 0 && s.DeletionTimestamp != nil {
		return engine.Result{}, setFinalizers(ctx, c.Client, s, FinalizerVolumes, "")
	}
	return engine.Result{RequeueAfter: again}, errors.Join(errs...)
}

// placesOf is what the control plane decides about volumes (which, where, attached how), without
// what their hosts say (mounted) or the messages.
func placesOf(vs []v1.VolumeStatus) string {
	out := make([]v1.VolumeStatus, len(vs))
	for i, v := range vs {
		v.Mounted, v.Message = false, ""
		out[i] = v
	}
	return fmt.Sprintf("%+v", out)
}

func find(vs []v1.VolumeStatus, name string) int {
	for i, v := range vs {
		if v.Name == name {
			return i
		}
	}
	return -1
}

// ensure creates the volume (in the host's region) and attaches it to the silo's host.
func (c *Volumes) ensure(ctx context.Context, s *v1.Silo, h *v1.Host, spec v1.Volume, vs v1.VolumeStatus) (v1.VolumeStatus, time.Duration, error) {
	vs.Kept = false
	vs.Class, vs.Message = spec.Class, ""
	p, cls, ok := c.Plugins.Storage(spec.Class)
	if !ok {
		vs.Message = "no plugin serves storage class " + spec.Class
		return vs, 30 * time.Second, nil
	}
	if h == nil {
		vs.Message = "waiting for a host"
		return vs, 0, nil
	}
	if cls.Mounted() {
		return c.ensureMounted(ctx, s, h, p, cls, spec, vs)
	}
	hp, known := c.Providers.Of(h)
	if !known {
		vs.Message = "waiting for the plugins to describe " + h.Name
		return vs, c.poll(), nil
	}
	if hp == nil || hp.Name != p.Info.Name {
		vs.Message = h.Name + " isn't a " + p.Info.Name + " machine"
		return vs, time.Minute, nil
	}
	hi := info(h.Name, hp)
	if vs.Handle == "" {
		size, err := v1.ParseBytes(spec.Size)
		if err != nil || size <= 0 {
			return vs, 0, fmt.Errorf("size %q: a provider volume needs a size", spec.Size)
		}
		label, err := VolumeLabel(s, spec.Name)
		if err != nil { // admission refuses these; a silo from before it waits, saying why
			vs.Message = err.Error()
			return vs, 0, nil
		}
		st, err := p.Conn.EnsureVolume(ctx, kplugin.Volume{Class: spec.Class, ID: VolumeID(s, spec.Name),
			Name: label, SizeBytes: size, Region: hi.Region})
		if errors.Is(err, kplugin.ErrInProgress) {
			vs.Message = err.Error()
			return vs, c.poll(), nil
		}
		if err != nil {
			return vs, 0, err
		}
		vs.Handle, vs.Region = st.Handle, st.Region
	}
	if vs.Region != "" && vs.Region != hi.Region {
		vs.Message = fmt.Sprintf("the volume is in %s and %s in %s: it can't attach there", vs.Region, h.Name, hi.Region)
		return vs, time.Minute, nil
	}
	if vs.AttachedTo == h.Name && vs.Device != "" {
		return vs, 0, nil
	}
	if vs.AttachedTo != "" && vs.AttachedTo != h.Name {
		// It moved: the old host must let go first, unless that host is lost and the silo was
		// fenced there (its agent stopped it): then the volume is detached anyway.
		attachedLost := false
		if oh, ok := c.Hosts.Get("", vs.AttachedTo); ok {
			attachedLost, _ = hostctl.Lost(oh.(*v1.Host))
		} else {
			// The Host object is gone. Detach is safe once lostNow agrees; deleting the volume
			// is not, and this path never does that.
			attachedLost = true
		}
		if vs.Mounted && !moves.ForceRelease(s, vs, attachedLost) {
			vs.Message = "waiting for " + vs.AttachedTo + " to unmount it"
			return vs, c.poll(), nil
		}
		if vs.Mounted { // forced off a lost host: only if it is lost now, not in a cache behind
			if lost, err := c.lostNow(ctx, vs.AttachedTo); err != nil || !lost {
				vs.Message = "waiting for " + vs.AttachedTo + " to unmount it"
				return vs, c.poll(), err
			}
		}
		old := hi
		if oh, ok := c.Hosts.Get("", vs.AttachedTo); ok {
			ohp, known := c.Providers.Of(oh.(*v1.Host))
			if !known {
				vs.Message = "waiting for the plugins to describe " + vs.AttachedTo
				return vs, c.poll(), nil
			}
			if ohp != nil {
				old = info(vs.AttachedTo, ohp)
			}
		}
		err := p.Conn.DetachVolume(ctx, kplugin.Attachment{Class: spec.Class, Handle: vs.Handle, Host: old})
		if errors.Is(err, kplugin.ErrInProgress) {
			vs.Message = "detaching from " + vs.AttachedTo
			return vs, c.poll(), nil
		}
		if err != nil {
			return vs, 0, err
		}
		vs.AttachedTo, vs.Device = "", ""
	}
	at, err := p.Conn.AttachVolume(ctx, kplugin.Attachment{Class: spec.Class, Handle: vs.Handle, Host: hi})
	if errors.Is(err, kplugin.ErrInProgress) {
		vs.Message = "attaching to " + h.Name
		return vs, c.poll(), nil
	}
	if err != nil {
		return vs, 0, err
	}
	vs.AttachedTo, vs.Device = h.Name, at.Device
	return vs, 0, nil
}

// ensureMounted creates a mount-reach volume and points it at the silo's host once the host it
// was on has let go.
func (c *Volumes) ensureMounted(ctx context.Context, s *v1.Silo, h *v1.Host, p *plugins.Plugin, cls kplugin.Class, spec v1.Volume, vs v1.VolumeStatus) (v1.VolumeStatus, time.Duration, error) {
	var size int64
	if spec.Size != "" {
		var err error
		if size, err = v1.ParseBytes(spec.Size); err != nil || size < 0 {
			return vs, 0, fmt.Errorf("size %q: %v", spec.Size, err)
		}
	}
	// Created once; asked again when the size grows (a quota grows online).
	if vs.Handle == "" || size > vs.SizeBytes {
		region := ""
		if hp, known := c.Providers.Of(h); cls.Topology != kplugin.TopologyGlobal && known && hp != nil {
			region = hp.Region
		} else if cls.Topology != kplugin.TopologyGlobal && !known {
			vs.Message = "waiting for the plugins to describe " + h.Name
			return vs, c.poll(), nil
		}
		label, err := VolumeLabel(s, spec.Name)
		if err != nil { // admission refuses these; a silo from before it waits, saying why
			vs.Message = err.Error()
			return vs, 0, nil
		}
		st, err := p.Conn.EnsureVolume(ctx, kplugin.Volume{Class: spec.Class, ID: VolumeID(s, spec.Name),
			Name: label, SizeBytes: size, Region: region})
		if errors.Is(err, kplugin.ErrInProgress) {
			vs.Message = err.Error()
			return vs, c.poll(), nil
		}
		if err != nil {
			return vs, 0, err
		}
		if vs.Handle != "" && st.Handle != vs.Handle {
			return vs, 0, fmt.Errorf("the plugin answered handle %s for a volume it called %s", st.Handle, vs.Handle)
		}
		vs.Handle, vs.Region = st.Handle, st.Region
		vs.SizeBytes, vs.SizeNotEnforced = size, size > 0 && !st.SizeEnforced
		if cls.Topology == kplugin.TopologyGlobal {
			vs.Region = "" // anywhere: nothing holds the silo to a region
		}
	}
	attachedLost := false
	if vs.AttachedTo != "" && vs.AttachedTo != h.Name {
		if oh, ok := c.Hosts.Get("", vs.AttachedTo); ok {
			attachedLost, _ = hostctl.Lost(oh.(*v1.Host))
		} else {
			// Same as a block volume: a deleted host is lost for the detach, never a reason to
			// delete the volume. lostNow re-reads, so a cache that hasn't seen a live host yet
			// does not detach it.
			attachedLost = true
		}
		if attachedLost && vs.Mounted { // forced off a lost host: only if it is lost now
			var err error
			if attachedLost, err = c.lostNow(ctx, vs.AttachedTo); err != nil {
				return vs, c.poll(), err
			}
		}
	}
	next, wait := PlaceMounted(s, vs, h.Name, attachedLost)
	if wait != "" {
		next.Message = wait
		return next, c.poll(), nil
	}
	return next, 0, nil
}

// PlaceMounted decides where a mount-reach volume should be mounted: on host (the silo's), once
// the host it was on has unmounted it, or right away if that host is lost and the silo was fenced
// there. wait says why not yet. Pure.
func PlaceMounted(s *v1.Silo, vs v1.VolumeStatus, host string, attachedLost bool) (v1.VolumeStatus, string) {
	vs.Device = ""
	switch {
	case vs.AttachedTo == host:
	case vs.AttachedTo != "" && vs.Mounted && !moves.ForceRelease(s, vs, attachedLost):
		return vs, "waiting for " + vs.AttachedTo + " to unmount it"
	default:
		vs.AttachedTo = host
	}
	return vs, ""
}

// keptVolumeMessage is what status says about a volume taken out of the spec.
const keptVolumeMessage = "kept: taken out of the spec; it stays until the silo is deleted"

// retain keeps a volume the spec no longer names. It is deleted only with the silo.
func (c *Volumes) retain(vs v1.VolumeStatus) (v1.VolumeStatus, time.Duration, error) {
	vs.Kept = true
	if vs.Mounted {
		vs.Message = "waiting for " + vs.AttachedTo + " to unmount it"
		return vs, c.poll(), nil
	}
	vs.Message = keptVolumeMessage
	return vs, 0, nil
}

// detachKept detaches volumes taken out of the spec, after a fresh read still says they are
// unwanted, unmounted and kept. It does not delete them.
func (c *Volumes) detachKept(ctx context.Context, s *v1.Silo, names []string) (time.Duration, error) {
	if len(names) == 0 || c.Client == nil {
		return 0, nil
	}
	var cur v1.Silo
	if err := c.Client.Get(ctx, "Silo", s.Namespace, s.Name, &cur); err != nil {
		return 0, client.IgnoreNotFound(err)
	}
	if cur.UID != s.UID || cur.DeletionTimestamp != nil {
		return 0, nil
	}
	want := map[string]bool{}
	for _, v := range v1.PluginVolumes(&cur) {
		want[v.Name] = true
	}
	var wait time.Duration
	changed := false
	for _, name := range names {
		if want[name] {
			continue
		}
		j := find(cur.Status.Volumes, name)
		if j < 0 || cur.Status.Volumes[j].Mounted || !cur.Status.Volumes[j].Kept {
			continue
		}
		vs := &cur.Status.Volumes[j]
		if vs.AttachedTo == "" {
			continue
		}
		if vs.Handle != "" {
			p, cls, ok := c.Plugins.Storage(vs.Class)
			if !ok {
				vs.Message = "detaching it needs the plugin serving " + vs.Class
				changed = true
				wait = 30 * time.Second
				continue
			}
			if !cls.Mounted() {
				hi := kplugin.HostInfo{Name: vs.AttachedTo}
				if c.Hosts != nil {
					if oh, ok := c.Hosts.Get("", vs.AttachedTo); ok {
						if ohp, known := c.Providers.Of(oh.(*v1.Host)); known && ohp != nil {
							hi = info(vs.AttachedTo, ohp)
						}
					}
				}
				err := p.Conn.DetachVolume(ctx, kplugin.Attachment{Class: vs.Class, Handle: vs.Handle, Host: hi})
				if errors.Is(err, kplugin.ErrInProgress) {
					vs.Message = "detaching from " + vs.AttachedTo
					changed = true
					wait = c.poll()
					continue
				}
				if err != nil && !errors.Is(err, kplugin.ErrNotFound) {
					return 0, err
				}
			}
		}
		vs.AttachedTo, vs.Device = "", ""
		vs.Kept = true
		vs.Message = keptVolumeMessage
		changed = true
	}
	if !changed {
		return wait, nil
	}
	if err := c.Client.UpdateStatus(ctx, &cur); err != nil {
		return 0, err
	}
	if c.Records != nil {
		for _, name := range names {
			j := find(cur.Status.Volumes, name)
			if j < 0 {
				continue
			}
			if err := c.writeRecord(ctx, &cur, cur.Status.Volumes[j]); err != nil {
				return 0, err
			}
		}
	}
	return wait, nil
}

func (c *Volumes) writeRecord(ctx context.Context, s *v1.Silo, vs v1.VolumeStatus) error {
	key := recordKey(s, vs.Name)
	o, err := c.Records.Get(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		data, merr := json.Marshal(recorded(vs))
		if merr != nil {
			return merr
		}
		_, err = c.Records.Create(ctx, key, data)
		return err
	}
	if err != nil {
		return err
	}
	r, err := decodeRecord(o)
	if err != nil {
		return err
	}
	r.VolumeStatus = recorded(vs)
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if string(o.Data) == string(data) {
		return nil
	}
	_, err = c.Records.Update(ctx, o.Key, data, o.Revision)
	return err
}

// remove detaches (once unmounted) and deletes a volume; done when it's gone.
func (c *Volumes) remove(ctx context.Context, s *v1.Silo, vs v1.VolumeStatus) (v1.VolumeStatus, bool, time.Duration, error) {
	if vs.Handle == "" {
		return vs, true, 0, nil
	}
	p, cls, ok := c.Plugins.Storage(vs.Class)
	if !ok {
		vs.Message = "deleting it needs the plugin serving " + vs.Class
		return vs, false, 30 * time.Second, nil
	}
	if vs.Mounted {
		vs.Message = "waiting for " + vs.AttachedTo + " to unmount it"
		return vs, false, c.poll(), nil
	}
	if cls.Mounted() {
		vs.AttachedTo, vs.Device = "", "" // nothing attached: unmounted is let go
	}
	if vs.AttachedTo != "" {
		hi := kplugin.HostInfo{Name: vs.AttachedTo}
		if oh, ok := c.Hosts.Get("", vs.AttachedTo); ok {
			ohp, known := c.Providers.Of(oh.(*v1.Host))
			if !known {
				vs.Message = "waiting for the plugins to describe " + vs.AttachedTo
				return vs, false, c.poll(), nil
			}
			if ohp != nil {
				hi = info(vs.AttachedTo, ohp)
			}
		}
		err := p.Conn.DetachVolume(ctx, kplugin.Attachment{Class: vs.Class, Handle: vs.Handle, Host: hi})
		if errors.Is(err, kplugin.ErrInProgress) {
			vs.Message = "detaching from " + vs.AttachedTo
			return vs, false, c.poll(), nil
		}
		if err != nil && !errors.Is(err, kplugin.ErrNotFound) {
			return vs, false, 0, err
		}
		vs.AttachedTo, vs.Device = "", ""
	}
	err := p.Conn.DeleteVolume(ctx, kplugin.VolumeRef{Class: vs.Class, Handle: vs.Handle})
	if errors.Is(err, kplugin.ErrInProgress) {
		vs.Message = "deleting"
		return vs, false, c.poll(), nil
	}
	if err != nil && !errors.Is(err, kplugin.ErrNotFound) {
		return vs, false, 0, err
	}
	_ = s
	return vs, true, 0, nil
}

// Map implements engine.Mapper: a host's provider details reach the silos on it.
func (c *Volumes) Map(changed engine.Key) []engine.Key {
	if changed.Kind != "Host" {
		return nil
	}
	key := ""
	if o, ok := c.Hosts.Get("", changed.Name); ok {
		key = fmt.Sprintf("%+v", o.(*v1.Host).Status.Provider)
	}
	c.mu.Lock()
	if c.hostsSeen == nil {
		c.hostsSeen = map[string]string{}
	}
	prev, had := c.hostsSeen[changed.Name]
	c.hostsSeen[changed.Name] = key
	c.mu.Unlock()
	if had && prev == key {
		return nil // a heartbeat
	}
	var keys []engine.Key
	for _, o := range c.Silos.List() {
		if s := o.(*v1.Silo); s.Status.Host == changed.Name && (len(v1.PluginVolumes(s)) > 0 || len(s.Status.Volumes) > 0) {
			keys = append(keys, engine.Key{Kind: "Silo", Namespace: s.Namespace, Name: s.Name})
		}
	}
	return keys
}

var (
	_ engine.Controller = (*Volumes)(nil)
	_ engine.Mapper     = (*Volumes)(nil)
)
