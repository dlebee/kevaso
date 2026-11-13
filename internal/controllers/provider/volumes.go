package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	v1 "kevaso.com/core/api/v1"
	hostctl "kevaso.com/core/internal/controllers/host"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/sdk/kplugin"
)

// Volumes creates a silo's volumes on a plugin's storage class and attaches them to its host; the
// host's agent formats each once and mounts it. Removing one (from the spec, or deleting the silo)
// waits until the host has unmounted it, then detaches it (polled: a detach can take minutes,
// E032) and deletes it.
//
// A mount-reach class (juicefs) attaches nothing: the volume is created once, and status says
// which host should mount it (attachedTo); that host's agent asks the plugin's node side to mount
// it. When the silo moves, the old host unmounts it first, then attachedTo moves on.
type Volumes struct {
	Client  *client.Client
	Silos   *informer.Informer
	Hosts   *informer.Informer
	Plugins *plugins.Registry
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

// VolumeLabel is a human label for it on the provider's side (≤ 32 characters, letters, digits, -).
func VolumeLabel(s *v1.Silo, name string) string {
	l := "kvo-" + s.Namespace + "-" + s.Name + "-" + name
	if len(l) > 26 {
		l = l[:26]
	}
	return strings.TrimRight(l, "-") + "-" + s.UID[:5]
}

// Reconcile implements engine.Controller.
func (c *Volumes) Reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	o, ok := c.Silos.Get(k.Namespace, k.Name)
	if !ok {
		return engine.Result{}, nil
	}
	s := o.(*v1.Silo)
	want := map[string]v1.Volume{}
	if s.DeletionTimestamp == nil {
		for _, v := range v1.PluginVolumes(s) {
			want[v.Name] = v
		}
	}
	if len(want) == 0 && len(s.Status.Volumes) == 0 {
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
	var again time.Duration
	var errs []error
	keep := vols[:0]
	for _, vs := range vols {
		spec, wanted := want[vs.Name]
		var (
			next v1.VolumeStatus
			done bool
			wait time.Duration
			err  error
		)
		if wanted {
			next, wait, err = c.ensure(ctx, s, host, spec, vs)
		} else {
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
	if err := updateStatus(ctx, c.Client, s, func(st *v1.SiloStatus) {
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
	if len(keep) == 0 && s.DeletionTimestamp != nil {
		return engine.Result{}, setFinalizers(ctx, c.Client, s, FinalizerVolumes, "")
	}
	return engine.Result{RequeueAfter: again}, errors.Join(errs...)
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
	if h.Status.Provider == nil || h.Status.Provider.Name != p.Info.Name {
		vs.Message = h.Name + " isn't a " + p.Info.Name + " machine"
		return vs, time.Minute, nil
	}
	hi := info(h)
	if vs.Handle == "" {
		size, err := v1.ParseBytes(spec.Size)
		if err != nil || size <= 0 {
			return vs, 0, fmt.Errorf("size %q: a provider volume needs a size", spec.Size)
		}
		st, err := p.Conn.EnsureVolume(ctx, kplugin.Volume{Class: spec.Class, ID: VolumeID(s, spec.Name),
			Name: VolumeLabel(s, spec.Name), SizeBytes: size, Region: hi.Region})
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
		}
		if vs.Mounted && !moves.ForceRelease(s, vs, attachedLost) {
			vs.Message = "waiting for " + vs.AttachedTo + " to unmount it"
			return vs, c.poll(), nil
		}
		old := hi
		if oh, ok := c.Hosts.Get("", vs.AttachedTo); ok && oh.(*v1.Host).Status.Provider != nil {
			old = info(oh.(*v1.Host))
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
		if cls.Topology != kplugin.TopologyGlobal && h.Status.Provider != nil {
			region = h.Status.Provider.Region
		}
		st, err := p.Conn.EnsureVolume(ctx, kplugin.Volume{Class: spec.Class, ID: VolumeID(s, spec.Name),
			Name: VolumeLabel(s, spec.Name), SizeBytes: size, Region: region})
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
		if oh, ok := c.Hosts.Get("", vs.AttachedTo); ok && oh.(*v1.Host).Status.Provider != nil {
			hi = info(oh.(*v1.Host))
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
