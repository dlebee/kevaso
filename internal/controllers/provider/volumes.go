package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/sdk/kplugin"
)

// Volumes creates a silo's volumes on a plugin's storage class and attaches them to its host; the
// host's agent formats each once and mounts it. Removing one (from the spec, or deleting the silo)
// waits until the host has unmounted it, then detaches it (polled: a detach can take minutes,
// E032) and deletes it.
type Volumes struct {
	Client  *client.Client
	Silos   *informer.Informer
	Hosts   *informer.Informer
	Plugins *plugins.Registry
	// Poll is how soon to look again while something is in progress (default 5s).
	Poll time.Duration
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
	p, _, ok := c.Plugins.Storage(spec.Class)
	if !ok {
		vs.Message = "no plugin serves storage class " + spec.Class
		return vs, 30 * time.Second, nil
	}
	if h == nil {
		vs.Message = "waiting for a host"
		return vs, 0, nil
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
		// It moved: the old host must let go first.
		if vs.Mounted {
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

// remove detaches (once unmounted) and deletes a volume; done when it's gone.
func (c *Volumes) remove(ctx context.Context, s *v1.Silo, vs v1.VolumeStatus) (v1.VolumeStatus, bool, time.Duration, error) {
	if vs.Handle == "" {
		return vs, true, 0, nil
	}
	p, _, ok := c.Plugins.Storage(vs.Class)
	if !ok {
		vs.Message = "deleting it needs the plugin serving " + vs.Class
		return vs, false, 30 * time.Second, nil
	}
	if vs.Mounted {
		vs.Message = "waiting for " + vs.AttachedTo + " to unmount it"
		return vs, false, c.poll(), nil
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
