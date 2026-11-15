package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	hostctl "kevaso.com/core/internal/controllers/host"
	"kevaso.com/core/internal/store"
)

// K-037: who writes what the provider controllers act on.
//
//   - A volume's class, handle, region, attachedTo, device, sizeBytes and sizeNotEnforced in a
//     silo's status: the volumes controller (moves.HostWrite refuses a host's change to any of
//     them; mounted is the host's). The controller acts only on what it recorded itself
//     (VolumeRecordKind, in the store, out of the API's reach): a status that disagrees is put
//     back, and a handle it never recorded is never given to the plugin.
//   - A Host's status.provider: the provider-hosts controller, from the plugin's DescribeHosts. A
//     worker may write its own Host's status, so balancers and volumes act on what the plugin said
//     (Providers), never on the status.

// Providers is what the plugins said about each host when the provider-hosts controller asked
// (this process: asked again by each new leader). Nil: the Host's status is used (tests without
// that controller).
type Providers struct {
	mu sync.Mutex
	m  map[string]*v1.HostProvider
}

func (p *Providers) set(host string, hp *v1.HostProvider) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m == nil {
		p.m = map[string]*v1.HostProvider{}
	}
	if hp != nil {
		c := *hp
		hp = &c
	}
	p.m[host] = hp
}

// Of is h's provider details to act on, and whether they are known yet (false: the plugins
// haven't been asked about h since this control plane started; wait).
func (p *Providers) Of(h *v1.Host) (*v1.HostProvider, bool) {
	if p == nil {
		return h.Status.Provider, true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	hp, ok := p.m[h.Name]
	if hp != nil {
		c := *hp
		hp = &c
	}
	return hp, ok
}

// VolumeRecordKind is the store kind of the volumes controller's own record of each volume (not
// an API kind: no client reads or writes it).
const VolumeRecordKind = "VolumeRecord"

func recordKey(s *v1.Silo, volume string) store.Key {
	return store.Key{Kind: VolumeRecordKind, Namespace: s.Namespace, Name: s.UID + "." + volume}
}

// recorded is the part of a volume's status the control plane decides: all but mounted and the
// message.
func recorded(vs v1.VolumeStatus) v1.VolumeStatus {
	vs.Mounted, vs.Message = false, ""
	return vs
}

// unknown reports whether a volume status says anything the control plane decides (beyond its
// name and class).
func unknown(vs v1.VolumeStatus) bool {
	return vs.Handle != "" || vs.Region != "" || vs.AttachedTo != "" || vs.Device != "" || vs.SizeBytes != 0 || vs.SizeNotEnforced
}

// records reads the control plane's records of s's volumes, by volume name.
func (c *Volumes) records(ctx context.Context, s *v1.Silo) (map[string]store.Object, error) {
	objs, _, err := c.Records.List(ctx, store.Selector{Kind: VolumeRecordKind, Namespace: s.Namespace})
	if err != nil {
		return nil, err
	}
	out := map[string]store.Object{}
	for _, o := range objs {
		if name, ok := strings.CutPrefix(o.Name, s.UID+"."); ok {
			out[name] = o
		}
	}
	return out, nil
}

// trusted is vs as the control plane recorded it: a status that disagrees is put back (keeping
// mounted, the host's), and one it never recorded keeps only its name, class and where it is
// attached (the plugin is asked for the handle of the silo's own volume ID, and attaching again
// gives the device). For a volume being removed, ok is false when there is nothing to trust.
func trusted(vs v1.VolumeStatus, rec *store.Object, wanted bool) (v1.VolumeStatus, bool, error) {
	if rec != nil {
		full, err := decodeRecord(*rec)
		if err != nil {
			return vs, false, err
		}
		r := full.VolumeStatus
		if recorded(vs) != r {
			r.Mounted, r.Message = vs.Mounted, "its status disagreed with the control plane's record; put back"
			return r, true, nil
		}
		return vs, true, nil
	}
	if !unknown(vs) {
		return vs, true, nil
	}
	if !wanted {
		vs.Message = "the control plane has no record of handle " + vs.Handle + ": not acting on what status says; delete it by hand if it is this silo's"
		return vs, false, nil
	}
	return v1.VolumeStatus{Name: vs.Name, Class: vs.Class, AttachedTo: vs.AttachedTo, Mounted: vs.Mounted,
		Message: "its status named a volume the control plane never recorded; asking the plugin"}, true, nil
}

// keepRecords writes the records of the volumes kept and removes the others of s.
func (c *Volumes) keepRecords(ctx context.Context, s *v1.Silo, have map[string]store.Object, keep []v1.VolumeStatus) error {
	for _, vs := range keep {
		r := recorded(vs)
		o, ok := have[vs.Name]
		if !unknown(r) { // nothing decided (yet, or any more)
			if ok {
				if _, err := c.Records.Delete(ctx, o.Key, o.Revision); err != nil && !errors.Is(err, store.ErrNotFound) {
					return err
				}
			}
			continue
		}
		data, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if ok {
			if string(o.Data) == string(data) {
				continue
			}
			_, err = c.Records.Update(ctx, o.Key, data, o.Revision)
		} else {
			_, err = c.Records.Create(ctx, recordKey(s, vs.Name), data)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// dropRecords removes s's records of volumes no longer in its status, but those being removed
// (removing, or dropped by this round).
func (c *Volumes) dropRecords(ctx context.Context, have map[string]store.Object, keep []v1.VolumeStatus, removing map[string]bool) error {
	var errs []error
	for name, o := range have {
		if find(keep, name) >= 0 || removing[name] {
			continue
		}
		if r, err := decodeRecord(o); err == nil && r.Removing {
			continue
		}
		if _, err := c.Records.Delete(ctx, o.Key, o.Revision); err != nil && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrConflict) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// volumeRecord is a record as stored: the volume as the control plane decided it, and whether it
// is being removed. A removal starts with a conditional write that drops the volume from the
// silo's status (no host can mount it, or say it is mounted, once it is gone); only then is the
// record marked removing, and the detach and delete are made from the record (review of
// check-then-act, item 1).
type volumeRecord struct {
	v1.VolumeStatus
	Removing bool `json:"removing,omitempty"`
}

func decodeRecord(o store.Object) (volumeRecord, error) {
	var r volumeRecord
	err := json.Unmarshal(o.Data, &r)
	return r, err
}

// markRemoving marks the record of volume name as being removed (its status entry is gone).
func (c *Volumes) markRemoving(ctx context.Context, s *v1.Silo, name string) error {
	for range 5 {
		o, err := c.Records.Get(ctx, recordKey(s, name))
		if errors.Is(err, store.ErrNotFound) {
			return nil // nothing was ever made
		}
		if err != nil {
			return err
		}
		r, err := decodeRecord(o)
		if err != nil {
			return err
		}
		r.Removing = true
		data, _ := json.Marshal(r)
		if _, err = c.Records.Update(ctx, o.Key, data, o.Revision); !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return errors.New("the volume's record kept changing")
}

// removals carries on the removals under way (records marked removing): detach, then delete,
// keeping the record up to date, dropping it when done. pending: the names still being removed.
func (c *Volumes) removals(ctx context.Context, s *v1.Silo, have map[string]store.Object) (pending map[string]bool, wait time.Duration, err error) {
	pending = map[string]bool{}
	var errs []error
	for name, o := range have {
		r, derr := decodeRecord(o)
		if derr != nil || !r.Removing {
			continue
		}
		vs := r.VolumeStatus
		vs.Mounted = false // its status entry is gone: no host can have it mounted
		next, done, w, rerr := c.remove(ctx, s, vs)
		if rerr != nil {
			errs = append(errs, fmt.Errorf("volume %s: %w", name, rerr))
		}
		if w > 0 && (wait == 0 || w < wait) {
			wait = w
		}
		if done {
			if _, err := c.Records.Delete(ctx, o.Key, o.Revision); err != nil && !errors.Is(err, store.ErrNotFound) {
				errs = append(errs, err)
				pending[name] = true
			}
			continue
		}
		pending[name] = true
		if recorded(next) != recorded(vs) {
			r.VolumeStatus = recorded(next)
			data, _ := json.Marshal(r)
			if _, err := c.Records.Update(ctx, o.Key, data, o.Revision); err != nil && !errors.Is(err, store.ErrConflict) {
				errs = append(errs, err)
			}
		}
	}
	return pending, wait, errors.Join(errs...)
}

// lostNow reads host fresh, not from the cache: a volume is forced off a host only while that
// host is lost now (a cache that still says lost after it came back would detach a disk its
// guest has open).
func (c *Volumes) lostNow(ctx context.Context, host string) (bool, error) {
	var h v1.Host
	if err := c.Client.Get(ctx, "Host", "", host, &h); err != nil {
		if client.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}
	lost, _ := hostctl.Lost(&h)
	return lost, nil
}

// removalsUnderWay reports whether any record of s remains (a removal under way, or a volume to
// put back): the silo's finalizer stays until there is none. A store that can't say counts as
// yes.
func (c *Volumes) removalsUnderWay(ctx context.Context, s *v1.Silo) bool {
	if c.Records == nil {
		return false
	}
	have, err := c.records(ctx, s)
	return err != nil || len(have) > 0
}
