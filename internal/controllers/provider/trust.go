package provider

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"

	v1 "kevaso.com/core/api/v1"
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
		var r v1.VolumeStatus
		if err := json.Unmarshal(rec.Data, &r); err != nil {
			return vs, false, err
		}
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

// dropRecords removes s's records of volumes no longer in its status.
func (c *Volumes) dropRecords(ctx context.Context, have map[string]store.Object, keep []v1.VolumeStatus) error {
	var errs []error
	for name, o := range have {
		if find(keep, name) >= 0 {
			continue
		}
		if _, err := c.Records.Delete(ctx, o.Key, o.Revision); err != nil && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrConflict) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
