// Package kplugintest is a fake provider plugin, in memory: every interface, with knobs to make
// operations take a while (ErrInProgress) or fail. Core's tests use it; a provider's tests can
// compare against it.
package kplugintest

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"sync"

	"kevaso.com/core/sdk/kplugin"
)

// Fake is an in-memory plugin named "fake" with classes fake-lb (node ports), fake-ip (announced),
// fake-block and DNS provider fake-dns.
type Fake struct {
	mu sync.Mutex
	// Machines: host address → what the plugin knows about it (only these are its own).
	Machines map[string]kplugin.HostInfo
	LBs      map[string]kplugin.LoadBalancer // by ID
	Volumes  map[string]*FakeVolume          // by handle
	Records  map[string]kplugin.Record       // by name/type
	// DetachCalls before a detach completes (0: at once); counts down per volume.
	DetachSlow int
	// Fail, if set, is returned by every mutating call.
	Fail  error
	Calls []string
	next  int
}

// FakeVolume is a fake block volume.
type FakeVolume struct {
	kplugin.Volume
	Handle     string
	AttachedTo string // machine ID
	detachLeft int
}

// New returns an empty fake.
func New() *Fake {
	return &Fake{Machines: map[string]kplugin.HostInfo{}, LBs: map[string]kplugin.LoadBalancer{},
		Volumes: map[string]*FakeVolume{}, Records: map[string]kplugin.Record{}}
}

func (f *Fake) call(s string, args ...any) error {
	f.Calls = append(f.Calls, fmt.Sprintf(s, args...))
	return f.Fail
}

// Info implements kplugin.Plugin.
func (f *Fake) Info(context.Context) (kplugin.Info, error) {
	return kplugin.Info{Name: "fake", Version: "0.0.0", Protocol: kplugin.Protocol, Hosts: true,
		LoadBalancers: []kplugin.Class{
			{Name: "fake-lb", OwnHostsOnly: true, NodePorts: true},
			{Name: "fake-ip", OwnHostsOnly: true, Announce: true},
		},
		Storage: []kplugin.Class{{Name: "fake-block", OwnHostsOnly: true}},
		DNS:     []string{"fake-dns"}}, nil
}

// DescribeHosts implements kplugin.HostDescriber.
func (f *Fake) DescribeHosts(_ context.Context, hosts []kplugin.Host) ([]kplugin.HostInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []kplugin.HostInfo
	for _, h := range hosts {
		if m, ok := f.Machines[h.Address]; ok {
			m.Name = h.Name
			out = append(out, m)
		}
	}
	return out, nil
}

// EnsureLoadBalancer implements kplugin.LoadBalancers.
func (f *Fake) EnsureLoadBalancer(_ context.Context, lb kplugin.LoadBalancer) (kplugin.LoadBalancerStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("ensure-lb %s %s", lb.Class, lb.ID); err != nil {
		return kplugin.LoadBalancerStatus{}, err
	}
	if len(lb.Backends) == 0 {
		return kplugin.LoadBalancerStatus{}, fmt.Errorf("no backends")
	}
	f.LBs[lb.ID] = lb
	ids := make([]string, 0, len(f.LBs))
	for id := range f.LBs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if lb.Class == "fake-ip" {
		if lb.Address == "" {
			return kplugin.LoadBalancerStatus{}, fmt.Errorf("fake-ip needs an address")
		}
		return kplugin.LoadBalancerStatus{Address: lb.Address}, nil
	}
	n := 0
	for i, id := range ids {
		if id == lb.ID {
			n = i
		}
	}
	addr := netip.AddrFrom4([4]byte{198, 51, 100, byte(10 + n)})
	return kplugin.LoadBalancerStatus{Address: addr.String(), SourceRanges: []string{"192.168.255.0/24"}}, nil
}

// DeleteLoadBalancer implements kplugin.LoadBalancers.
func (f *Fake) DeleteLoadBalancer(_ context.Context, ref kplugin.LoadBalancerRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("delete-lb %s", ref.ID); err != nil {
		return err
	}
	if _, ok := f.LBs[ref.ID]; !ok {
		return kplugin.ErrNotFound
	}
	delete(f.LBs, ref.ID)
	return nil
}

// EnsureVolume implements kplugin.Volumes.
func (f *Fake) EnsureVolume(_ context.Context, v kplugin.Volume) (kplugin.VolumeStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("ensure-volume %s", v.ID); err != nil {
		return kplugin.VolumeStatus{}, err
	}
	for _, x := range f.Volumes {
		if x.ID == v.ID {
			return kplugin.VolumeStatus{Handle: x.Handle, Region: x.Region, SizeBytes: x.SizeBytes}, nil
		}
	}
	f.next++
	h := fmt.Sprintf("vol-%d", f.next)
	f.Volumes[h] = &FakeVolume{Volume: v, Handle: h}
	return kplugin.VolumeStatus{Handle: h, Region: v.Region, SizeBytes: v.SizeBytes}, nil
}

// AttachVolume implements kplugin.Volumes.
func (f *Fake) AttachVolume(_ context.Context, a kplugin.Attachment) (kplugin.AttachmentStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("attach %s %s", a.Handle, a.Host.ID); err != nil {
		return kplugin.AttachmentStatus{}, err
	}
	v, ok := f.Volumes[a.Handle]
	switch {
	case !ok:
		return kplugin.AttachmentStatus{}, kplugin.ErrNotFound
	case v.Region != a.Host.Region:
		return kplugin.AttachmentStatus{}, fmt.Errorf("volume in %s, host in %s", v.Region, a.Host.Region)
	case v.AttachedTo != "" && v.AttachedTo != a.Host.ID:
		return kplugin.AttachmentStatus{}, fmt.Errorf("attached to %s: %w", v.AttachedTo, kplugin.ErrConflict)
	}
	v.AttachedTo = a.Host.ID
	return kplugin.AttachmentStatus{Device: "/dev/disk/by-id/fake-" + v.Handle}, nil
}

// DetachVolume implements kplugin.Volumes.
func (f *Fake) DetachVolume(_ context.Context, a kplugin.Attachment) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("detach %s", a.Handle); err != nil {
		return err
	}
	v, ok := f.Volumes[a.Handle]
	if !ok || v.AttachedTo == "" {
		return nil
	}
	if v.detachLeft == 0 && f.DetachSlow > 0 {
		v.detachLeft = f.DetachSlow + 1
	}
	if v.detachLeft > 1 {
		v.detachLeft--
		return fmt.Errorf("volume %s still detaching: %w", v.Handle, kplugin.ErrInProgress)
	}
	v.detachLeft = 0
	v.AttachedTo = ""
	return nil
}

// DeleteVolume implements kplugin.Volumes.
func (f *Fake) DeleteVolume(_ context.Context, ref kplugin.VolumeRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("delete-volume %s", ref.Handle); err != nil {
		return err
	}
	v, ok := f.Volumes[ref.Handle]
	if !ok {
		return kplugin.ErrNotFound
	}
	if v.AttachedTo != "" {
		return fmt.Errorf("volume %s is attached", ref.Handle)
	}
	delete(f.Volumes, ref.Handle)
	return nil
}

// EnsureRecord implements kplugin.DNS.
func (f *Fake) EnsureRecord(_ context.Context, r kplugin.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("ensure-record %s %s", r.Name, r.Type); err != nil {
		return err
	}
	k := r.Name + "/" + r.Type
	if cur, ok := f.Records[k]; ok && cur.Owner != r.Owner {
		return fmt.Errorf("%s is owned by %q: %w", k, cur.Owner, kplugin.ErrConflict)
	}
	f.Records[k] = r
	return nil
}

// DeleteRecord implements kplugin.DNS.
func (f *Fake) DeleteRecord(_ context.Context, r kplugin.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("delete-record %s %s", r.Name, r.Type); err != nil {
		return err
	}
	k := r.Name + "/" + r.Type
	cur, ok := f.Records[k]
	if !ok {
		return kplugin.ErrNotFound
	}
	if cur.Owner != r.Owner {
		return fmt.Errorf("%s is owned by %q: %w", k, cur.Owner, kplugin.ErrConflict)
	}
	delete(f.Records, k)
	return nil
}

// CallLog returns the calls so far.
func (f *Fake) CallLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.Calls...)
}

// Snapshot returns copies, for assertions.
func (f *Fake) Snapshot() (lbs map[string]kplugin.LoadBalancer, vols map[string]FakeVolume, recs map[string]kplugin.Record) {
	f.mu.Lock()
	defer f.mu.Unlock()
	lbs, vols, recs = map[string]kplugin.LoadBalancer{}, map[string]FakeVolume{}, map[string]kplugin.Record{}
	for k, v := range f.LBs {
		lbs[k] = v
	}
	for k, v := range f.Volumes {
		vols[k] = *v
	}
	for k, v := range f.Records {
		recs[k] = v
	}
	return
}

var (
	_ kplugin.Plugin        = (*Fake)(nil)
	_ kplugin.HostDescriber = (*Fake)(nil)
	_ kplugin.LoadBalancers = (*Fake)(nil)
	_ kplugin.Volumes       = (*Fake)(nil)
	_ kplugin.DNS           = (*Fake)(nil)
)
