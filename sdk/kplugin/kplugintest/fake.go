// Package kplugintest is a fake provider plugin, in memory: every interface, with knobs to make
// operations take a while (ErrInProgress) or fail. Core's tests use it; a provider's tests can
// compare against it.
package kplugintest

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"

	"kevaso.com/core/sdk/kplugin"
)

// Fake is an in-memory plugin named "fake" with classes fake-lb (node ports: its address is the
// balancer's, so it can't reserve or send), fake-lb-filtered (the same, filtering client
// sources), fake-ip (announced: reserves addresses apart from load balancers, which follow the
// silo in a region and can be sent from),
// fake-block (a device), fake-share (mounted by the node side, global topology)
// and DNS provider fake-dns. Node returns its node side on one host; all node sides share the
// fake's volumes, like hosts sharing a network filesystem.
type Fake struct {
	mu sync.Mutex
	// Machines: a host's external or internal IP → what the plugin knows about it (only these are
	// its own).
	Machines map[string]kplugin.HostInfo
	LBs      map[string]kplugin.LoadBalancer // by ID
	// Reserved are fake-ip's reserved addresses, by ID (an IP's UID).
	Reserved map[string]kplugin.AddressStatus
	Volumes  map[string]*FakeVolume    // by handle
	Records  map[string]kplugin.Record // by name/type
	// Mounts are the node sides' mounts of fake-share volumes: "HOST:PATH" → handle.
	Mounts map[string]string
	// DetachCalls before a detach completes (0: at once); counts down per volume.
	DetachSlow int
	// Networking, if set, is what Info declares instead of FakeNetworking.
	Networking *kplugin.Networking
	// BalancerIPv6: its node-port balancers answer on IPv6 too (like a Linode NodeBalancer), at
	// 2001:db8:b::<their IPv4>.
	BalancerIPv6 bool
	// Fail, if set, is returned by every mutating call.
	Fail error
	// ShareRefused, if set, is what fake-ip answers when asked to share an address with its
	// holder's host (an account limit, say); SetShareRefused changes it while plugins run.
	ShareRefused error
	Calls        []string
	next         int
	lbAddr       map[string]string // a node-port balancer's address, by its group (sharedBy)
}

// SetShareRefused sets ShareRefused (nil: shares again).
func (f *Fake) SetShareRefused(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ShareRefused = err
}

// sharedBy is the group a balancer is in: services in one namespace naming the same
// fake.kevaso.com/balancer share one balancer (one address); any other is its own (its ID).
func sharedBy(lb kplugin.LoadBalancer) string {
	if b := lb.Annotations[kplugin.Domain("fake")+AnnotationBalancer]; b != "" {
		return lb.Namespace + "/" + b
	}
	return lb.ID
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
	return &Fake{Machines: map[string]kplugin.HostInfo{}, LBs: map[string]kplugin.LoadBalancer{}, Reserved: map[string]kplugin.AddressStatus{}, lbAddr: map[string]string{},
		Volumes: map[string]*FakeVolume{}, Records: map[string]kplugin.Record{}, Mounts: map[string]string{}}
}

// Fake classes.
const (
	ClassBlock = "fake-block"
	ClassShare = "fake-share"
	// ClassFilteredLB is a node-port class whose load balancer filters client sources.
	ClassFilteredLB = "fake-lb-filtered"
	// ClassLB is the node-port class; ClassIP the announced one, which reserves addresses.
	ClassLB = "fake-lb"
	ClassIP = "fake-ip"
)

func (f *Fake) call(s string, args ...any) error {
	f.Calls = append(f.Calls, fmt.Sprintf(s, args...))
	return f.Fail
}

// Info implements kplugin.Plugin.
func (f *Fake) Info(context.Context) (kplugin.Info, error) {
	return kplugin.Info{Name: "fake", Version: "0.0.0", Protocol: kplugin.Protocol, Hosts: true,
		LoadBalancers: []kplugin.Class{
			{Name: ClassLB, OwnHostsOnly: true, NodePorts: true, Follows: kplugin.FollowsRegion},
			{Name: ClassFilteredLB, OwnHostsOnly: true, NodePorts: true, FiltersSources: true, Follows: kplugin.FollowsRegion},
			{Name: ClassIP, OwnHostsOnly: true, Announce: true, Reserve: true, SendsFrom: true, Exclusive: true, Follows: kplugin.FollowsRegion},
		},
		Storage: []kplugin.Class{
			{Name: ClassBlock, OwnHostsOnly: true},
			{Name: ClassShare, Topology: kplugin.TopologyGlobal, Reach: kplugin.ReachMount},
		},
		DNS: []string{"fake-dns"}, Networking: f.networking()}, nil
}

func (f *Fake) networking() *kplugin.Networking {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Networking != nil {
		return f.Networking
	}
	return FakeNetworking()
}

// The fake's annotations (in its domain, fake.kevaso.com/).
const (
	AnnotationBalancer      = "balancer"        // string, a name: services naming the same one share it
	AnnotationBalancerSize  = "balancer-size"   // enum: small | medium | large
	AnnotationConnections   = "max-connections" // int, 1 to 10000
	AnnotationProxyProtocol = "proxy-protocol"  // bool
	AnnotationIPTag         = "tag"             // string, on an IP
)

// FakeNetworking is what the fake declares by default: Provider IPs and load balancers in two
// regions, its own hosts only, a balancer with its own address (no kept IP in front, like a
// Linode NodeBalancer) that doesn't keep the client's address, and an annotation of each type.
func FakeNetworking() *kplugin.Networking {
	one, most := int64(1), int64(10000)
	return &kplugin.Networking{ProviderIPs: true, LoadBalancers: true, Reach: kplugin.FollowsRegion,
		Regions: []string{"ca-central", "us-ord"}, OwnHostsOnly: true,
		Annotations: []kplugin.Annotation{
			{Key: AnnotationBalancer, Description: "share a balancer: services naming the same one share it", Pattern: `[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?`},
			{Key: AnnotationBalancerSize, Description: "the balancer's size", Type: kplugin.AnnotationEnum, Values: []string{"small", "medium", "large"}},
			{Key: AnnotationConnections, Description: "connections the balancer accepts at once", Type: kplugin.AnnotationInt, Min: &one, Max: &most},
			{Key: AnnotationProxyProtocol, Description: "send the client's address in the PROXY protocol", Type: kplugin.AnnotationBool},
			{Key: AnnotationIPTag, Description: "a tag on the reserved address", On: []string{kplugin.OnIP}},
		}}
}

// DescribeHosts implements kplugin.HostDescriber.
func (f *Fake) DescribeHosts(_ context.Context, hosts []kplugin.Host) ([]kplugin.HostInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []kplugin.HostInfo
	for _, h := range hosts {
		for _, a := range []string{h.ExternalIP, h.InternalIP} {
			if m, ok := f.Machines[a]; ok && a != "" {
				m.Name = h.Name
				out = append(out, m)
				break
			}
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
	if len(lb.Backends) == 0 && len(lb.Ports) == 0 { // parked: it keeps its address, sends nowhere
		if _, ok := f.LBs[lb.ID]; !ok {
			return kplugin.LoadBalancerStatus{}, kplugin.ErrNotFound
		}
		f.LBs[lb.ID] = lb
		return kplugin.LoadBalancerStatus{Address: f.lbAddr[sharedBy(lb)], AddressIPv6: f.lbAddr6(f.lbAddr[sharedBy(lb)])}, nil
	}
	for k := range lb.Annotations {
		if err := fakeAnnotation(k); err != nil {
			return kplugin.LoadBalancerStatus{}, err
		}
	}
	for _, p := range lb.Ports {
		for k := range p.Annotations {
			if err := fakeAnnotation(k); err != nil {
				return kplugin.LoadBalancerStatus{}, fmt.Errorf("port %s of %s: %w", p.Name, p.Service, err)
			}
		}
		if lb.Class != ClassIP && len(p.Backends) == 0 {
			return kplugin.LoadBalancerStatus{}, fmt.Errorf("port %s of %s has no backends", p.Name, p.Service)
		}
	}
	if len(lb.Backends) == 0 {
		return kplugin.LoadBalancerStatus{}, fmt.Errorf("no backends")
	}
	if lb.Class == ClassIP {
		if lb.Address == "" {
			return kplugin.LoadBalancerStatus{}, fmt.Errorf("fake-ip needs an address")
		}
		if !f.reserved(lb.Address) { // a balancer is its service's; the address it answers on, a kept IP's
			return kplugin.LoadBalancerStatus{}, fmt.Errorf("fake-ip: %s isn't reserved", lb.Address)
		}
		if f.ShareRefused != nil {
			return kplugin.LoadBalancerStatus{}, f.ShareRefused
		}
		f.LBs[lb.ID] = lb
		return kplugin.LoadBalancerStatus{Address: lb.Address}, nil
	}
	f.LBs[lb.ID] = lb
	// A balancer's address is its own for its whole life (shared by the services sharing it):
	// the lowest free from 198.51.100.10.
	g := sharedBy(lb)
	if f.lbAddr[g] == "" {
		taken := map[string]bool{}
		for _, a := range f.lbAddr {
			taken[a] = true
		}
		for n := 10; ; n++ {
			if a := netip.AddrFrom4([4]byte{198, 51, 100, byte(n)}).String(); !taken[a] {
				f.lbAddr[g] = a
				break
			}
		}
	}
	return kplugin.LoadBalancerStatus{Address: f.lbAddr[g], AddressIPv6: f.lbAddr6(f.lbAddr[g]), SourceRanges: []string{"192.168.255.0/24"}}, nil
}

// LBAddr6 is the IPv6 address its node-port balancer at v4 answers on ("" without BalancerIPv6).
func (f *Fake) LBAddr6(v4 string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lbAddr6(v4)
}

// lbAddr6 is a node-port balancer's IPv6 address when BalancerIPv6 (its IPv4 in the last 32 bits).
func (f *Fake) lbAddr6(v4 string) string {
	a, err := netip.ParseAddr(v4)
	if !f.BalancerIPv6 || err != nil {
		return ""
	}
	b := a.As4()
	return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0x0b, 12: b[0], 13: b[1], 14: b[2], 15: b[3]}).String()
}

// FakeAnnotations are the annotations the fake knows (it refuses others in its domain): the
// ones it declares (FakeNetworking) and fake.kevaso.com/algorithm.
var FakeAnnotations = func() []string {
	out := []string{"fake.kevaso.com/algorithm"}
	for _, a := range FakeNetworking().Annotations {
		out = append(out, kplugin.Domain("fake")+a.Key)
	}
	return out
}()

func fakeAnnotation(k string) error {
	if strings.HasPrefix(k, "fake.kevaso.com/") && !slices.Contains(FakeAnnotations, k) {
		return fmt.Errorf("unknown annotation %s (the fake knows %s): %w", k, strings.Join(FakeAnnotations, ", "), kplugin.ErrUnsupported)
	}
	return nil
}

// LBOf is the load balancer in namespace ns with a port for holder (silo/NAME or service/NAME),
// with only that holder's ports (ok false if none).
func (f *Fake) LBOf(ns, holder string) (kplugin.LoadBalancer, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ids := make([]string, 0, len(f.LBs))
	for id := range f.LBs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		lb := f.LBs[id]
		if lb.Namespace != ns {
			continue
		}
		var mine []kplugin.Port
		for _, p := range lb.Ports {
			if p.Service == holder {
				mine = append(mine, p)
			}
		}
		if len(mine) > 0 {
			lb.Ports = mine
			return lb, true
		}
	}
	return kplugin.LoadBalancer{}, false
}

// reserved says whether addr is one of fake-ip's reservations.
func (f *Fake) reserved(addr string) bool {
	for _, r := range f.Reserved {
		if r.Address == addr {
			return true
		}
	}
	return false
}

// DeleteLoadBalancer implements kplugin.LoadBalancers.
func (f *Fake) DeleteLoadBalancer(_ context.Context, ref kplugin.LoadBalancerRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("delete-lb %s", ref.ID); err != nil {
		return err
	}
	lb, ok := f.LBs[ref.ID]
	if !ok {
		return kplugin.ErrNotFound
	}
	delete(f.LBs, ref.ID)
	g := sharedBy(lb)
	for _, o := range f.LBs {
		if sharedBy(o) == g {
			return nil // still shared: the balancer stays, with the others' ports
		}
	}
	delete(f.lbAddr, g) // its last service gone: the balancer with it
	return nil
}

// ReserveAddress implements kplugin.Addresses: fake-ip only, 203.0.113.100 onwards (or the one
// asked for), idempotent by ID.
func (f *Fake) ReserveAddress(_ context.Context, r kplugin.AddressReservation) (kplugin.AddressStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("reserve-address %s %s", r.Class, r.ID); err != nil {
		return kplugin.AddressStatus{}, err
	}
	if r.Class != ClassIP {
		return kplugin.AddressStatus{}, fmt.Errorf("class %s holds no address apart from a load balancer: %w", r.Class, kplugin.ErrUnsupported)
	}
	if st, ok := f.Reserved[r.ID]; ok {
		return st, nil
	}
	if r.Region == "" {
		return kplugin.AddressStatus{}, fmt.Errorf("reserving an address needs a region")
	}
	taken := map[string]bool{}
	for _, st := range f.Reserved {
		taken[st.Address] = true
	}
	addr := r.Address
	handle := "adopted:" + addr
	if r.Family == "IPv6" && (f.Networking == nil || !f.Networking.ProviderIPv6) {
		return kplugin.AddressStatus{}, fmt.Errorf("fake declares no IPv6 Provider IPs: %w", kplugin.ErrUnsupported)
	}
	if addr == "" {
		for n := 100; ; n++ {
			a := netip.AddrFrom4([4]byte{203, 0, 113, byte(n)}).String()
			if r.Family == "IPv6" { // 2001:db8:f::N (documentation range)
				a = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0x0f, 14: byte(n >> 8), 15: byte(n)}).String()
			}
			if !taken[a] {
				addr, handle = a, "reserved:"+a
				break
			}
		}
	} else if taken[addr] {
		return kplugin.AddressStatus{}, fmt.Errorf("%s is reserved for another IP: %w", addr, kplugin.ErrConflict)
	}
	st := kplugin.AddressStatus{Address: addr, Region: r.Region, Handle: handle}
	f.Reserved[r.ID] = st
	return st, nil
}

// ReleaseAddress implements kplugin.Addresses: fake-ip's reservation (refused while a load
// balancer still shares it), or for the node-port classes the load balancer keyed by the IP.
func (f *Fake) ReleaseAddress(_ context.Context, ref kplugin.AddressRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("release-address %s %s", ref.Class, ref.ID); err != nil {
		return err
	}
	if ref.Class != ClassIP {
		lb, ok := f.LBs[ref.ID]
		if !ok {
			return kplugin.ErrNotFound
		}
		delete(f.LBs, ref.ID)
		delete(f.lbAddr, sharedBy(lb))
		return nil
	}
	if _, ok := f.Reserved[ref.ID]; !ok {
		return kplugin.ErrNotFound
	}
	for _, lb := range f.LBs {
		if lb.Address != "" && lb.Address == f.Reserved[ref.ID].Address {
			return fmt.Errorf("%s still fronts %s's balancer: %w", lb.Address, lb.Name, kplugin.ErrConflict)
		}
	}
	delete(f.Reserved, ref.ID)
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
			if v.SizeBytes > x.SizeBytes { // grows (online); never shrinks
				x.SizeBytes = v.SizeBytes
			}
			return kplugin.VolumeStatus{Handle: x.Handle, Region: x.Region, SizeBytes: x.SizeBytes, SizeEnforced: x.Class == ClassBlock}, nil
		}
	}
	f.next++
	h := fmt.Sprintf("vol-%d", f.next)
	switch v.Class {
	case ClassBlock:
	case ClassShare: // a folder on a shared filesystem: anywhere, so no region
		h, v.Region = fmt.Sprintf("share-%d", f.next), ""
	default:
		return kplugin.VolumeStatus{}, fmt.Errorf("storage class %s: %w", v.Class, kplugin.ErrUnsupported)
	}
	f.Volumes[h] = &FakeVolume{Volume: v, Handle: h}
	// A block volume's size is its device's; the fake share enforces none (like a folder without a quota).
	return kplugin.VolumeStatus{Handle: h, Region: v.Region, SizeBytes: v.SizeBytes, SizeEnforced: v.Class == ClassBlock}, nil
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
	case v.Class != ClassBlock:
		return kplugin.AttachmentStatus{}, fmt.Errorf("%s volumes are mounted by the node side, not attached: %w", v.Class, kplugin.ErrUnsupported)
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
	for at, h := range f.Mounts {
		if h == ref.Handle {
			return fmt.Errorf("volume %s is mounted at %s", ref.Handle, at)
		}
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

// FakeNode is the fake's node side on one host.
type FakeNode struct {
	*Fake
	Host string
}

// Node returns the fake's node side on host.
func (f *Fake) Node(host string) *FakeNode { return &FakeNode{Fake: f, Host: host} }

// Info implements kplugin.Plugin: the node side serves only the mount classes.
func (n *FakeNode) Info(ctx context.Context) (kplugin.Info, error) {
	i, _ := n.Fake.Info(ctx)
	out := kplugin.Info{Name: i.Name, Version: i.Version, Protocol: i.Protocol}
	for _, c := range i.Storage {
		if c.Mounted() {
			out.Storage = append(out.Storage, c)
		}
	}
	return out, nil
}

// MountVolume implements kplugin.Node.
func (n *FakeNode) MountVolume(_ context.Context, m kplugin.NodeMount) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.call("mount %s %s %s", n.Host, m.Handle, m.Path); err != nil {
		return err
	}
	v, ok := n.Volumes[m.Handle]
	switch {
	case !ok:
		return fmt.Errorf("volume %s: %w", m.Handle, kplugin.ErrNotFound)
	case v.Class != ClassShare:
		return fmt.Errorf("%s volumes aren't mounted by the node side: %w", v.Class, kplugin.ErrUnsupported)
	case m.Path == "":
		return fmt.Errorf("mount %s: no path", m.Handle)
	}
	at := n.Host + ":" + m.Path
	if cur, ok := n.Mounts[at]; ok && cur != m.Handle {
		return fmt.Errorf("%s already has %s mounted: %w", at, cur, kplugin.ErrConflict)
	}
	n.Mounts[at] = m.Handle
	return nil
}

// UnmountVolume implements kplugin.Node.
func (n *FakeNode) UnmountVolume(_ context.Context, m kplugin.NodeMount) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.call("unmount %s %s", n.Host, m.Path); err != nil {
		return err
	}
	delete(n.Mounts, n.Host+":"+m.Path)
	return nil
}

// MountVolume implements kplugin.Node for the fake as one host with no name (core's
// plugins.Conn wants every interface); Node gives a host's own.
func (f *Fake) MountVolume(ctx context.Context, m kplugin.NodeMount) error {
	return f.Node("").MountVolume(ctx, m)
}

// UnmountVolume implements kplugin.Node (see MountVolume).
func (f *Fake) UnmountVolume(ctx context.Context, m kplugin.NodeMount) error {
	return f.Node("").UnmountVolume(ctx, m)
}

// MountsOf returns the paths where handle is mounted, as HOST:PATH.
func (f *Fake) MountsOf(handle string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for at, h := range f.Mounts {
		if h == handle {
			out = append(out, at)
		}
	}
	sort.Strings(out)
	return out
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
	_ kplugin.Addresses     = (*Fake)(nil)
	_ kplugin.Volumes       = (*Fake)(nil)
	_ kplugin.DNS           = (*Fake)(nil)
	_ kplugin.Node          = (*Fake)(nil)
	_ kplugin.Node          = (*FakeNode)(nil)
)
