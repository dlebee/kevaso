package ips

import (
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

var t0 = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

func at(min int) *time.Time { t := t0.Add(time.Duration(min) * time.Minute); return &t }

func ip(name, class string, mut ...func(*v1.IP)) *v1.IP {
	x := &v1.IP{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "web3", UID: "ip-" + name}, Spec: v1.IPSpec{Class: class}}
	for _, m := range mut {
		m(x)
	}
	return x
}

func lbSilo(name, class, ipName string, created int) *v1.Silo {
	return &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "web3", UID: "silo-" + name, CreationTimestamp: at(created)},
		Spec: v1.SiloSpec{Service: &v1.SiloService{Expose: v1.ExposeLoadBalancer, LoadBalancer: &v1.LoadBalancerSpec{Class: class, IP: ipName}}}}
}

func TestClaims(t *testing.T) {
	ownedBy := func(uid string) func(*v1.IP) {
		return func(x *v1.IP) { x.OwnerReferences = []meta.OwnerReference{{Kind: "Silo", Name: "n", UID: uid}} }
	}
	svc := &v1.Service{ObjectMeta: meta.ObjectMeta{Name: "pub", Namespace: "web3", UID: "svc-pub", CreationTimestamp: at(5)},
		Spec: v1.ServiceSpec{Type: v1.ServiceLoadBalancer, LoadBalancerClass: "fake-lb", LoadBalancerIP: "eth"}}
	other := lbSilo("eth", "fake-ip", "eth", 0)
	other.Namespace = "elsewhere"
	for _, c := range []struct {
		name  string
		ip    *v1.IP
		silos []*v1.Silo
		svcs  []*v1.Service
		want  []string
	}{
		{"named by a silo", ip("eth", "fake-ip"), []*v1.Silo{lbSilo("a", "fake-ip", "eth", 1)}, nil, []string{"silo/a"}},
		{"oldest first", ip("eth", "fake-ip"), []*v1.Silo{lbSilo("b", "fake-ip", "eth", 2), lbSilo("a", "fake-ip", "eth", 1)}, []*v1.Service{svc},
			[]string{"silo/a", "silo/b", "service/pub"}},
		{"another namespace doesn't claim", ip("eth", "fake-ip"), []*v1.Silo{other}, nil, nil},
		{"made for it and owned: claims", ip("node", "fake-ip", ownedBy("silo-node")), []*v1.Silo{lbSilo("node", "fake-ip", "", 0)}, nil, []string{"silo/node"}},
		{"same name, not its own: doesn't take a kept one", ip("node", "fake-ip"), []*v1.Silo{lbSilo("node", "fake-ip", "", 0)}, nil, nil},
		{"kept but still bound to it: claims", ip("node", "fake-ip", func(x *v1.IP) { x.Status.BoundUID = "silo-node" }),
			[]*v1.Silo{lbSilo("node", "fake-ip", "", 0)}, nil, []string{"silo/node"}},
		{"worker-ip has no IP", ip("node", v1.LBWorkerIP), []*v1.Silo{lbSilo("node", v1.LBWorkerIP, "", 0)}, nil, nil},
		{"egress.ip claims", ip("out", v1.LBIPPool), []*v1.Silo{{ObjectMeta: meta.ObjectMeta{Name: "p", Namespace: "web3", UID: "silo-p"},
			Spec: v1.SiloSpec{Network: v1.SiloNetwork{Egress: v1.Egress{Source: v1.EgressPool, IP: "out"}}}}}, nil, []string{"silo/p"}},
	} {
		var got []string
		for _, cl := range Claims(c.ip, c.silos, c.svcs) {
			got = append(got, cl.Holder)
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: claims %v, want %v", c.name, got, c.want)
		}
	}
}

func TestDecide(t *testing.T) {
	a := Claim{Holder: "silo/a", UID: "silo-a", Created: t0}
	b := Claim{Holder: "silo/b", UID: "silo-b", Created: t0.Add(time.Minute)}
	gone := Claim{Holder: "silo/a", UID: "silo-a", Created: t0, Deleting: true}
	bound := func(c Claim) func(*v1.IP) {
		return func(x *v1.IP) { x.Status.BoundTo, x.Status.BoundUID = c.Holder, c.UID }
	}
	owned := func(x *v1.IP) {
		x.Spec.Reclaim = v1.ReclaimDelete
		x.OwnerReferences = []meta.OwnerReference{{Kind: "Silo", Name: "a", UID: "silo-a"}}
	}
	deleting := func(x *v1.IP) { x.DeletionTimestamp = at(0) }
	for _, c := range []struct {
		name   string
		ip     *v1.IP
		claims []Claim
		holder string
		delete bool
	}{
		{"reserved, nobody claims: stays reserved", ip("x", "fake-ip"), nil, "", false},
		{"first claim binds", ip("x", "fake-ip"), []Claim{a, b}, "silo/a", false},
		{"bound stays bound though an older one claims", ip("x", "fake-ip", bound(b)), []Claim{a, b}, "silo/b", false},
		{"holder being deleted still holds it", ip("x", "fake-ip", bound(a)), []Claim{gone, b}, "silo/a", false},
		{"a silo being deleted takes nothing new", ip("x", "fake-ip"), []Claim{gone}, "", false},
		{"holder gone: the next one binds", ip("x", "fake-ip", bound(a)), []Claim{b}, "silo/b", false},
		{"holder gone, kept: unbound, stays", ip("x", "fake-ip", bound(a)), nil, "", false},
		{"made for a service, still claimed: stays", ip("x", "fake-ip", owned), []Claim{a}, "silo/a", false},
		{"made for a service that's gone: goes", ip("x", "fake-ip", owned, bound(a)), nil, "", true},
		{"made for one that never held it and no longer names it: goes", ip("x", "fake-ip", owned), nil, "", true},
		{"reclaim Delete by hand, its holder let go: goes", ip("x", "fake-ip", func(x *v1.IP) { x.Spec.Reclaim = v1.ReclaimDelete }, bound(a)), nil, "", true},
		{"reclaim Delete by hand, never held: stays reserved", ip("x", "fake-ip", func(x *v1.IP) { x.Spec.Reclaim = v1.ReclaimDelete }), nil, "", false},
		{"kept (owner dropped) and let go: stays", ip("x", "fake-ip", bound(a)), nil, "", false},
		{"being deleted: binds nobody new", ip("x", "fake-ip", deleting), []Claim{a}, "", false},
	} {
		d := Decide(c.ip, c.claims)
		if d.Holder.Holder != c.holder || d.Bound != (c.holder != "") || d.Delete != c.delete {
			t.Errorf("%s: holder %q bound %v delete %v (%s), want %q delete %v", c.name, d.Holder.Holder, d.Bound, d.Delete, d.Why, c.holder, c.delete)
		}
	}
}

func TestCanNameAndDelete(t *testing.T) {
	x := ip("eth", "fake-ip", func(x *v1.IP) { x.Status.BoundTo, x.Status.BoundUID = "silo/a", "silo-a" })
	if why := CanName(x, "silo/b", "silo-b"); !strings.Contains(why, "held by silo/a") {
		t.Errorf("naming a bound IP: %q", why)
	}
	if why := CanName(x, "silo/a", "silo-a2"); why != "" {
		t.Errorf("its holder (recreated) naming it again: %q", why)
	}
	if why := CanDelete(x); !strings.Contains(why, "held by silo/a") {
		t.Errorf("deleting a bound IP: %q", why)
	}
	if why := CanDelete(ip("free", "fake-ip")); why != "" {
		t.Errorf("deleting a reserved IP: %q", why)
	}
}

func host(name string, addrs ...string) *v1.Host {
	return &v1.Host{ObjectMeta: meta.ObjectMeta{Name: name}, Spec: v1.HostSpec{Network: v1.HostNetwork{Addresses: addrs}}}
}

func poolIP(name, h, addr string) *v1.IP {
	return ip(name, v1.LBIPPool, func(x *v1.IP) { x.Status.Host, x.Status.Address = h, addr })
}

func TestExpand(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want string
		err  string
	}{
		{[]string{"203.0.113.20/30"}, "203.0.113.21 203.0.113.22", ""},
		{[]string{"203.0.113.20/31", "198.51.100.7"}, "203.0.113.20 203.0.113.21 198.51.100.7", ""},
		{[]string{"203.0.113.9/32"}, "203.0.113.9", ""},
		{[]string{"203.0.113.21/30"}, "203.0.113.21 203.0.113.22", ""}, // masked
		{[]string{"2001:db8::/64"}, "", "IPv6"},
		{[]string{"10.0.0.0/16"}, "", "at most a /22"},
		{[]string{"nope"}, "", "isn't an address"},
	} {
		got, err := Expand(c.in)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%v: %v, want an error with %q", c.in, err, c.err)
			}
			continue
		}
		var s []string
		for _, a := range got {
			s = append(s, a.String())
		}
		if err != nil || strings.Join(s, " ") != c.want {
			t.Errorf("%v: %v %v, want %s", c.in, s, err, c.want)
		}
	}
}

func TestAllocate(t *testing.T) {
	hosts := []*v1.Host{host("hv2", "203.0.113.20/30"), host("hv1", "198.51.100.7"), host("bare")}
	for _, c := range []struct {
		name     string
		ip       *v1.IP
		all      []*v1.IP
		placed   string
		wantHost string
		wantAddr string
		err      string
	}{
		{"no hint: first host by name with a free one", ip("a", v1.LBIPPool), nil, "", "hv1", "198.51.100.7", ""},
		{"the host's first free", ip("a", v1.LBIPPool, func(x *v1.IP) { x.Spec.Host = "hv2" }), nil, "", "hv2", "203.0.113.21", ""},
		{"never twice", ip("b", v1.LBIPPool, func(x *v1.IP) { x.Spec.Host = "hv2" }), []*v1.IP{poolIP("a", "hv2", "203.0.113.21")}, "", "hv2", "203.0.113.22", ""},
		{"its own counts as free (idempotent)", poolIP("a", "hv2", "203.0.113.21"), []*v1.IP{poolIP("a", "hv2", "203.0.113.21")}, "hv2", "hv2", "203.0.113.21", ""},
		{"where its holder is placed", ip("a", v1.LBIPPool), nil, "hv2", "hv2", "203.0.113.21", ""},
		{"skips a full host", ip("c", v1.LBIPPool), []*v1.IP{poolIP("x", "hv1", "198.51.100.7")}, "", "hv2", "203.0.113.21", ""},
		{"host full", ip("c", v1.LBIPPool, func(x *v1.IP) { x.Spec.Host = "hv1" }), []*v1.IP{poolIP("x", "hv1", "198.51.100.7")}, "", "", "", "hv1 has no free address"},
		{"host without addresses", ip("c", v1.LBIPPool, func(x *v1.IP) { x.Spec.Host = "bare" }), nil, "", "", "", "kvoadm host addresses bare add"},
		{"a picked address", ip("c", v1.LBIPPool, func(x *v1.IP) { x.Spec.Address = "203.0.113.22" }), nil, "", "hv2", "203.0.113.22", ""},
		{"a picked address someone holds", ip("c", v1.LBIPPool, func(x *v1.IP) { x.Spec.Address = "203.0.113.22" }), []*v1.IP{poolIP("x", "hv2", "203.0.113.22")}, "", "", "", "is IP web3/x's"},
		{"a picked address on another host than asked", ip("c", v1.LBIPPool, func(x *v1.IP) { x.Spec.Address = "203.0.113.22"; x.Spec.Host = "hv1" }), nil, "", "", "", "isn't one of hv1's"},
		{"no such host", ip("c", v1.LBIPPool, func(x *v1.IP) { x.Spec.Host = "nope" }), nil, "", "", "", "doesn't exist"},
	} {
		h, a, err := Allocate(c.ip, hosts, c.all, c.placed)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: %s %s %v, want an error with %q", c.name, h, a, err, c.err)
			}
			continue
		}
		if err != nil || h != c.wantHost || a != c.wantAddr {
			t.Errorf("%s: %s %s %v, want %s %s", c.name, h, a, err, c.wantHost, c.wantAddr)
		}
	}
	free := Free(hosts, []*v1.IP{poolIP("x", "hv2", "203.0.113.21")}, nil)
	if free["hv2"] != 1 || free["hv1"] != 1 || free["bare"] != 0 {
		t.Errorf("free: %v", free)
	}
}

func TestCheckHostAddresses(t *testing.T) {
	all := []*v1.IP{poolIP("x", "hv2", "203.0.113.21"), poolIP("y", "hv1", "198.51.100.7")}
	if why := CheckHostAddresses("hv2", []string{"203.0.113.21/32"}, all); why != "" {
		t.Errorf("keeping the address in use: %q", why)
	}
	if why := CheckHostAddresses("hv2", nil, all); !strings.Contains(why, "203.0.113.21 (IP web3/x)") {
		t.Errorf("removing an address in use: %q", why)
	}
	if why := CheckHostAddresses("hv3", nil, all); why != "" {
		t.Errorf("another host's: %q", why)
	}
	if why := Overlap([]*v1.Host{host("a", "203.0.113.20/30"), host("b", "203.0.113.22")}); !strings.Contains(why, "overlaps") {
		t.Errorf("overlap: %q", why)
	}
}
