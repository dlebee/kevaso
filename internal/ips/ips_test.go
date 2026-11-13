package ips

import (
	"fmt"
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

func lbSilo(name, class, ipName string, created int, ports ...int) *v1.Silo {
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "web3", UID: "silo-" + name, CreationTimestamp: at(created)},
		Spec: v1.SiloSpec{Service: &v1.SiloService{Expose: v1.ExposeLoadBalancer, LoadBalancer: &v1.LoadBalancerSpec{Class: class, IP: ipName}}}}
	if len(ports) == 0 {
		ports = []int{30303}
	}
	for _, p := range ports {
		s.Spec.Service.Ports = append(s.Spec.Service.Ports, v1.ServicePort{Name: fmt.Sprint("p", p), Port: p})
	}
	return s
}

func dedicated(s *v1.Silo) *v1.Silo { s.Spec.Service.LoadBalancer.Dedicated = true; return s }

func TestClaims(t *testing.T) {
	ownedBy := func(uid string) func(*v1.IP) {
		return func(x *v1.IP) { x.OwnerReferences = []meta.OwnerReference{{Kind: "Silo", Name: "n", UID: uid}} }
	}
	svc := &v1.Service{ObjectMeta: meta.ObjectMeta{Name: "pub", Namespace: "web3", UID: "svc-pub", CreationTimestamp: at(5)},
		Spec: v1.ServiceSpec{Type: v1.ServiceLoadBalancer, LoadBalancerClass: "fake-lb", LoadBalancerIP: "eth", Ports: []v1.ServicePortSpec{{Name: "https", Port: 443}}}}
	defSvc := &v1.Service{ObjectMeta: meta.ObjectMeta{Name: "front", Namespace: "web3", UID: "svc-front", CreationTimestamp: at(6)},
		Spec: v1.ServiceSpec{Type: v1.ServiceLoadBalancer, LoadBalancerClass: "fake-lb", Ports: []v1.ServicePortSpec{{Name: "https", Port: 443}}}}
	other := lbSilo("eth", "fake-ip", "eth", 0)
	other.Namespace = "elsewhere"
	def := v1.DefaultIPName("fake-lb")
	for _, c := range []struct {
		name      string
		ip        *v1.IP
		exclusive bool
		silos     []*v1.Silo
		svcs      []*v1.Service
		want      []string
	}{
		{"named by a silo", ip("eth", "fake-ip"), true, []*v1.Silo{lbSilo("a", "fake-ip", "eth", 1)}, nil, []string{"silo/a"}},
		{"oldest first", ip("eth", "fake-lb"), false, []*v1.Silo{lbSilo("b", "fake-lb", "eth", 2), lbSilo("a", "fake-lb", "eth", 1)}, []*v1.Service{svc},
			[]string{"silo/a", "silo/b", "service/pub"}},
		{"another namespace doesn't claim (no sharing across namespaces)", ip("eth", "fake-ip"), true, []*v1.Silo{other}, nil, nil},
		{"the class's default: every service of the class naming none", ip(def, "fake-lb"), false,
			[]*v1.Silo{lbSilo("a", "fake-lb", "", 1), lbSilo("b", "fake-lb", "", 2), dedicated(lbSilo("c", "fake-lb", "", 3)), lbSilo("d", "fake-lb-filtered", "", 4)},
			[]*v1.Service{defSvc}, []string{"silo/a", "silo/b", "service/front"}},
		{"dedicated, made for it and owned: claims its own", ip("c", "fake-lb", ownedBy("silo-c")), false, []*v1.Silo{dedicated(lbSilo("c", "fake-lb", "", 0))}, nil, []string{"silo/c"}},
		{"exclusive class, made for it: claims its own", ip("node", "fake-ip", ownedBy("silo-node")), true, []*v1.Silo{lbSilo("node", "fake-ip", "", 0)}, nil, []string{"silo/node"}},
		{"same name, not its own: doesn't take a kept one", ip("node", "fake-ip"), true, []*v1.Silo{lbSilo("node", "fake-ip", "", 0)}, nil, nil},
		{"kept but still held by it: claims", ip("node", "fake-ip", func(x *v1.IP) { x.Status.BoundTo = []v1.IPHolder{{Holder: "silo/node", UID: "silo-node"}} }), true,
			[]*v1.Silo{lbSilo("node", "fake-ip", "", 0)}, nil, []string{"silo/node"}},
		{"worker-ip has no IP", ip("node", v1.LBWorkerIP), false, []*v1.Silo{lbSilo("node", v1.LBWorkerIP, "", 0)}, nil, nil},
		{"egress.ip claims", ip("out", v1.LBIPPool), true, []*v1.Silo{{ObjectMeta: meta.ObjectMeta{Name: "p", Namespace: "web3", UID: "silo-p"},
			Spec: v1.SiloSpec{Network: v1.SiloNetwork{Egress: v1.Egress{Source: v1.EgressPool, IP: "out"}}}}}, nil, []string{"silo/p"}},
	} {
		var got []string
		for _, cl := range Claims(c.ip, c.exclusive, c.silos, c.svcs) {
			got = append(got, cl.Holder)
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: claims %v, want %v", c.name, got, c.want)
		}
	}
}

// The sharing table: who holds an IP and who waits, and when it goes.
func TestDecide(t *testing.T) {
	cl := func(name string, min int, ports ...string) Claim {
		return Claim{Holder: "silo/" + name, UID: "silo-" + name, Created: t0.Add(time.Duration(min) * time.Minute), Ports: ports}
	}
	a, b, c := cl("a", 0, "80/TCP"), cl("b", 1, "443/TCP"), cl("c", 2, "80/TCP")
	gone := a
	gone.Deleting = true
	bound := func(cs ...Claim) func(*v1.IP) {
		return func(x *v1.IP) {
			for _, c := range cs {
				x.Status.BoundTo = append(x.Status.BoundTo, v1.IPHolder{Holder: c.Holder, UID: c.UID, Ports: c.Ports})
			}
		}
	}
	owned := func(x *v1.IP) {
		x.Spec.Reclaim = v1.ReclaimDelete
		x.OwnerReferences = []meta.OwnerReference{{Kind: "Silo", Name: "a", UID: "silo-a"}}
	}
	defaultIP := func(x *v1.IP) {
		x.Spec.Reclaim = v1.ReclaimDelete
		x.Labels = map[string]string{v1.LabelDefaultIP: x.Spec.Class}
	}
	deleting := func(x *v1.IP) { x.DeletionTimestamp = at(0) }
	for _, tc := range []struct {
		name      string
		ip        *v1.IP
		exclusive bool
		claims    []Claim
		holders   string
		waiting   string // substring of the first waiting reason
		delete    bool
	}{
		{"reserved, nobody claims: stays reserved", ip("x", "fake-lb"), false, nil, "", "", false},
		{"shared by default: both on their own ports", ip("x", "fake-lb", defaultIP), false, []Claim{a, b}, "silo/a,silo/b", "", false},
		{"a port clash: the later one waits, told who has it", ip("x", "fake-lb"), false, []Claim{a, b, c}, "silo/a,silo/b", "port 80/TCP on IP x is silo/a's", false},
		{"the same port on UDP is another port", ip("x", "fake-lb"), false, []Claim{a, cl("u", 3, "80/UDP")}, "silo/a,silo/u", "", false},
		{"holders keep it though an older one clashes", ip("x", "fake-lb", bound(c)), false, []Claim{a, c}, "silo/c", "port 80/TCP on IP x is silo/c's", false},
		{"exclusive: one holder, the next waits", ip("x", "fake-ip"), true, []Claim{a, b}, "silo/a", "held by silo/a", false},
		{"exclusive: the holder stays while being deleted", ip("x", "fake-ip", bound(a)), true, []Claim{gone, b}, "silo/a", "held by silo/a", false},
		{"one being deleted takes nothing new", ip("x", "fake-lb"), false, []Claim{gone}, "", "", false},
		{"a holder gone: the rest stay", ip("x", "fake-lb", defaultIP, bound(a, b)), false, []Claim{b}, "silo/b", "", false},
		{"the default's last service gone: it goes", ip("x", "fake-lb", defaultIP, bound(b)), false, nil, "", "", true},
		{"the default, kept, its last service gone: stays", ip("x", "fake-lb", defaultIP, bound(b), func(x *v1.IP) { x.Spec.Reclaim = v1.ReclaimRetain }), false, nil, "", "", false},
		{"made for a service (dedicated), still claimed: stays", ip("x", "fake-lb", owned), false, []Claim{a}, "silo/a", "", false},
		{"made for a service that's gone: goes", ip("x", "fake-lb", owned, bound(a)), false, nil, "", "", true},
		{"made for one that never held it and no longer names it: goes", ip("x", "fake-lb", owned), false, nil, "", "", true},
		{"reclaim Delete by hand, its last holder let go: goes", ip("x", "fake-lb", func(x *v1.IP) { x.Spec.Reclaim = v1.ReclaimDelete }, bound(a)), false, nil, "", "", true},
		{"reclaim Delete by hand, never held: stays reserved", ip("x", "fake-lb", func(x *v1.IP) { x.Spec.Reclaim = v1.ReclaimDelete }), false, nil, "", "", false},
		{"kept and let go: stays", ip("x", "fake-lb", bound(a)), false, nil, "", "", false},
		{"being deleted: takes nobody new", ip("x", "fake-lb", deleting), false, []Claim{a}, "", "being released", false},
	} {
		d := Decide(tc.ip, tc.exclusive, tc.claims)
		var hs []string
		for _, h := range d.Holders {
			hs = append(hs, h.Holder)
		}
		w := ""
		if len(d.Waiting) > 0 {
			w = d.Waiting[0].Reason
		}
		if strings.Join(hs, ",") != tc.holders || d.Delete != tc.delete || (tc.waiting == "" && w != "") || !strings.Contains(w, tc.waiting) {
			t.Errorf("%s: holders %v waiting %q delete %v (%s), want %q %q delete %v", tc.name, hs, w, d.Delete, d.Why, tc.holders, tc.waiting, tc.delete)
		}
	}
}

func TestCanNameAndDelete(t *testing.T) {
	shared := ip("web", "fake-lb", func(x *v1.IP) {
		x.Status.BoundTo = []v1.IPHolder{{Holder: "silo/a", UID: "silo-a", Ports: []string{"80/TCP"}}}
	})
	if why := CanName(shared, false, "silo/b", "silo-b", []string{"443/TCP"}); why != "" {
		t.Errorf("another port on a shared IP: %q", why)
	}
	if why := CanName(shared, false, "silo/b", "silo-b", []string{"80/TCP"}); !strings.Contains(why, "port 80/TCP on IP web is silo/a's") {
		t.Errorf("the same port: %q", why)
	}
	if why := CanName(shared, false, "silo/a", "silo-a", []string{"80/TCP", "443/TCP"}); why != "" {
		t.Errorf("its holder changing its ports: %q", why)
	}
	x := ip("eth", "fake-ip", func(x *v1.IP) { x.Status.BoundTo = []v1.IPHolder{{Holder: "silo/a", UID: "silo-a"}} })
	if why := CanName(x, true, "silo/b", "silo-b", []string{"9/TCP"}); !strings.Contains(why, "held by silo/a") {
		t.Errorf("naming an exclusive IP someone holds: %q", why)
	}
	if why := CanName(x, true, "silo/a", "silo-a2", nil); why != "" {
		t.Errorf("its holder (recreated) naming it again: %q", why)
	}
	if why := CanDelete(x); !strings.Contains(why, "held by silo/a") {
		t.Errorf("deleting a held IP: %q", why)
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
