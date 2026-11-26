package scheduler

import (
	"sort"
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/sdk/kplugin"
)

// The providers the address tests know: linode (its machines, in its region, two regions served),
// anycast (an address that reaches anywhere), sticky (an address stays on the host first given it),
// old (built before the sdk declared networking).
var nets = plugins.Static{
	"linode":  {ProviderIPs: true, LoadBalancers: true, Reach: kplugin.FollowsRegion, OwnHostsOnly: true, Regions: []string{"us-ord", "ca-central"}},
	"anycast": {ProviderIPs: true, Reach: kplugin.FollowsGlobal},
	"sticky":  {ProviderIPs: true, Reach: kplugin.FollowsHost, OwnHostsOnly: true},
	"old":     nil,
}

func ext(ip string) hostOpt { return func(h *v1.Host) { h.Spec.ExternalIP = ip } }
func addr(name, ip string) hostOpt {
	return func(h *v1.Host) {
		h.Spec.Addresses = append(h.Spec.Addresses, v1.HostAddress{Name: name, Kind: v1.NetworkExternal, Address: ip})
	}
}

// cluster: two bare metals (bm1 has the extra address mail and mail2's on bm2), three Linodes,
// and a box at home with no external IP.
func cluster() []*v1.Host {
	return hosts(
		host("bm1", ext("198.51.100.1"), addr("mail", "198.51.100.17")),
		host("bm2", ext("198.51.100.2"), addr("mail2", "198.51.100.18")),
		host("lin1", ext("172.236.0.1"), provider("linode", "us-ord")),
		host("lin2", ext("172.236.0.2"), provider("linode", "us-ord")),
		host("lin3", ext("172.105.0.3"), provider("linode", "ca-central")),
		host("home", func(h *v1.Host) { h.Spec.InternalIP, h.Spec.Network.BehindNAT = "192.168.1.5", true }),
	)
}

// web is a silo with one https port and the services ways make.
func web(name string, ways ...func(*v1.Silo)) *v1.Silo {
	s := silo(name)
	s.UID = "uid-" + name
	s.Spec.Ports = []v1.SiloPort{{Name: "https", Port: 8443}}
	for _, w := range ways {
		w(s)
	}
	return s
}

func svc(sv v1.SiloService) func(*v1.Silo) {
	return func(s *v1.Silo) {
		sv.Ports = []v1.ServicePort{{Port: "https", As: 443}}
		if sv.Name == "" {
			sv.Name = sv.Type
			if sv.HostPort != nil && sv.HostPort.IP != "" {
				sv.Name = "on-" + sv.HostPort.IP
			}
		}
		s.Spec.Services = append(s.Spec.Services, sv)
	}
}
func workerExternal() func(*v1.Silo) { return svc(v1.SiloService{Type: v1.ServiceHostPort}) }
func hostPortIP(ip string) func(*v1.Silo) {
	return svc(v1.SiloService{Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: ip}})
}
func hostPortOwn() func(*v1.Silo) {
	return svc(v1.SiloService{Name: "own", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{Own: true}})
}
func balancer(p string) func(*v1.Silo) {
	return svc(v1.SiloService{Name: "shop-" + p, Type: v1.ServiceLoadBalancer, LoadBalancer: &v1.LoadBalancerSpec{Provider: p}})
}
func egressFrom(ip string) func(*v1.Silo) {
	return func(s *v1.Silo) { s.Spec.Network.Egress.Source = &v1.EgressSource{IP: ip} }
}

// hostIP is an IP of type Host on address, held by holder (nil: nobody).
func hostIP(name, address string, holder *v1.Silo) *v1.IP {
	return ipObj(name, v1.IPTypeHost, func(x *v1.IP) {
		x.Spec.HostAddress = address
		if holder != nil {
			boundTo(holder)(x)
		}
	})
}

// providerIP is an IP of type Provider of p in region, reserved, held by holder.
func providerIP(name, p, region string, holder *v1.Silo, f ...func(*v1.IP)) *v1.IP {
	return ipObj(name, v1.IPTypeProvider, func(x *v1.IP) {
		x.Spec.Provider, x.Spec.Region = p, region
		x.Status.Address, x.Status.Region = "203.0.113.50", region
		if holder != nil {
			boundTo(holder)(x)
		}
		for _, o := range f {
			o(x)
		}
	})
}

// fits are the hosts a silo can go to: each one scheduled alone.
func fits(s *v1.Silo, hs []*v1.Host, env Env) []string {
	env.Hosts = hs
	var out []string
	for _, h := range hs {
		if d, _ := ScheduleIn(s, []*v1.Host{h}, nil, env); d.Host == h.Name {
			out = append(out, h.Name)
		}
	}
	sort.Strings(out)
	return out
}

// Placement follows the address: each way in alone, then several together (they intersect).
func TestPlacementFollowsTheAddress(t *testing.T) {
	type tc struct {
		name     string
		silo     *v1.Silo
		ips      func(*v1.Silo) []*v1.IP
		fits     string            // the hosts it can go to, sorted, comma-separated
		excluded map[string]string // host → its reason (substring)
	}
	// Cases on other machines than cluster()'s.
	machines := map[string]func([]*v1.Host) []*v1.Host{
		"ip type Provider that stays on its host": func(hs []*v1.Host) []*v1.Host { // lin2 and lin4 are sticky's machines
			hs[3].Status.Provider.Name = "sticky"
			return append(hs, host("lin4", provider("sticky", "us-ord")))
		},
	}
	held := func(f func(s *v1.Silo) []*v1.IP) func(*v1.Silo) []*v1.IP { return f }
	none := held(func(*v1.Silo) []*v1.IP { return nil })
	cases := []tc{
		{"worker external: any host with an external IP", web("a", workerExternal()), none,
			"bm1,bm2,lin1,lin2,lin3", map[string]string{"home": "no external IP, which port 443/TCP asks for"}},
		{"internal only: anywhere", web("a", svc(v1.SiloService{Name: "metrics"})), none, "bm1,bm2,home,lin1,lin2,lin3", nil},
		{"ip type Host: pinned to that host", web("a", hostPortIP("mail")),
			held(func(s *v1.Silo) []*v1.IP { return []*v1.IP{hostIP("mail", "mail", s)} }),
			"bm1", map[string]string{"bm2": "IP mail is host bm1's address", "lin1": "IP mail is host bm1's address"}},
		{"ip type Provider: the provider's machines in its region", web("a", hostPortIP("edge")),
			held(func(s *v1.Silo) []*v1.IP { return []*v1.IP{providerIP("edge", "linode", "us-ord", s)} }),
			"lin1,lin2", map[string]string{"lin3": "IP edge is linode's, in us-ord", "bm1": "IP edge is linode's, in us-ord"}},
		{"ip type Provider reaching anywhere", web("a", hostPortIP("any")),
			held(func(s *v1.Silo) []*v1.IP { return []*v1.IP{providerIP("any", "anycast", "", s)} }),
			"bm1,bm2,home,lin1,lin2,lin3", nil},
		{"ip type Provider that stays on its host", web("a", hostPortIP("st")),
			held(func(s *v1.Silo) []*v1.IP {
				return []*v1.IP{providerIP("st", "sticky", "us-ord", s, func(x *v1.IP) { x.Status.Host = "lin2" })}
			}),
			"lin2", map[string]string{"lin1": "IP st stays on host lin2 (provider sticky's addresses don't move)", "lin4": "stays on host lin2"}},
		{"egress.source ip: placed by it too", web("a", workerExternal(), egressFrom("mail")),
			held(func(s *v1.Silo) []*v1.IP { return []*v1.IP{hostIP("mail", "mail", s)} }), "bm1", nil},
		{"a load balancer: the provider's machines in the regions it serves", web("a", balancer("linode")), none,
			"lin1,lin2,lin3", map[string]string{"bm1": "service shop-linode: provider linode's balancer needs a linode machine"}},
		{"a balancer that exists: its region", web("a", balancer("linode"), func(s *v1.Silo) {
			s.Status.Host, s.Status.Service.LoadBalancerIP = "lin1", "172.236.9.9"
		}), none, "lin1,lin2", map[string]string{"lin3": "service shop-linode: provider linode's balancer is in region us-ord"}},
		// Several ways in: the intersection.
		{"worker external and a Host IP: that host", web("a", workerExternal(), hostPortIP("mail")),
			held(func(s *v1.Silo) []*v1.IP { return []*v1.IP{hostIP("mail", "mail", s)} }), "bm1", nil},
		{"a Provider IP and a balancer: its region", web("a", hostPortIP("edge"), balancer("linode")),
			held(func(s *v1.Silo) []*v1.IP { return []*v1.IP{providerIP("edge", "linode", "ca-central", s)} }), "lin3", nil},
		{"a balancer and an address reaching anywhere: the balancer's", web("a", hostPortIP("any"), balancer("linode")),
			held(func(s *v1.Silo) []*v1.IP { return []*v1.IP{providerIP("any", "anycast", "", s)} }), "lin1,lin2,lin3", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := Env{IPs: c.ips(c.silo), Networking: nets}
			hs := cluster()
			if m := machines[c.name]; m != nil {
				hs = m(hs)
			}
			if got := strings.Join(fits(c.silo, hs, env), ","); got != c.fits {
				t.Fatalf("fits %q, want %q", got, c.fits)
			}
			env.Hosts = hs
			d, _ := ScheduleIn(c.silo, hs, nil, env)
			for h, why := range c.excluded {
				if !strings.Contains(d.Excluded[h], why) {
					t.Errorf("%s excluded for %q, want %q", h, d.Excluded[h], why)
				}
			}
		})
	}
}

// Could work later: unschedulable with the reason, for the whole silo; never refused here.
func TestUnschedulableUntilItCanWork(t *testing.T) {
	quota := func(x *v1.IP) {
		x.Status.Address = ""
		x.Status.Conditions = []meta.Condition{{Type: "Reserved", Status: meta.ConditionFalse, Message: "linode: IP quota reached for the account"}}
	}
	for _, c := range []struct {
		name  string
		silo  *v1.Silo
		hosts []*v1.Host
		ips   func(*v1.Silo) []*v1.IP
		want  string
	}{
		{"an IP that doesn't exist yet", web("a", hostPortIP("mail")), cluster(), func(*v1.Silo) []*v1.IP { return nil },
			"IP mail doesn't exist"},
		{"an IP held by another silo", web("a", hostPortIP("mail")), cluster(), func(*v1.Silo) []*v1.IP {
			return []*v1.IP{hostIP("mail", "mail", web("b"))}
		}, "IP mail is held by silo/b: one holder at a time; it's this silo's once that one lets it go"},
		{"an IP held by another, as the IP controller says it", web("a", hostPortIP("mail")), cluster(), func(s *v1.Silo) []*v1.IP {
			x := hostIP("mail", "mail", web("b"))
			x.Status.Waiting = []v1.IPWaiting{{Holder: "silo/a", UID: s.UID, Reason: "IP mail is held by silo/b: one holder at a time; it's yours once that one lets it go"}}
			return []*v1.IP{x}
		}, "IP mail is held by silo/b: one holder at a time; it's yours once that one lets it go"},
		{"an IP not bound yet", web("a", hostPortIP("mail")), cluster(), func(*v1.Silo) []*v1.IP { return []*v1.IP{hostIP("mail", "mail", nil)} },
			"waiting for IP mail to be bound to it"},
		{"a host address nobody has yet", web("a", hostPortIP("mail")), cluster(), func(s *v1.Silo) []*v1.IP { return []*v1.IP{hostIP("mail", "mail3", s)} },
			"no host has address mail3 (kvoadm host addresses HOST add mail3 ADDRESS)"},
		{"the provider's quota", web("a", hostPortIP("edge")), cluster(), func(s *v1.Silo) []*v1.IP {
			return []*v1.IP{providerIP("edge", "linode", "us-ord", s, quota)}
		}, "waiting for provider linode to reserve IP edge's address: linode: IP quota reached for the account"},
		{"no address yet", web("a", hostPortIP("edge")), cluster(), func(s *v1.Silo) []*v1.IP {
			return []*v1.IP{providerIP("edge", "linode", "us-ord", s, func(x *v1.IP) { x.Status.Address = "" })}
		}, "waiting for provider linode to reserve IP edge's address"},
		{"a provider not installed (yet)", web("a", balancer("linode-work")), cluster(), func(*v1.Silo) []*v1.IP { return nil },
			"service shop-linode-work: provider linode-work: no such provider: installed are anycast, linode, old, sticky"},
		{"a provider that declares nothing", web("a", balancer("old")), cluster(), func(*v1.Silo) []*v1.IP { return nil },
			"service shop-old: provider old declares nothing about networking (built against an sdk before wire revision 2), so Kevaso can't tell whether it makes IPs or load balancers: upgrade the plugin"},
		{"no worker with an external IP", web("a", workerExternal()),
			hosts(host("home1", func(h *v1.Host) { h.Spec.InternalIP = "192.168.1.5" }), host("home2")),
			func(*v1.Silo) []*v1.IP { return nil },
			"no worker with an external IP, which port 443/TCP asks for (hostPort: worker external): it goes ahead once one has one"},
		{"a Mac without a public IP", web("a", workerExternal(), withRuntime(v1.RuntimeTart)),
			hosts(mac("mini"), mac("studio")), func(*v1.Silo) []*v1.IP { return nil },
			"no Mac with a public IP, which port 443/TCP asks for (hostPort: worker external): it goes ahead once one has one"},
		{"two Host IPs on two hosts", web("a", hostPortIP("mail"), egressFrom("mail2")), cluster(), func(s *v1.Silo) []*v1.IP {
			return []*v1.IP{hostIP("mail", "mail", s), hostIP("mail2", "mail2", s)}
		}, "its ways in can't meet: IP mail is host bm1's address, and IP mail2 is host bm2's address: no host has both"},
		{"a Host IP outside a balancer's reach", web("a", hostPortIP("mail"), balancer("linode")), cluster(), func(s *v1.Silo) []*v1.IP {
			return []*v1.IP{hostIP("mail", "mail", s)}
		}, "its ways in can't meet: IP mail is host bm1's address, and service shop-linode: provider linode's balancer needs a linode machine"},
		{"Provider IPs in two regions", web("a", hostPortIP("e1"), egressFrom("e2")), cluster(), func(s *v1.Silo) []*v1.IP {
			return []*v1.IP{providerIP("e1", "linode", "us-ord", s), providerIP("e2", "linode", "ca-central", s)}
		}, "its ways in can't meet: IP e1 is linode's, in us-ord, and IP e2 is linode's, in ca-central: no region is both"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d, err := ScheduleIn(c.silo, c.hosts, nil, Env{IPs: c.ips(c.silo), Networking: nets})
			if err != nil || d.Host != "" || d.Reason != c.want || d.Message() != c.want {
				t.Fatalf("got %+v %v\nwant reason %q", d, err, c.want)
			}
		})
	}
	// Hosts excluded for different reasons: no summary, each host says its own.
	d, _ := ScheduleIn(web("a", workerExternal()), hosts(host("home"), host("down", notReady())), nil, Env{})
	if d.Reason != "" || d.Excluded["down"] != "host not Ready" || !strings.HasPrefix(d.Message(), "no host fits (") {
		t.Fatalf("mixed: %+v", d)
	}
}

// own: a SiloSet instance takes its IPSet member by ordinal, placed by the member's type.
func TestOwnPlacement(t *testing.T) {
	set := &v1.SiloSet{}
	set.Name, set.Namespace, set.Spec.IPs = "edge", "dev", "edge-ips"
	instance := func(i int, ways ...func(*v1.Silo)) *v1.Silo {
		s := web(v1.InstanceName("edge", i), append([]func(*v1.Silo){hostPortOwn()}, ways...)...)
		s.Labels = map[string]string{v1.LabelSiloSet: "edge"}
		return s
	}
	static := &v1.IPSet{Spec: v1.IPSetSpec{Type: v1.IPSetStatic, Members: []v1.IPSetMember{{IP: "a0"}, {HostAddress: "mail"}}}}
	static.Name, static.Namespace = "edge-ips", "dev"
	dynamic := &v1.IPSet{Spec: v1.IPSetSpec{Type: v1.IPSetDynamic, Provider: "linode", Region: "ca-central", Max: 2}}
	dynamic.Name, dynamic.Namespace = "edge-ips", "dev"
	member := func(name string, i int, holder *v1.Silo) *v1.IP {
		return providerIP(name, "linode", "ca-central", holder, func(x *v1.IP) {
			x.Labels = map[string]string{v1.LabelIPSet: "edge-ips", v1.LabelIPSetOrdinal: string(rune('0' + i))}
		})
	}
	e0, e1, e2 := instance(0), instance(1), instance(2)
	for _, c := range []struct {
		name   string
		silo   *v1.Silo
		ipset  *v1.IPSet
		sets   []*v1.SiloSet
		ips    []*v1.IP
		fits   string // "" : nowhere, then reason
		reason string
	}{
		{"static: member 0 is an IP of type Provider", e0, static, []*v1.SiloSet{set},
			[]*v1.IP{providerIP("a0", "linode", "us-ord", e0)}, "lin1,lin2", ""},
		{"static: member 1 is a host address", e1, static, []*v1.SiloSet{set}, nil, "bm1", ""},
		{"static: no member 2", e2, static, []*v1.SiloSet{set}, nil, "",
			"no free member in IPSet edge-ips: instance edge-2 takes member 2, and it has 2 (add one at the end)"},
		{"static: member 0 held by another", e0, static, []*v1.SiloSet{set},
			[]*v1.IP{providerIP("a0", "linode", "us-ord", web("old"))}, "",
			"IP a0 (IPSet edge-ips, member 0) is held by silo/old: one holder at a time; it's this silo's once that one lets it go"},
		{"dynamic: its member reserved and held", e0, dynamic, []*v1.SiloSet{set},
			[]*v1.IP{member("edge-ips-0", 0, e0)}, "lin3", ""},
		{"dynamic: its member not reserved yet", e1, dynamic, []*v1.SiloSet{set}, nil, "",
			"waiting for IPSet edge-ips to reserve member 1 (IP edge-ips-1)"},
		{"dynamic: past max", e2, dynamic, []*v1.SiloSet{set}, nil, "",
			"no free member in IPSet edge-ips: instance edge-2 takes member 2, and its max is 2"},
		{"the set's status names the member", e1, func() *v1.IPSet {
			x := *dynamic
			x.Status.Members = []v1.IPSetMemberStatus{{Ordinal: 1, IP: "kept-1"}}
			return &x
		}(), []*v1.SiloSet{set}, []*v1.IP{providerIP("kept-1", "linode", "us-ord", e1)}, "lin1,lin2", ""},
		{"no SiloSet to read: the labelled member it holds", e0, nil, nil, []*v1.IP{member("edge-ips-0", 0, e0)}, "lin3", ""},
		{"no SiloSet, no member", e0, nil, nil, nil, "", "waiting for SiloSet edge (own takes its IPSet's member 0)"},
		{"no IPSet", e0, nil, []*v1.SiloSet{set}, nil, "", "IPSet edge-ips doesn't exist"},
		{"not an instance", web("solo", hostPortOwn()), static, []*v1.SiloSet{set}, nil, "",
			"own: solo isn't a SiloSet instance, so it has no IPSet member"},
		{"own and worker external: intersect", instance(0, workerExternal()), dynamic, []*v1.SiloSet{set},
			[]*v1.IP{member("edge-ips-0", 0, instance(0))}, "lin3", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			env := Env{IPs: c.ips, SiloSets: c.sets, Networking: nets}
			if c.ipset != nil {
				env.IPSets = []*v1.IPSet{c.ipset}
			}
			if c.fits != "" {
				if got := strings.Join(fits(c.silo, cluster(), env), ","); got != c.fits {
					t.Fatalf("fits %q, want %q", got, c.fits)
				}
				return
			}
			d, _ := ScheduleIn(c.silo, cluster(), nil, env)
			if d.Host != "" || d.Reason != c.reason {
				t.Fatalf("got %+v\nwant %q", d, c.reason)
			}
		})
	}
	// Egress and the host's address follow own too.
	e0.Status.Host = "bm1"
	env := Env{IPSets: []*v1.IPSet{static}, SiloSets: []*v1.SiloSet{set}, Networking: nets, Hosts: cluster(),
		IPs: []*v1.IP{hostIP("m", "mail", e1)}}
	e1.Spec.Network.Egress.Source = &v1.EgressSource{Own: true}
	env.IPs[0].Labels = map[string]string{v1.LabelIPSet: "edge-ips", v1.LabelIPSetOrdinal: "1"}
	env.IPs[0].Status.Address, env.IPs[0].Status.Host = "198.51.100.17", "bm1"
	st, err := ServiceStatus(e1, cluster()[0], nil, env)
	if err != nil || st.EgressIP != "198.51.100.17" || len(st.HostAddresses) != 1 || st.HostAddresses[0] != "198.51.100.17" {
		t.Fatalf("own egress: %+v %v", st, err)
	}
}

// Moves stay within the area; "can move: … (why)" says where, for kvo describe silo.
func TestCanMove(t *testing.T) {
	small := func(hs []*v1.Host, name string) {
		for _, h := range hs {
			if h.Name == name {
				h.Status.Allocatable.Memory = "1Gi"
			}
		}
	}
	for _, c := range []struct {
		name  string
		silo  *v1.Silo
		ips   func(*v1.Silo) []*v1.IP
		hosts func([]*v1.Host)
		want  string
	}{
		{"worker: anywhere", web("a", workerExternal(), on("bm1")), func(*v1.Silo) []*v1.IP { return nil }, nil,
			"can move: to bm2, lin1, lin2, lin3 (anywhere: its ways in follow the worker)"},
		{"a Host IP: pinned", web("a", hostPortIP("mail"), on("bm1")),
			func(s *v1.Silo) []*v1.IP { return []*v1.IP{hostIP("mail", "mail", s)} }, nil,
			"can move: no (pinned to host bm1: IP mail is host bm1's address)"},
		{"a Provider IP: within its region", web("a", hostPortIP("edge"), on("lin1")),
			func(s *v1.Silo) []*v1.IP { return []*v1.IP{providerIP("edge", "linode", "us-ord", s)} }, nil,
			"can move: to lin2 (within linode machines in us-ord: IP edge is linode's, in us-ord)"},
		{"within its region, but full", web("a", hostPortIP("edge"), on("lin1")),
			func(s *v1.Silo) []*v1.IP { return []*v1.IP{providerIP("edge", "linode", "us-ord", s)} },
			func(hs []*v1.Host) { small(hs, "lin2") },
			"can move: no other host fits now (within linode machines in us-ord: IP edge is linode's, in us-ord; lin2: not enough memory (needs 4Gi))"},
		{"a balancer: its provider's machines", web("a", balancer("linode"), on("lin1")), func(*v1.Silo) []*v1.IP { return nil }, nil,
			"can move: to lin2, lin3 (within linode machines in us-ord, ca-central: service shop-linode: provider linode's balancer reaches linode machines in us-ord, ca-central)"},
		{"not now", web("a", hostPortIP("mail"), on("bm1")), func(*v1.Silo) []*v1.IP { return nil }, nil,
			"can move: not now (IP mail doesn't exist)"},
		{"nowhere", web("a", hostPortIP("mail"), egressFrom("mail2"), on("bm1")),
			func(s *v1.Silo) []*v1.IP { return []*v1.IP{hostIP("mail", "mail", s), hostIP("mail2", "mail2", s)} }, nil,
			"can move: nowhere (IP mail is host bm1's address, and IP mail2 is host bm2's address: no host has both)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			hs := cluster()
			if c.hosts != nil {
				c.hosts(hs)
			}
			m, err := CanMove(c.silo, hs, nil, Env{IPs: c.ips(c.silo), Networking: nets})
			if err != nil || m.String() != c.want {
				t.Fatalf("%v\n got %s\nwant %s", err, m, c.want)
			}
		})
	}
	// The move path: out of reach refused with the reason, within it allowed.
	s := web("a", hostPortIP("edge"), on("lin1"))
	env := Env{IPs: []*v1.IP{providerIP("edge", "linode", "us-ord", s)}, Networking: nets}
	hs := cluster()
	if why, err := MoveTo(s, hs[4], hs, nil, env); err != nil || why != "IP edge is linode's, in us-ord" {
		t.Fatalf("to lin3: %q %v", why, err)
	}
	if why, err := MoveTo(s, hs[3], hs, nil, env); err != nil || why != "" {
		t.Fatalf("to lin2: %q %v", why, err)
	}
}

// status.movable: yes or no and why, from the ways in and the data's own summary.
func TestMovable(t *testing.T) {
	none := func(*v1.Silo) []*v1.IP { return nil }
	for _, c := range []struct {
		name string
		silo *v1.Silo
		ips  func(*v1.Silo) []*v1.IP
		data string
		want string
	}{
		{"worker", web("a", workerExternal(), on("bm1")), none, "Anywhere", "yes: any worker"},
		{"no data summary yet", web("a", on("bm1")), none, "", "yes: any worker"},
		{"a Provider IP", web("a", hostPortIP("api-edge"), on("lin1")),
			func(s *v1.Silo) []*v1.IP { return []*v1.IP{providerIP("api-edge", "linode", "us-ord", s)} }, "Anywhere",
			"yes: within linode/us-ord (IP api-edge)"},
		{"a Host IP", web("a", hostPortIP("mail"), on("bm1")),
			func(s *v1.Silo) []*v1.IP { return []*v1.IP{hostIP("mail", "mail", s)} }, "Anywhere",
			"no: pinned to bm1 (IP mail is that host's address)"},
		{"a balancer", web("a", balancer("linode"), on("lin1")), none, "Anywhere",
			"yes: within linode/us-ord or linode/ca-central (service shop-linode's balancer)"},
		{"a balancer and volumes in a region", web("a", balancer("linode"), on("lin1")), none, "Region (us-ord)",
			"yes: within linode/us-ord (service shop-linode's balancer, its volumes)"},
		{"volumes in a region, worker", web("a", workerExternal(), on("bm1")), none, "Region (us-ord)",
			"yes: within region us-ord (its volumes)"},
		{"volumes elsewhere than the address", web("a", hostPortIP("e"), on("lin3")),
			func(s *v1.Silo) []*v1.IP { return []*v1.IP{providerIP("e", "linode", "ca-central", s)} }, "Region (us-ord)",
			"no: its volumes are in us-ord, and IP e in ca-central"},
		{"disks on the host", web("a", workerExternal(), on("bm2")), none, "Pinned (bm2)", "no: pinned to bm2 (its disks stay there)"},
		{"recreate", web("a", workerExternal(), on("bm2")), none, "Recreate", "yes: any worker, without its data (onHostLoss: Recreate)"},
		{"waiting", web("a", hostPortIP("mail"), on("bm1")), none, "Anywhere", "not now: IP mail doesn't exist"},
		{"two hosts", web("a", hostPortIP("mail"), egressFrom("mail2"), on("bm1")),
			func(s *v1.Silo) []*v1.IP { return []*v1.IP{hostIP("mail", "mail", s), hostIP("mail2", "mail2", s)} }, "Anywhere",
			"no: IP mail is host bm1's address, and IP mail2 is host bm2's address: no host has both"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := Movable(c.silo, Env{IPs: c.ips(c.silo), Networking: nets, Hosts: cluster()}, c.data); got != c.want {
				t.Fatalf("\n got %s\nwant %s", got, c.want)
			}
		})
	}
}
