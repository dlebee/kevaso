package scheduler

import (
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

func exposed(name, host string, f func(*v1.Silo)) *v1.Silo {
	s := silo(name)
	s.Spec.Service = &v1.SiloService{Ports: []v1.ServicePort{{Name: "p2p", Port: 30303}, {Name: "disc", Port: 30303, Protocol: "UDP"}, {Name: "rpc", Port: 8545}},
		Expose: v1.ExposeHostPort, HostPort: &v1.HostPortSpec{Ports: []string{"p2p", "disc"}}}
	s.Status.Host = host
	if f != nil {
		f(s)
	}
	return s
}

func ipObj(name, class string, f func(*v1.IP)) *v1.IP {
	x := &v1.IP{}
	x.Name, x.Namespace, x.UID, x.Spec.Class = name, "dev", "ip-"+name, class
	if f != nil {
		f(x)
	}
	return x
}

func boundTo(s *v1.Silo) func(*v1.IP) {
	return func(x *v1.IP) { x.Status.BoundTo = []v1.IPHolder{{Holder: v1.HolderSiloPrefix + s.Name, UID: s.UID}} }
}

func TestHostPortScheduling(t *testing.T) {
	behind := host("home", func(h *v1.Host) { h.Spec.Network.BehindNAT = true })
	// Behind NAT: no.
	d, _ := Schedule(exposed("a", "", nil), hosts(behind), nil)
	if d.Host != "" || !strings.Contains(d.Excluded["home"], "behind NAT") {
		t.Fatalf("behind NAT: %+v", d)
	}
	// The same port on the same host goes elsewhere; a private port of the same number doesn't count.
	first := exposed("first", "metal-1", nil)
	d, _ = Schedule(exposed("second", "", nil), hosts(host("metal-1"), host("metal-2")), []*v1.Silo{first})
	if d.Host != "metal-2" || !strings.Contains(d.Excluded["metal-1"], "port 30303/TCP already open for dev/first") {
		t.Fatalf("conflict: %+v", d)
	}
	rpcOnly := exposed("rpc", "", func(s *v1.Silo) {
		s.Spec.Service.Ports = []v1.ServicePort{{Name: "x", Port: 8545}, {Name: "p", Port: 30303}}
		s.Spec.Service.HostPort.Ports = []string{"x"}
	})
	if d, _ = Schedule(rpcOnly, hosts(host("metal-1")), []*v1.Silo{first}); d.Host != "metal-1" {
		t.Fatalf("8545 is private on first: %+v", d)
	}
	// Private services don't care about NAT.
	private := exposed("p", "", func(s *v1.Silo) { s.Spec.Service.Expose, s.Spec.Service.HostPort = "", nil })
	if d, _ = Schedule(private, hosts(behind), nil); d.Host != "home" {
		t.Fatalf("private silo behind NAT: %+v", d)
	}
}

func TestIPScheduling(t *testing.T) {
	lb := func(name, class string) *v1.Silo {
		return exposed(name, "", func(s *v1.Silo) {
			s.UID = "uid-" + name
			s.Spec.Service.Expose, s.Spec.Service.HostPort = v1.ExposeLoadBalancer, nil
			s.Spec.Service.LoadBalancer = &v1.LoadBalancerSpec{Class: class, IP: "eth"}
			s.Spec.Network.Egress.Source = v1.EgressSameAsService
		})
	}
	m1 := host("metal-1", func(h *v1.Host) {
		h.Spec.Address = "198.51.100.10"
		h.Spec.Network.Addresses = []string{"198.51.100.16/30"}
	})
	m2 := host("metal-2")
	hs := hosts(m1, m2)
	a := lb("a", v1.LBIPPool)
	// Not made yet, held by another, not bound yet: nowhere.
	if d, _ := Schedule(a, hs, nil); !strings.Contains(d.Excluded["metal-1"], "IP eth doesn't exist") {
		t.Fatalf("no IP: %+v", d)
	}
	other := ipObj("eth", v1.LBIPPool, func(x *v1.IP) {
		x.Status.BoundTo = []v1.IPHolder{{Holder: "silo/b", UID: "uid-b"}}
		x.Status.Waiting = []v1.IPWaiting{{Holder: "silo/a", UID: "uid-a", Reason: "IP eth is held by silo/b"}}
	})
	if d, _ := Schedule(a, hs, nil, other); !strings.Contains(d.Excluded["metal-1"], "held by silo/b") {
		t.Fatalf("held: %+v", d)
	}
	if d, _ := Schedule(a, hs, nil, ipObj("eth", v1.LBIPPool, nil)); !strings.Contains(d.Excluded["metal-1"], "waiting for IP eth to be bound") {
		t.Fatalf("unbound: %+v", d)
	}
	// Bound, not reserved yet: a host with a free extra address.
	free := ipObj("eth", v1.LBIPPool, boundTo(a))
	if d, _ := Schedule(a, hs, nil, free); d.Host != "metal-1" || !strings.Contains(d.Excluded["metal-2"], "no free extra address") {
		t.Fatalf("free address: %+v", d)
	}
	// Reserved: the host its address is routed to, only.
	res := ipObj("eth", v1.LBIPPool, func(x *v1.IP) { boundTo(a)(x); x.Status.Host, x.Status.Address = "metal-1", "198.51.100.17" })
	if d, _ := Schedule(a, hs, nil, res); d.Host != "metal-1" || !strings.Contains(d.Excluded["metal-2"], "routed to metal-1") {
		t.Fatalf("reserved: %+v", d)
	}
	a.Status.Host = "metal-1"
	st, err := ServiceStatus(a, m1, nil, Env{IPs: []*v1.IP{res}})
	if err != nil || st.IP != "eth" || st.PublicIP != "198.51.100.17" || st.EgressIP != "198.51.100.17" || st.EgressNote != "" ||
		len(st.HostAddresses) != 1 || st.HostAddresses[0] != "198.51.100.17" || st.Name != "a.dev.kevaso" {
		t.Fatalf("a: %+v %v", st, err)
	}
	// A plugin's IP: in its region only.
	p := lb("p", "fake-ip")
	pip := ipObj("eth", "fake-ip", func(x *v1.IP) { boundTo(p)(x); x.Status.Region, x.Status.Address = "ca-central", "203.0.113.100" })
	inRegion := host("lin-1", func(h *v1.Host) { h.Status.Provider = &v1.HostProvider{Name: "fake", Region: "ca-central"} })
	away := host("lin-2", func(h *v1.Host) { h.Status.Provider = &v1.HostProvider{Name: "fake", Region: "us-east"} })
	env := Env{IPs: []*v1.IP{pip}, Classes: map[string]Class{"fake-ip": {Plugin: "fake", Reserve: true, SendsFrom: true, Follows: "region"}}}
	if d, _ := ScheduleIn(p, hosts(inRegion, away), nil, env); d.Host != "lin-1" || !strings.Contains(d.Excluded["lin-2"], "in ca-central") {
		t.Fatalf("region: %+v", d)
	}
	env.Classes["fake-ip"] = Class{Plugin: "fake", Follows: "global"}
	if d, _ := ScheduleIn(p, hosts(away), nil, env); d.Host != "lin-2" {
		t.Fatalf("global: %+v", d)
	}
}

// The table of design §7.2b: can a silo use the same IP out as in?
func TestEgressTable(t *testing.T) {
	h := host("metal-1", func(h *v1.Host) { h.Spec.Address = "198.51.100.10" })
	classes := map[string]Class{
		"fake-ip": {Plugin: "fake", Reserve: true, SendsFrom: true, Exclusive: true},
		"fake-lb": {Plugin: "fake", NodePorts: true},
	}
	mk := func(expose, class, source string) *v1.Silo {
		s := exposed("n", "metal-1", nil)
		s.UID = "uid-n"
		s.Spec.Service.Expose = expose
		if expose != v1.ExposeHostPort {
			s.Spec.Service.HostPort = nil
		}
		if expose == v1.ExposeLoadBalancer {
			s.Spec.Service.LoadBalancer = &v1.LoadBalancerSpec{Class: class}
		}
		s.Spec.Network.Egress.Source = source
		return s
	}
	for _, c := range []struct {
		name      string
		silo      *v1.Silo
		in        string
		ip        *v1.IP
		want      string
		note      string // substring; "" means no note
		sameInOut bool
	}{
		{"hostPort, host", mk(v1.ExposeHostPort, "", ""), "198.51.100.10", nil, "198.51.100.10", "", true},
		{"hostPort, sameAsService", mk(v1.ExposeHostPort, "", v1.EgressSameAsService), "198.51.100.10", nil, "198.51.100.10", "", true},
		{"worker-ip, sameAsService", mk(v1.ExposeLoadBalancer, v1.LBWorkerIP, v1.EgressSameAsService), "198.51.100.10", nil, "198.51.100.10", "", true},
		{"ip-pool, sameAsService", mk(v1.ExposeLoadBalancer, v1.LBIPPool, v1.EgressSameAsService), "198.51.100.17", nil, "198.51.100.17", "", true},
		{"ip-pool, host", mk(v1.ExposeLoadBalancer, v1.LBIPPool, ""), "198.51.100.17", nil, "198.51.100.10", "sameAsService sends from 198.51.100.17", false},
		{"announced, sameAsService", mk(v1.ExposeLoadBalancer, "fake-ip", v1.EgressSameAsService), "203.0.113.100",
			ipObj("n", "fake-ip", func(x *v1.IP) { x.Status.Address = "203.0.113.100" }), "203.0.113.100", "", true},
		{"announced, sameAsService, address not yet", mk(v1.ExposeLoadBalancer, "fake-ip", v1.EgressSameAsService), "", nil, "198.51.100.10", "waiting for IP n", false},
		{"balancer in front, sameAsService: never its address", mk(v1.ExposeLoadBalancer, "fake-lb", v1.EgressSameAsService), "198.51.100.200", nil,
			"198.51.100.10", "on no host, so nothing can send from it", false},
		{"balancer in front, host", mk(v1.ExposeLoadBalancer, "fake-lb", ""), "198.51.100.200", nil, "198.51.100.10", "balancer's, on no host", false},
		{"no plugin serves the class: not applied", mk(v1.ExposeLoadBalancer, "gone-lb", v1.EgressSameAsService), "198.51.100.200", nil,
			"198.51.100.10", "not applied", false},
		{"private", mk(v1.ExposePrivate, "", ""), "", nil, "198.51.100.10", "", false},
	} {
		var held *v1.IP
		if c.ip != nil {
			held = c.ip
		}
		out, note := Egress(c.silo, h, c.in, held, nil, classes)
		if out != c.want || (c.note == "" && note != "") || !strings.Contains(note, c.note) {
			t.Errorf("%s: out %q (%s), want %q (%q)", c.name, out, note, c.want, c.note)
		}
		if c.sameInOut != (out == c.in) {
			t.Errorf("%s: in %s out %s, same %v", c.name, c.in, out, c.sameInOut)
		}
	}
	// pool: its own IP's address out, whatever it's reached on.
	s := mk(v1.ExposeHostPort, "", v1.EgressPool)
	s.Spec.Network.Egress.IP = "out"
	own := ipObj("out", v1.LBIPPool, func(x *v1.IP) { x.Status.Address, x.Status.Host = "198.51.100.18", "metal-1" })
	if out, note := Egress(s, h, "198.51.100.10", nil, own, classes); out != "198.51.100.18" || !strings.Contains(note, "IP out's own address") {
		t.Errorf("pool: %s %s", out, note)
	}
}

func TestServiceStatusHostPort(t *testing.T) {
	h := host("metal-1", func(h *v1.Host) { h.Spec.Address = "198.51.100.10" })
	s := exposed("n", "metal-1", func(s *v1.Silo) { s.Spec.Network.Egress.Source = v1.EgressSameAsService })
	st, _ := ServiceStatus(s, h, nil, Env{})
	if st.PublicIP != "198.51.100.10" || st.EgressIP != "198.51.100.10" || len(st.HostAddresses) != 0 {
		t.Fatalf("%+v", st)
	}
	plain := silo("plain")
	if st, _ := ServiceStatus(plain, h, nil, Env{}); st.PublicIP != "" || st.EgressIP != "198.51.100.10" {
		t.Fatalf("private: %+v", st)
	}
	if st, _ := ServiceStatus(plain, host("home", func(h *v1.Host) { h.Spec.Network.BehindNAT = true }), nil, Env{}); st.EgressIP != "" {
		t.Fatalf("behind NAT there's no known egress address: %+v", st)
	}
}
