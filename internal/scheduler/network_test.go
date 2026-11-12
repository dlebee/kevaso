package scheduler

import (
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

func exposed(name, host string, f func(*v1.Silo)) *v1.Silo {
	s := silo(name)
	s.Spec.Service = &v1.Service{Ports: []v1.ServicePort{{Name: "p2p", Port: 30303}, {Name: "disc", Port: 30303, Protocol: "UDP"}, {Name: "rpc", Port: 8545}},
		Expose: v1.ExposeHostPort, HostPort: &v1.HostPortSpec{Ports: []string{"p2p", "disc"}}}
	s.Status.Host = host
	if f != nil {
		f(s)
	}
	return s
}

func pool(name, host string, addrs ...string) *v1.IPPool {
	p := &v1.IPPool{}
	p.Name, p.Spec.Host, p.Spec.Addresses = name, host, addrs
	return p
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

func TestPoolScheduling(t *testing.T) {
	lb := func(name string) *v1.Silo {
		return exposed(name, "", func(s *v1.Silo) {
			s.Spec.Service.Expose, s.Spec.Service.HostPort = v1.ExposeLoadBalancer, nil
			s.Spec.Service.LoadBalancer = &v1.LoadBalancerSpec{Class: v1.LBIPPool, Pool: "extra"}
			s.Spec.Network.Egress.Source = v1.EgressSameAsService
		})
	}
	p := pool("extra", "metal-1", "198.51.100.16/30") // .17 and .18 usable
	hs := hosts(host("metal-1"), host("metal-2"))
	d, _ := Schedule(lb("a"), hs, nil, p)
	if d.Host != "metal-1" || !strings.Contains(d.Excluded["metal-2"], "routed to metal-1") {
		t.Fatalf("pool host: %+v", d)
	}
	// Two silos, same port, own addresses: both fit on metal-1.
	a := lb("a")
	a.Status.Host = "metal-1"
	st, err := ServiceStatus(a, hs[0], nil, []*v1.IPPool{p})
	if err != nil || st.PoolIP != "198.51.100.17" || st.PublicIP != "198.51.100.17" || st.EgressIP != "198.51.100.17" || st.Name != "a.dev.kevaso" {
		t.Fatalf("a: %+v %v", st, err)
	}
	a.Status.Service = st
	b := lb("b")
	if d, _ = Schedule(b, hs, []*v1.Silo{a}, p); d.Host != "metal-1" {
		t.Fatalf("b: %+v", d)
	}
	b.Status.Host = "metal-1"
	stB, _ := ServiceStatus(b, hs[0], []*v1.Silo{a}, []*v1.IPPool{p})
	if stB.PoolIP != "198.51.100.18" {
		t.Fatalf("b's address %+v", stB)
	}
	b.Status.Service = stB
	// A third: the pool is full.
	if d, _ = Schedule(lb("c"), hs, []*v1.Silo{a, b}, p); d.Host != "" || !strings.Contains(d.Excluded["metal-1"], "no free address") {
		t.Fatalf("full pool: %+v", d)
	}
	// Stable: a keeps its address on a later decision.
	if again, _ := ServiceStatus(a, hs[0], []*v1.Silo{a, b}, []*v1.IPPool{p}); again.PoolIP != "198.51.100.17" {
		t.Fatalf("a's address moved: %+v", again)
	}
	// A missing pool says so.
	if d, _ = Schedule(lb("d"), hs, nil); !strings.Contains(d.Excluded["metal-1"], "IPPool extra doesn't exist") {
		t.Fatalf("no pool: %+v", d)
	}
}

func TestServiceStatusHostPort(t *testing.T) {
	h := host("metal-1", func(h *v1.Host) { h.Spec.Address = "198.51.100.10" })
	s := exposed("n", "metal-1", func(s *v1.Silo) { s.Spec.Network.Egress.Source = v1.EgressSameAsService })
	st, _ := ServiceStatus(s, h, nil, nil)
	if st.PublicIP != "198.51.100.10" || st.EgressIP != "198.51.100.10" || st.PoolIP != "" {
		t.Fatalf("%+v", st)
	}
	plain := silo("plain")
	if st, _ := ServiceStatus(plain, h, nil, nil); st.PublicIP != "" || st.EgressIP != "198.51.100.10" {
		t.Fatalf("private: %+v", st)
	}
	if st, _ := ServiceStatus(plain, host("home", func(h *v1.Host) { h.Spec.Network.BehindNAT = true }), nil, nil); st.EgressIP != "" {
		t.Fatalf("behind NAT there's no known egress address: %+v", st)
	}
}

func TestPoolAddresses(t *testing.T) {
	got := PoolAddresses(pool("p", "h", "198.51.100.16/29", "198.51.100.40", "198.51.100.50/31"))
	var s []string
	for _, a := range got {
		s = append(s, a.String())
	}
	want := "198.51.100.17 198.51.100.18 198.51.100.19 198.51.100.20 198.51.100.21 198.51.100.22 198.51.100.40 198.51.100.50 198.51.100.51"
	if strings.Join(s, " ") != want {
		t.Fatalf("%s", strings.Join(s, " "))
	}
}
