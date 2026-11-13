package worker

import (
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

func TestNetworkView(t *testing.T) {
	h := &v1.Host{ObjectMeta: meta.ObjectMeta{Name: "metal-1"}, Spec: v1.HostSpec{InternalIP: "10.0.0.5", ExternalIP: "198.51.100.10"}}
	mk := func(name, host, addr string, f func(*v1.Silo)) *v1.Silo {
		s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "web3", UID: "u-" + name}}
		s.Status.Host, s.Status.SiloIP = host, addr
		if f != nil {
			f(s)
		}
		return s
	}
	node := mk("eth-node", "metal-1", "10.64.0.2", func(s *v1.Silo) {
		s.Spec.Ports = []v1.SiloPort{{Name: "p2p", Port: 30303}}
		s.Spec.Service = &v1.SiloService{Ports: []v1.ServicePort{{Port: "p2p", HostPort: []string{v1.NetworkExternal}}}}
		s.Spec.Network.Egress.Source = v1.EgressSameAsService
		s.Status.Service = v1.SiloServiceStatus{EgressIP: "198.51.100.10"}
	})
	plain := mk("plain", "metal-1", "10.64.0.3", func(s *v1.Silo) { s.Status.Service.EgressIP = "198.51.100.10" })
	pooled := mk("pooled", "metal-1", "10.64.0.4", func(s *v1.Silo) {
		s.Status.Service.HostAddresses = []string{"198.51.100.17"}
		s.Status.Service.LoadBalancerIP = "198.51.100.17"
	})
	elsewhere := mk("far", "metal-2", "10.64.9.2", nil)
	pending := mk("pending", "", "", nil)
	node.Spec.Grants = []string{"p2p-anywhere", "missing"}
	grants := []*v1.Grant{
		{ObjectMeta: meta.ObjectMeta{Name: "p2p-anywhere", Namespace: "web3"}, Spec: v1.GrantSpec{Egress: []v1.EgressRule{{To: "0.0.0.0/0", Ports: []string{"30303"}, Protocols: []string{"tcp", "udp"}}}}},
		{ObjectMeta: meta.ObjectMeta{Name: "p2p-anywhere", Namespace: "other"}, Spec: v1.GrantSpec{Egress: []v1.EgressRule{{To: "10.0.0.0/8"}}}},
	}
	v := NetworkView("metal-1", h, []*v1.Silo{node, plain, pooled, elsewhere, pending}, grants, map[string]map[string][]string{"web3/eth-node": {"p2p": {"web3/far"}}})
	if len(v.Local) != 3 || len(v.All) != 4 || v.ExternalIP.String() != "198.51.100.10" || v.InternalIP.String() != "10.0.0.5" {
		t.Fatalf("view %+v", v)
	}
	for _, s := range v.Local {
		if !strings.HasPrefix(s.Tap, "kvt") {
			t.Errorf("%s has no tap", s.Key)
		}
		switch s.Key {
		case "web3/eth-node":
			if s.LoadBalancerIP.IsValid() || s.EgressIP.String() != "198.51.100.10" || len(s.Paths["p2p"]) != 1 {
				t.Errorf("eth-node %+v", s)
			}
			if len(s.Egress) != 1 || s.Egress[0].Prefix.String() != "0.0.0.0/0" { // its namespace's grant only
				t.Errorf("eth-node egress %+v", s.Egress)
			}
		case "web3/pooled":
			if s.LoadBalancerIP.String() != "198.51.100.17" {
				t.Errorf("pooled load-balancer address %v", s.LoadBalancerIP)
			}
		case "web3/plain":
			if s.EgressIP.IsValid() { // source host: the masquerade does it
				t.Errorf("plain got an SNAT address")
			}
		}
	}
	if got := PoolAddresses("metal-1", []*v1.Silo{node, pooled, elsewhere}); len(got) != 1 || got[0] != "198.51.100.17" {
		t.Fatalf("pool addresses %v", got)
	}
}

func TestWithIngressPaths(t *testing.T) {
	api := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "api", Namespace: "payments"}, Spec: v1.SiloSpec{
		Ports:   []v1.SiloPort{{Name: "http", Port: 8080}},
		Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "http", AllowFrom: []string{"worker"}}}}}}
	other := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "other", Namespace: "payments"}, Spec: v1.SiloSpec{
		Ports:   []v1.SiloPort{{Name: "http", Port: 8080}},
		Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "http"}}}}}
	class := &v1.IngressClass{ObjectMeta: meta.ObjectMeta{Name: "public"}, Spec: v1.IngressClassSpec{Controller: v1.IngressController{Driver: "nginx", Silo: "ingress-public", Namespace: "kevaso-system"}}}
	ing := &v1.Ingress{ObjectMeta: meta.ObjectMeta{Name: "api", Namespace: "payments"}, Spec: v1.IngressSpec{IngressClass: "public",
		Rules: []v1.IngressRule{{Path: "/", Service: v1.IngressTarget{Name: "api", Port: "http"}}}}}
	stray := &v1.Ingress{ObjectMeta: meta.ObjectMeta{Name: "x", Namespace: "payments"}, Spec: v1.IngressSpec{IngressClass: "missing",
		Rules: []v1.IngressRule{{Service: v1.IngressTarget{Name: "other", Port: "http"}}}}}
	ctl := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "ingress-public", Namespace: "kevaso-system"}}
	got := WithIngressPaths([]*v1.Silo{api, other, ctl}, nil, []*v1.Ingress{ing, stray}, []*v1.IngressClass{class})
	if p := got["payments/api"]["http"]; len(p) != 1 || p[0] != "kevaso-system/ingress-public" {
		t.Fatalf("api paths %+v", got)
	}
	if len(api.Spec.Service.Ports[0].AllowFrom) != 1 {
		t.Fatal("the silo given was changed")
	}
	if len(got["payments/other"]) != 0 {
		t.Fatal("an Ingress of a class that doesn't exist opened a path")
	}
	// A SiloSet runs the controller: every one of its silos gets the path.
	class.Spec.Controller = v1.IngressController{Driver: "nginx", SiloSet: "edge", Namespace: "kevaso-system"}
	e0 := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "edge-0", Namespace: "kevaso-system", Labels: map[string]string{v1.LabelSiloSet: "edge"}}}
	e1 := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "edge-1", Namespace: "kevaso-system", Labels: map[string]string{v1.LabelSiloSet: "edge"}}}
	got = WithIngressPaths([]*v1.Silo{api, e0, e1, ctl}, nil, []*v1.Ingress{ing}, []*v1.IngressClass{class})
	if p := got["payments/api"]["http"]; len(p) != 2 || p[0] != "kevaso-system/edge-0" || p[1] != "kevaso-system/edge-1" {
		t.Fatalf("a SiloSet's silos: %+v", got)
	}
}
