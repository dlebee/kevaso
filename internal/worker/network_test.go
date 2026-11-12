package worker

import (
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

func TestNetworkView(t *testing.T) {
	h := &v1.Host{ObjectMeta: meta.ObjectMeta{Name: "metal-1"}, Spec: v1.HostSpec{Address: "198.51.100.10"}}
	mk := func(name, host, addr string, f func(*v1.Silo)) *v1.Silo {
		s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "web3", UID: "u-" + name}}
		s.Status.Host, s.Status.Address = host, addr
		if f != nil {
			f(s)
		}
		return s
	}
	node := mk("eth-node", "metal-1", "10.64.0.2", func(s *v1.Silo) {
		s.Spec.Service = &v1.Service{Ports: []v1.ServicePort{{Name: "p2p", Port: 30303}}, Expose: v1.ExposeHostPort}
		s.Spec.Network.Egress.Source = v1.EgressSameAsService
		s.Status.Service = v1.ServiceStatus{PublicIP: "198.51.100.10", EgressIP: "198.51.100.10"}
	})
	plain := mk("plain", "metal-1", "10.64.0.3", func(s *v1.Silo) { s.Status.Service.EgressIP = "198.51.100.10" })
	pooled := mk("pooled", "metal-1", "10.64.0.4", func(s *v1.Silo) { s.Status.Service.PoolIP = "198.51.100.17" })
	elsewhere := mk("far", "metal-2", "10.64.9.2", nil)
	pending := mk("pending", "", "", nil)
	node.Spec.Grants = []string{"p2p-anywhere", "missing"}
	grants := []*v1.Grant{
		{ObjectMeta: meta.ObjectMeta{Name: "p2p-anywhere", Namespace: "web3"}, Spec: v1.GrantSpec{Egress: []v1.EgressRule{{To: "0.0.0.0/0", Ports: []string{"30303"}, Protocols: []string{"tcp", "udp"}}}}},
		{ObjectMeta: meta.ObjectMeta{Name: "p2p-anywhere", Namespace: "other"}, Spec: v1.GrantSpec{Egress: []v1.EgressRule{{To: "10.0.0.0/8"}}}},
	}
	v := NetworkView("metal-1", h, []*v1.Silo{node, plain, pooled, elsewhere, pending}, grants)
	if len(v.Local) != 3 || len(v.All) != 4 || v.Address.String() != "198.51.100.10" {
		t.Fatalf("view %+v", v)
	}
	for _, s := range v.Local {
		if !strings.HasPrefix(s.Tap, "kvt") {
			t.Errorf("%s has no tap", s.Key)
		}
		switch s.Key {
		case "web3/eth-node":
			if s.PublicIP.String() != "198.51.100.10" || s.EgressIP.String() != "198.51.100.10" {
				t.Errorf("eth-node %+v", s)
			}
			if len(s.Egress) != 1 || s.Egress[0].Prefix.String() != "0.0.0.0/0" { // its namespace's grant only
				t.Errorf("eth-node egress %+v", s.Egress)
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
