package scheduler

import (
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// A HostPort port on an IP (hostPort: { ip: NAME }) is reachable at that IP's address while the
// silo holds it on its host: the port status says so, in the column of the address's kind, so
// describe's "In and out" and an Ingress's front see it. It said nothing ("nothing in").
func TestPortStatusOnAnIP(t *testing.T) {
	h := &v1.Host{ObjectMeta: meta.ObjectMeta{Name: "w2"}, Spec: v1.HostSpec{InternalIP: "54.39.243.98",
		Addresses: []v1.HostAddress{{Name: "web", Kind: v1.NetworkExternal, Address: "203.0.113.50"}, {Name: "lan", Kind: v1.NetworkInternal, Address: "10.77.0.3"}}}}
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "app", Namespace: "ai", UID: "u1"}}
	s.Spec.Ports = []v1.SiloPort{{Name: "web", Port: 8080}}
	s.Spec.Services = []v1.SiloService{{Name: "app-web", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: "web"}, Ports: []v1.ServicePort{{Port: "web"}}}}
	ip := func(typ, hostAddr, addr, host string) *v1.IP {
		return &v1.IP{ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "ai"}, Spec: v1.IPSpec{Type: typ, HostAddress: hostAddr},
			Status: v1.IPStatus{Address: addr, Host: host}}
	}
	for _, c := range []struct {
		name               string
		held               *v1.IP
		internal, external string
	}{
		{"a host's external address", ip(v1.IPTypeHost, "web", "203.0.113.50", "w2"), "", "203.0.113.50:8080"},
		{"a host's internal address", ip(v1.IPTypeHost, "lan", "10.77.0.3", "w2"), "10.77.0.3:8080", ""},
		{"a provider's", ip(v1.IPTypeProvider, "", "172.232.0.9", "w2"), "", "172.232.0.9:8080"},
		{"on another host", ip(v1.IPTypeHost, "web", "203.0.113.50", "w1"), "", ""},
		{"not reserved yet", ip(v1.IPTypeHost, "web", "", ""), "", ""},
		{"not held", nil, "", ""},
	} {
		got := PortStatusWith(s, h, "", func(v1.OpenPort) *v1.IP { return c.held })
		if len(got) != 1 || got[0].Internal != c.internal || got[0].External != c.external {
			t.Errorf("%s: %+v, want internal %q external %q", c.name, got, c.internal, c.external)
		}
	}
	st := v1.SiloServiceStatus{EgressIP: "54.39.243.98", Ports: PortStatusWith(s, h, "", func(v1.OpenPort) *v1.IP { return ip(v1.IPTypeHost, "web", "203.0.113.50", "w2") })}
	if line := st.AddressesLine(); !strings.Contains(line, "in 203.0.113.50") {
		t.Errorf("In and out: %q", line)
	}
}
