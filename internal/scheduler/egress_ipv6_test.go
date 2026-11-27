package scheduler

import (
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// The IPv6 effort: egress.source: { ip } sets the address out of that IP's family only. An IPv6
// source leaves IPv4 out the worker's (no "waiting" note: it waits for nothing in IPv4); an IPv4
// source leaves IPv6 out the worker's externalIPv6. A worker with no IPv6 has no IPv6 out.
func TestEgressSourceAppliesToItsFamilyOnly(t *testing.T) {
	h := host("metal-1", func(h *v1.Host) { h.Spec.ExternalIP, h.Spec.ExternalIPv6 = "198.51.100.10", "2001:db8::10" })
	v4only := host("metal-2", func(h *v1.Host) { h.Spec.ExternalIP = "198.51.100.20" })
	mk := func(src *v1.EgressSource) *v1.Silo {
		s := exposed("n", "metal-1", nil)
		s.UID = "uid-n"
		s.Spec.Network.Egress.Source = src
		return s
	}
	six := ipObj("mail6", v1.IPTypeHost, func(x *v1.IP) {
		x.Spec.Family = v1.FamilyIPv6
		x.Status.Address, x.Status.Host = "2001:db8::17", "metal-1"
	})
	four := ipObj("mail", v1.IPTypeHost, func(x *v1.IP) { x.Status.Address, x.Status.Host = "198.51.100.17", "metal-1" })
	for _, c := range []struct {
		name         string
		silo         *v1.Silo
		on           *v1.Host
		ip           *v1.IP
		family       string
		want, want6  string
		noteContains string
	}{
		{"no source", mk(nil), h, nil, "", "198.51.100.10", "2001:db8::10", ""},
		{"an IPv6 source, held", mk(&v1.EgressSource{IP: "mail6"}), h, six, v1.FamilyIPv6, "198.51.100.10", "2001:db8::17", ""},
		{"an IPv6 source, not held yet", mk(&v1.EgressSource{IP: "mail6"}), h, nil, v1.FamilyIPv6, "198.51.100.10", "2001:db8::10", ""},
		{"an IPv4 source", mk(&v1.EgressSource{IP: "mail"}), h, four, v1.FamilyIPv4, "198.51.100.17", "2001:db8::10", ""},
		{"an IPv4 source not held yet", mk(&v1.EgressSource{IP: "mail"}), h, nil, "", "198.51.100.10", "2001:db8::10", "waiting for IP mail's address"},
		{"no IPv6 on the worker", mk(nil), v4only, nil, "", "198.51.100.20", "", ""},
	} {
		out, note := Egress(c.silo, c.on, v1.SiloServiceStatus{}, c.ip, c.family)
		out6 := EgressIPv6(c.silo, c.on, c.ip, c.family)
		if out != c.want || out6 != c.want6 {
			t.Errorf("%s: out %q, out over IPv6 %q; want %q, %q", c.name, out, out6, c.want, c.want6)
		}
		if (c.noteContains == "") != (note == "") {
			t.Errorf("%s: note %q, want one with %q", c.name, note, c.noteContains)
		}
	}
}

// The status says both: ServiceStatus reads the source IP's family from the IPs it knows.
func TestServiceStatusHasTheIPv6AddressOut(t *testing.T) {
	h := host("metal-1", func(h *v1.Host) { h.Spec.ExternalIP, h.Spec.ExternalIPv6 = "198.51.100.10", "2001:db8::10" })
	s := exposed("n", "metal-1", nil)
	s.UID = "uid-n"
	s.Spec.Network.Egress.Source = &v1.EgressSource{IP: "mail6"}
	six := ipObj("mail6", v1.IPTypeHost, func(x *v1.IP) {
		boundTo(s)(x)
		x.Spec.Family = v1.FamilyIPv6
		x.Status.Address, x.Status.Host = "2001:db8::17", "metal-1"
	})
	st, err := ServiceStatus(s, h, nil, Env{IPs: []*v1.IP{six}})
	if err != nil {
		t.Fatal(err)
	}
	if st.EgressIP != "198.51.100.10" || st.EgressIPv6 != "2001:db8::17" || st.EgressNote != "" {
		t.Fatalf("out %q, over IPv6 %q, note %q", st.EgressIP, st.EgressIPv6, st.EgressNote)
	}
}

// A worker: external port answers on the worker's externalIPv6 too, and its status says where
// ("[ADDRESS]:PORT"), also on a worker with no external IPv4. A port with sources (IPv4 only) is
// closed on IPv6, so it has no IPv6 address; worker: internal is IPv4.
func TestPortStatusOnTheWorkersIPv6(t *testing.T) {
	both := host("metal-1", func(h *v1.Host) {
		h.Spec.InternalIP, h.Spec.ExternalIP, h.Spec.ExternalIPv6 = "10.0.0.5", "198.51.100.10", "2001:db8::10"
	})
	only6 := host("metal-2", func(h *v1.Host) { h.Spec.InternalIP, h.Spec.ExternalIPv6 = "10.0.0.6", "2001:db8::20" })
	s := silo("api")
	s.Status.SiloIP = "10.64.2.7"
	s.Spec.Ports = []v1.SiloPort{{Name: "web", Port: 8000}}
	s.Spec.Services = []v1.SiloService{
		{Name: "pub", Type: v1.ServiceHostPort, Ports: []v1.ServicePort{{Port: "web", As: 8443}}},
		{Name: "few", Type: v1.ServiceHostPort, Ports: []v1.ServicePort{{Port: "web", As: 9443, Sources: []string{"203.0.113.0/24"}}}},
		{Name: "int", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{Worker: v1.NetworkInternal}, Ports: []v1.ServicePort{{Port: "web", As: 443}}},
	}
	for _, c := range []struct {
		h    *v1.Host
		want []v1.ServicePortStatus
	}{
		{both, []v1.ServicePortStatus{
			{Port: "web", Mesh: "10.64.2.7:8000", External: "198.51.100.10:8443", ExternalIPv6: "[2001:db8::10]:8443"},
			{Port: "web", Mesh: "10.64.2.7:8000", External: "198.51.100.10:9443"},
			{Port: "web", Mesh: "10.64.2.7:8000", Internal: "10.0.0.5:443"},
		}},
		{only6, []v1.ServicePortStatus{
			{Port: "web", Mesh: "10.64.2.7:8000", ExternalIPv6: "[2001:db8::20]:8443"},
			{Port: "web", Mesh: "10.64.2.7:8000"},
			{Port: "web", Mesh: "10.64.2.7:8000", Internal: "10.0.0.6:443"},
		}},
	} {
		s.Status.Host = c.h.Name
		got := PortStatus(s, c.h, "")
		if len(got) != len(c.want) {
			t.Fatalf("%s: %+v", c.h.Name, got)
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Errorf("%s port %d: %+v, want %+v", c.h.Name, i, got[i], c.want[i])
			}
		}
	}
	st := v1.SiloServiceStatus{Ports: PortStatus(s, only6, "")}
	if got := st.Front(); got != "10.0.0.6" {
		t.Errorf("Front = %q: an IPv4 address still comes first", got)
	}
	if got := st.OutsideIPs(); len(got) != 2 || got[0] != "2001:db8::20" || got[1] != "10.0.0.6" {
		t.Errorf("OutsideIPs = %q", got)
	}
}

// A worker: external port answers on the worker's externalIPv6, so a worker with an IPv6 address
// and no external IPv4 can take it (a move to it was refused: "no external IP"). A port with
// sources can't: they are IPv4, and it is closed on IPv6. worker: internal is IPv4 only.
func TestWorkerExternalOnAHostWithOnlyIPv6(t *testing.T) {
	only6 := host("metal-2", func(h *v1.Host) { h.Spec.InternalIP, h.Spec.ExternalIPv6 = "10.0.0.6", "2001:db8::20" })
	none := host("metal-3", func(h *v1.Host) { h.Spec.InternalIP = "10.0.0.7" })
	mk := func(sources ...string) *v1.Silo {
		s := silo("api")
		s.Spec.Ports = []v1.SiloPort{{Name: "web", Port: 8000}}
		s.Spec.Services = []v1.SiloService{{Name: "pub", Type: v1.ServiceHostPort, Ports: []v1.ServicePort{{Port: "web", As: 8443, Sources: sources}}}}
		return s
	}
	if r := netFilter(mk(), only6, nil, Env{}); r != "" {
		t.Errorf("an IPv6-only worker refused a worker: external port: %s", r)
	}
	if r := netFilter(mk("203.0.113.0/24"), only6, nil, Env{}); r == "" {
		t.Errorf("a port with (IPv4) sources was placed where it can only answer on IPv6")
	}
	if r := netFilter(mk(), none, nil, Env{}); r == "" {
		t.Errorf("a worker with no external address at all took a worker: external port")
	}
}
