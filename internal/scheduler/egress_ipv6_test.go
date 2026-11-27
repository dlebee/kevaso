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
