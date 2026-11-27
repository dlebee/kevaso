package ips

import (
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// The IPv6 effort: one IP, one family. A Host IP's family is its host address's; a Static set's
// members are one family.
func familyHosts() []*v1.Host {
	return []*v1.Host{{Spec: v1.HostSpec{ExternalIP: "203.0.113.5", Addresses: []v1.HostAddress{
		{Name: "mail", Kind: v1.NetworkExternal, Address: "203.0.113.21"},
		{Name: "mail6", Kind: v1.NetworkExternal, Address: "2001:db8::21"},
	}}}}
}

func famIP(name, addr, family string) *v1.IP {
	x := &v1.IP{Spec: v1.IPSpec{Type: v1.IPTypeHost, HostAddress: addr, Family: family}}
	x.Name, x.Namespace = name, "mail"
	return x
}

func TestFamilyMismatch(t *testing.T) {
	hosts := familyHosts()
	hosts[0].Name = "w1"
	for _, c := range []struct {
		x    *v1.IP
		want string
	}{
		{famIP("a", "mail", ""), ""},
		{famIP("a", "mail", v1.FamilyIPv4), ""},
		{famIP("a", "mail6", v1.FamilyIPv6), ""},
		{famIP("a", "mail6", ""), "host address mail6 is IPv6 (2001:db8::21 on w1) and the IP is IPv4 (the default): a Host IP's family is its address's; set family: IPv6"},
		{famIP("a", "mail", v1.FamilyIPv6), "host address mail is IPv4 (203.0.113.21 on w1) and the IP is IPv6"},
		{famIP("a", "later", v1.FamilyIPv6), ""}, // no host has it yet: it could come in either
		{&v1.IP{Spec: v1.IPSpec{Type: v1.IPTypeProvider, Provider: "linode", Region: "us-ord", Family: v1.FamilyIPv6}}, ""},
	} {
		got := FamilyMismatch(c.x, hosts)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%+v: %q, want %q", c.x.Spec, got, c.want)
		}
	}
}

func TestAddressFamilyConflicts(t *testing.T) {
	h := familyHosts()[0]
	h.Name = "w1"
	if got := AddressFamilyConflicts(h, []*v1.IP{famIP("a", "mail", ""), famIP("b", "mail6", v1.FamilyIPv6)}); got != "" {
		t.Fatalf("matching families: %q", got)
	}
	got := AddressFamilyConflicts(h, []*v1.IP{famIP("b", "mail6", "")})
	if !strings.Contains(got, "mail6 2001:db8::21 is IPv6 and IP mail/b naming it is IPv4") {
		t.Fatalf("an IPv4 IP naming an IPv6 address: %q", got)
	}
}

func TestSetFamilies(t *testing.T) {
	hosts := familyHosts()
	ns := []*v1.IP{famIP("edge", "mail", ""), famIP("edge6", "mail6", v1.FamilyIPv6)}
	static := func(m ...v1.IPSetMember) *v1.IPSet {
		return &v1.IPSet{Spec: v1.IPSetSpec{Type: v1.IPSetStatic, Members: m}}
	}
	for _, c := range []struct {
		name string
		set  *v1.IPSet
		want string
	}{
		{"all IPv4", static(v1.IPSetMember{IP: "edge"}, v1.IPSetMember{HostAddress: "mail"}), ""},
		{"all IPv6", static(v1.IPSetMember{IP: "edge6"}, v1.IPSetMember{HostAddress: "mail6"}), ""},
		{"an IP of each", static(v1.IPSetMember{IP: "edge"}, v1.IPSetMember{IP: "edge6"}),
			"members[0] (ip: edge) is IPv4 and members[1] (ip: edge6) is IPv6: a set is one family; make two sets"},
		{"a host address of each", static(v1.IPSetMember{HostAddress: "mail6"}, v1.IPSetMember{HostAddress: "mail"}), "members[0] (hostAddress: mail6) is IPv6"},
		{"unknown members wait", static(v1.IPSetMember{IP: "later"}, v1.IPSetMember{IP: "edge6"}, v1.IPSetMember{HostAddress: "nowhere"}), ""},
		{"Dynamic", &v1.IPSet{Spec: v1.IPSetSpec{Type: v1.IPSetDynamic, Family: v1.FamilyIPv6}}, ""},
	} {
		got := SetFamilies(c.set, ns, hosts)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestMadeIPsHaveTheSetsFamily(t *testing.T) {
	dyn := &v1.IPSet{Spec: v1.IPSetSpec{Type: v1.IPSetDynamic, Provider: "linode", Region: "us-ord", Max: 2, Family: v1.FamilyIPv6}}
	dyn.Name = "edge"
	if x := Made(dyn, 0, dyn.Spec.Family); x == nil || x.Spec.Family != v1.FamilyIPv6 {
		t.Fatalf("a Dynamic IPv6 set's member: %+v", x)
	}
	st := &v1.IPSet{Spec: v1.IPSetSpec{Type: v1.IPSetStatic, Members: []v1.IPSetMember{{HostAddress: "mail6"}, {HostAddress: "mail"}}}}
	st.Name = "edge"
	if x := Made(st, 0, v1.FamilyIPv6); x == nil || x.Spec.Family != v1.FamilyIPv6 {
		t.Fatalf("an IPv6 host address member: %+v", x)
	}
	if x := Made(st, 1, v1.FamilyIPv4); x == nil || x.Spec.Family != "" {
		t.Fatalf("an IPv4 member is written as the default (no family): %+v", x)
	}
}
