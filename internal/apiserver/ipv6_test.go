package apiserver

import (
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// The IPv6 effort at admission, the pure part: one IP, one family; a set one family; IPv6 where
// IPv4 is required (and the reverse) refused with the fix.

func TestCheckIPFamily(t *testing.T) {
	host := v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "mail6"}
	for name, tc := range map[string]struct {
		family, want string
	}{
		"none: IPv4": {"", ""},
		"IPv4":       {v1.FamilyIPv4, ""},
		"IPv6":       {v1.FamilyIPv6, ""},
		"both":       {"IPv4+IPv6", `spec.family "IPv4+IPv6": IPv4 (the default) or IPv6; one IP is one address of one family`},
		"lower-case": {"ipv6", `spec.family "ipv6"`},
	} {
		t.Run(name, func(t *testing.T) {
			sp := host
			sp.Family = tc.family
			expect(t, checkIP(&v1.IP{Spec: sp}), tc.want)
			pv := v1.IPSpec{Type: v1.IPTypeProvider, Provider: "linode", Region: "us-ord", Family: tc.family}
			expect(t, checkIP(&v1.IP{Spec: pv}), tc.want) // a Provider IPv6 IP is accepted (it waits for the provider)
		})
	}
	o := &v1.IP{Spec: v1.IPSpec{Type: v1.IPTypeProvider, Provider: "linode", Region: "us-ord"}}
	n := &v1.IP{Spec: v1.IPSpec{Type: v1.IPTypeProvider, Provider: "linode", Region: "us-ord", Family: v1.FamilyIPv6}}
	expect(t, ipTransition(o, n), "spec can't change (type, family,")
}

func TestCheckIPSetFamily(t *testing.T) {
	dyn := func(f string) v1.IPSetSpec {
		return v1.IPSetSpec{Type: v1.IPSetDynamic, Provider: "linode", Region: "us-ord", Max: 2, Family: f}
	}
	expect(t, checkIPSet(&v1.IPSet{Spec: dyn("")}), "")
	expect(t, checkIPSet(&v1.IPSet{Spec: dyn(v1.FamilyIPv6)}), "")
	expect(t, checkIPSet(&v1.IPSet{Spec: dyn("v6")}), `spec.family "v6"`)
	expect(t, checkIPSet(&v1.IPSet{Spec: v1.IPSetSpec{Type: v1.IPSetStatic, Members: []v1.IPSetMember{{IP: "a"}}, Family: v1.FamilyIPv6}}),
		"type Static is its members' family: family is for type Dynamic")
	expect(t, ipSetTransition(&v1.IPSet{Spec: dyn("")}, &v1.IPSet{Spec: dyn(v1.FamilyIPv6)}), "spec.family can't change")
}

func TestHostAddressFamilies(t *testing.T) {
	base := func(f func(*v1.HostSpec)) *v1.Host {
		h := &v1.Host{Spec: v1.HostSpec{InternalIP: "10.0.0.5", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}
		f(&h.Spec)
		return h
	}
	for name, tc := range map[string]struct {
		set  func(*v1.HostSpec)
		want string
	}{
		"externalIPv6":                {func(s *v1.HostSpec) { s.ExternalIPv6 = "2001:db8::5" }, ""},
		"externalIPv6 IPv4":           {func(s *v1.HostSpec) { s.ExternalIPv6 = "203.0.113.5" }, `spec.externalIPv6: "203.0.113.5" is IPv4: it goes in spec.externalIP`},
		"externalIPv6 mapped":         {func(s *v1.HostSpec) { s.ExternalIPv6 = "::ffff:203.0.113.5" }, "is an IPv4-mapped address"},
		"externalIPv6 link-local":     {func(s *v1.HostSpec) { s.ExternalIPv6 = "fe80::1" }, "isn't a global IPv6 address"},
		"externalIPv6 unique local":   {func(s *v1.HostSpec) { s.ExternalIPv6 = "fd12:3456:789a::1" }, "isn't a global IPv6 address"},
		"externalIPv6 not an address": {func(s *v1.HostSpec) { s.ExternalIPv6 = "web" }, `"web" isn't an IPv6 address`},
		"externalIP IPv6":             {func(s *v1.HostSpec) { s.ExternalIP = "2001:db8::5" }, `spec.externalIP: "2001:db8::5" is IPv6: it goes in spec.externalIPv6`},
		"internalIP IPv6":             {func(s *v1.HostSpec) { s.InternalIP = "fd00::5" }, `spec.internalIP: "fd00::5" is IPv6: the internal IP is IPv4`},
		"externalIP mapped":           {func(s *v1.HostSpec) { s.ExternalIP = "::ffff:1.2.3.4" }, "isn't an IPv4 address"},
	} {
		t.Run(name, func(t *testing.T) { expect(t, semantic(base(tc.set)), tc.want) })
	}
}

func TestGrantIPv6IsNormalized(t *testing.T) {
	g := &v1.Grant{Spec: v1.GrantSpec{Egress: []v1.EgressRule{{To: "2001:DB8::7"}, {To: "2001:db8::1/48"}, {To: "203.0.113.7/32"}}}}
	normalize(g)
	for i, want := range []string{"2001:db8::7", "2001:db8::/48", "203.0.113.7"} {
		if got := g.Spec.Egress[i].To; got != want {
			t.Errorf("egress[%d] = %q, want %q", i, got, want)
		}
	}
	expect(t, semantic(g), "")
	expect(t, semantic(&v1.Grant{Spec: v1.GrantSpec{Egress: []v1.EgressRule{{To: "fe80::/64"}}}}), "which a grant never opens")
}
