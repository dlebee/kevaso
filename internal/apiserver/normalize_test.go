package apiserver

import (
	"slices"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// K-009 and K-036, admission half: every range a user writes for the firewall is parsed and put in
// one form before it is stored, so the rule generator never sees a duplicate, an overlap, a
// host-bit prefix or text that isn't a range.
func TestFirewallRangesAreNormalizedAtAdmission(t *testing.T) {
	silo := &v1.Silo{Spec: v1.SiloSpec{Services: []v1.SiloService{{Type: v1.ServiceHostPort, Ports: []v1.ServicePort{{Port: "web",
		Sources: []string{"10.1.2.3/8", "10.0.0.0/8", "192.0.2.7/32", "192.0.2.7", "198.51.100.0/24", "198.51.100.5", "10.9.9.9"}}}}}}}
	normalize(silo)
	want := []string{"10.0.0.0/8", "192.0.2.7", "198.51.100.0/24"}
	if got := silo.Spec.Services[0].Ports[0].Sources; !slices.Equal(got, want) {
		t.Errorf("sources %q, want %q", got, want)
	}
	// A set's template.
	set := &v1.SiloSet{Spec: v1.SiloSetSpec{Template: v1.SiloTemplate{SiloSpec: v1.SiloSpec{Services: []v1.SiloService{{Type: v1.ServiceHostPort, Ports: []v1.ServicePort{{Port: "web", Sources: []string{"203.0.113.9/24"}}}}}}}}}
	normalize(set)
	if got := set.Spec.Template.Services[0].Ports[0].Sources; !slices.Equal(got, []string{"203.0.113.0/24"}) {
		t.Errorf("template sources %q", got)
	}
	// Bad entries stay for semantic to refuse (and are never dropped silently).
	bad := &v1.Silo{Spec: v1.SiloSpec{Services: []v1.SiloService{{Type: v1.ServiceHostPort, Ports: []v1.ServicePort{{Port: "web", Sources: []string{"2001:db8::/32", "10.0.0.0/8"}}}}}}}
	normalize(bad)
	if got := bad.Spec.Services[0].Ports[0].Sources; !slices.Equal(got, []string{"10.0.0.0/8", "2001:db8::/32"}) {
		t.Errorf("bad kept: %q", got)
	}
	// A Grant's CIDRs.
	g := &v1.Grant{Spec: v1.GrantSpec{Egress: []v1.EgressRule{{To: "10.1.2.3/8"}, {To: "192.0.2.1/32"}, {To: "api.example.com"}}}}
	normalize(g)
	if g.Spec.Egress[0].To != "10.0.0.0/8" || g.Spec.Egress[1].To != "192.0.2.1" || g.Spec.Egress[2].To != "api.example.com" {
		t.Errorf("egress %+v", g.Spec.Egress)
	}
}
