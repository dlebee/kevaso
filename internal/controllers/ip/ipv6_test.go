package ip_test

import (
	"fmt"
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// The IPv6 effort: a Provider IP of family IPv6 is accepted and waits, saying why, until its
// provider can reserve IPv6 (wave 3); a Host IP of an IPv6 host address takes it now.
func TestAProviderIPv6WaitsAndAHostIPv6IsReserved(t *testing.T) {
	e := newSetEnv(t)
	e.must(e.c.Create(e.ctx, &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: "metal-1"},
		Spec: v1.HostSpec{InternalIP: "10.0.0.5", Addresses: []v1.HostAddress{{Name: "mail6", Kind: v1.NetworkExternal, Address: "2001:db8::22"}},
			Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}))
	e.must(e.c.Create(e.ctx, &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: "edge6", Namespace: "d"},
		Spec: v1.IPSpec{Type: v1.IPTypeProvider, Provider: "fake", Region: "ca-central", Family: v1.FamilyIPv6}}))
	e.must(e.c.Create(e.ctx, &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: "mail6", Namespace: "d"},
		Spec: v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "mail6", Family: v1.FamilyIPv6}}))
	e.eventually("the Provider IPv6 IP waits for its provider, and the Host one has its address", func() (bool, string) {
		p, _ := e.ip("edge6")
		h, _ := e.ip("mail6")
		r := meta.FindCondition(p.Status.Conditions, "Reserved")
		ok := r != nil && r.Status == meta.ConditionFalse && r.Reason == "Waiting" && strings.Contains(r.Message, "can't reserve IPv6 addresses yet") &&
			p.Status.Address == "" && h.Status.Address == "2001:db8::22" && h.Status.Host == "metal-1"
		return ok, fmt.Sprintf("edge6 %v; mail6 %+v", r, h.Status)
	})
}

// A Dynamic set's members are of its family; a Static set's hostAddress member is made once a
// host has the address, of that address's family.
func TestIPSetMembersHaveTheSetsFamily(t *testing.T) {
	e := newSetEnv(t)
	e.must(e.c.Create(e.ctx, &v1.IPSet{TypeMeta: tm("IPSet"), ObjectMeta: meta.ObjectMeta{Name: "edge6", Namespace: "d"},
		Spec: v1.IPSetSpec{Type: v1.IPSetDynamic, Provider: "fake", Region: "ca-central", Max: 2, Family: v1.FamilyIPv6}}))
	e.siloSet("mx", "edge6", 1)
	e.eventually("member 0 made, IPv6", func() (bool, string) {
		x, ok := e.ip("edge6-0")
		return ok && x.Spec.Family == v1.FamilyIPv6 && x.Spec.Type == v1.IPTypeProvider, fmt.Sprint(x)
	})

	e.must(e.c.Create(e.ctx, &v1.IPSet{TypeMeta: tm("IPSet"), ObjectMeta: meta.ObjectMeta{Name: "mail6", Namespace: "d"},
		Spec: v1.IPSetSpec{Type: v1.IPSetStatic, Members: []v1.IPSetMember{{HostAddress: "later6"}}}}))
	e.eventually("the set waits for the address, its member not made", func() (bool, string) {
		r := meta.FindCondition(e.set("mail6").Status.Conditions, "Ready")
		_, made := e.ip("mail6-0")
		return r != nil && r.Status == meta.ConditionFalse && strings.Contains(r.Message, "no host has address later6 yet") && !made, fmt.Sprint(r, made)
	})
	e.must(e.c.Create(e.ctx, &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: "metal-1"},
		Spec: v1.HostSpec{InternalIP: "10.0.0.5", Addresses: []v1.HostAddress{{Name: "later6", Kind: v1.NetworkExternal, Address: "2001:db8::30"}},
			Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}))
	e.eventually("member 0 made, IPv6 like its address, and reserved", func() (bool, string) {
		x, ok := e.ip("mail6-0")
		return ok && x.Spec.Family == v1.FamilyIPv6 && x.Status.Address == "2001:db8::30", fmt.Sprint(x)
	})
}
