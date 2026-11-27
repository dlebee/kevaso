package integration

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// The IPv6 effort, wave 1 (the API and addresses), in a real control plane: the cluster's ULA
// /48 gives each host its silo /64; a host takes an externalIPv6 and IPv6 extra addresses; one
// IP is one address of one family, a Host IP's its address's (a mismatch refused, either way it
// comes); a Static set is one family; a Provider IPv6 IP waits for its provider; a grant takes
// IPv6 ranges but never the cluster's own; egress.source sets the address out of its own family.

// editHost changes w1's spec, again on a conflict (its heartbeats write it too).
func editHost(ctx context.Context, t *testing.T, admin *client.Client, name string, f func(*v1.Host)) error {
	t.Helper()
	for i := 0; ; i++ {
		var h v1.Host
		if err := admin.Get(ctx, "Host", "", name, &h); err != nil {
			t.Fatal(err)
		}
		f(&h)
		err := admin.Update(ctx, &h)
		if !client.IsConflict(err) || i > 20 {
			return err
		}
	}
}

func refusedWith(t *testing.T, what string, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("%s: %v; want a refusal saying %q", what, err, want)
	}
}

func TestIPv6AddressesAndFamilies(t *testing.T) {
	r := newIPRig(t)
	ctx, admin, eventually := r.ctx, r.admin, r.eventually
	if err := admin.Create(ctx, ns("mail")); err != nil {
		t.Fatal(err)
	}
	getIP := func(name string) *v1.IP {
		var x v1.IP
		_ = admin.Get(ctx, "IP", "mail", name, &x)
		return &x
	}
	mkIP := func(name string, spec v1.IPSpec) error {
		return admin.Create(ctx, &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "mail"}, Spec: spec})
	}

	// The cluster's /48 and w1's /64 in it.
	var ula netip.Prefix
	eventually("w1 has its silo /64 in a unique local /48", func() (bool, string) {
		var h v1.Host
		_ = admin.Get(ctx, "Host", "", "w1", &h)
		p, err := netip.ParsePrefix(h.Status.Network.SiloSubnetIPv6)
		if err != nil || p.Bits() != 64 || p.Addr().As16()[0] != 0xfd || h.Status.Network.Index == 0 {
			return false, fmt.Sprintf("%+v", h.Status.Network)
		}
		want := fmt.Sprintf(":%x::/64", h.Status.Network.Index)
		ula = netip.PrefixFrom(p.Addr(), 48).Masked()
		return strings.HasSuffix(p.String(), want), p.String() + " want …" + want
	})

	// A host's addresses: externalIPv6, an IPv6 extra address; each in its own field.
	refusedWith(t, "an IPv6 externalIP", editHost(ctx, t, admin, "w1", func(h *v1.Host) { h.Spec.ExternalIP = "2001:db8::5" }), "it goes in spec.externalIPv6")
	refusedWith(t, "an IPv4 externalIPv6", editHost(ctx, t, admin, "w1", func(h *v1.Host) { h.Spec.ExternalIPv6 = "203.0.113.50" }), "it goes in spec.externalIP")
	if err := editHost(ctx, t, admin, "w1", func(h *v1.Host) {
		h.Spec.ExternalIPv6 = "2001:db8::5"
		h.Spec.Addresses = append(h.Spec.Addresses, v1.HostAddress{Name: "mail6", Kind: v1.NetworkExternal, Address: "2001:db8::21"})
	}); err != nil {
		t.Fatal(err)
	}

	// A Host IP's family is its address's.
	refusedWith(t, "an IPv4 IP on an IPv6 address", mkIP("x", v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "mail6"}), "set family: IPv6")
	refusedWith(t, "an IPv6 IP on an IPv4 address", mkIP("x", v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "mail", Family: v1.FamilyIPv6}), "set family: IPv4")
	refusedWith(t, "a family that isn't one", mkIP("x", v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "mail", Family: "dual"}), `spec.family "dual"`)
	if err := mkIP("mail", v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "mail"}); err != nil {
		t.Fatal(err)
	}
	if err := mkIP("mail6", v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "mail6", Family: v1.FamilyIPv6}); err != nil {
		t.Fatal(err)
	}
	// An IP naming an address no host has yet: the address that comes must be of its family.
	if err := mkIP("late6", v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "late6", Family: v1.FamilyIPv6}); err != nil {
		t.Fatal(err)
	}
	refusedWith(t, "an IPv4 address for an IPv6 IP", editHost(ctx, t, admin, "w1", func(h *v1.Host) {
		h.Spec.Addresses = append(h.Spec.Addresses, v1.HostAddress{Name: "late6", Kind: v1.NetworkExternal, Address: "203.0.113.40"})
	}), "an IP of type Host is one family, its address's")
	// An IP's family never changes.
	x := getIP("mail6")
	x.Spec.Family = ""
	refusedWith(t, "changing an IP's family", admin.Update(ctx, x), "spec can't change")

	// A Provider IPv6 IP is accepted, and waits for a provider that can reserve one.
	if err := mkIP("edge6", v1.IPSpec{Type: v1.IPTypeProvider, Provider: "fake", Region: "ca-central", Family: v1.FamilyIPv6}); err != nil {
		t.Fatal(err)
	}
	eventually("mail6 reserved on w1, edge6 waiting with the reason", func() (bool, string) {
		m, e := getIP("mail6"), getIP("edge6")
		c := meta.FindCondition(e.Status.Conditions, "Reserved")
		return m.Status.Address == "2001:db8::21" && m.Status.Host == "w1" &&
				c != nil && c.Status == meta.ConditionFalse && c.Reason == "Waiting" && strings.Contains(c.Message, "can't reserve IPv6 addresses yet"),
			fmt.Sprintf("mail6 %+v; edge6 %+v", m.Status, c)
	})

	// One family per set.
	set := func(name string, spec v1.IPSetSpec) error {
		return admin.Create(ctx, &v1.IPSet{TypeMeta: tm("IPSet"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "mail"}, Spec: spec})
	}
	refusedWith(t, "a Static set of both families", set("both", v1.IPSetSpec{Type: v1.IPSetStatic, Members: []v1.IPSetMember{{IP: "mail"}, {HostAddress: "mail6"}}}),
		"a set is one family; make two sets")
	refusedWith(t, "a Static set with a family", set("s6", v1.IPSetSpec{Type: v1.IPSetStatic, Members: []v1.IPSetMember{{IP: "mail6"}}, Family: v1.FamilyIPv6}),
		"family is for type Dynamic")
	if err := set("six", v1.IPSetSpec{Type: v1.IPSetStatic, Members: []v1.IPSetMember{{IP: "mail6"}}}); err != nil {
		t.Fatal(err)
	}
	if err := set("dyn6", v1.IPSetSpec{Type: v1.IPSetDynamic, Provider: "fake", Region: "ca-central", Max: 2, Family: v1.FamilyIPv6}); err != nil {
		t.Fatal(err)
	}

	// Grants take IPv6 ranges, never the cluster's own.
	grant := func(name, to string) error {
		return admin.Create(ctx, &v1.Grant{TypeMeta: tm("Grant"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "mail"},
			Spec: v1.GrantSpec{Egress: []v1.EgressRule{{To: to, Ports: []string{"443"}}}}})
	}
	if err := grant("v6", "2001:db8:abcd::/48"); err != nil {
		t.Fatal(err)
	}
	if err := grant("all6", "::/0"); err != nil {
		t.Fatal(err)
	}
	inside := netip.PrefixFrom(ula.Addr(), 64).String()
	refusedWith(t, "a grant to the silos' IPv6 range", grant("own", inside), "(the silos' IPv6 range), which a grant never opens")
	refusedWith(t, "a grant to IPv6 link-local", grant("ll", "fe80::/64"), "which a grant never opens")

	// egress.source { ip: mail6 } sets the IPv6 address out only: IPv4 out stays the worker's.
	if err := admin.Create(ctx, &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "mx6", Namespace: "mail"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "postfix"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
			Ports:    []v1.SiloPort{{Name: "smtp", Port: 2525}},
			Services: []v1.SiloService{{Name: "mx6", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: "mail6"}, Ports: []v1.ServicePort{{Port: "smtp", As: 25}}}},
			Network:  v1.SiloNetwork{Egress: v1.Egress{Source: &v1.EgressSource{IP: "mail6"}}}}}); err != nil {
		t.Fatal(err)
	}
	eventually("mx6 on w1, out over IPv4 from w1's address and over IPv6 from mail6's", func() (bool, string) {
		var s v1.Silo
		_ = admin.Get(ctx, "Silo", "mail", "mx6", &s)
		st := s.Status.Service
		return s.Status.Host == "w1" && st.EgressIP == "203.0.113.5" && st.EgressIPv6 == "2001:db8::21" && st.EgressNote == "",
			fmt.Sprintf("host %q, out %q, IPv6 out %q, note %q", s.Status.Host, st.EgressIP, st.EgressIPv6, st.EgressNote)
	})
}
