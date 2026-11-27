package apiserver

import (
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

func TestCheckIP(t *testing.T) {
	for name, tc := range map[string]struct {
		spec v1.IPSpec
		want string
	}{
		"Host":                               {v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "mail"}, ""},
		"Provider":                           {v1.IPSpec{Type: v1.IPTypeProvider, Provider: "linode", Region: "us-ord"}, ""},
		"no type, never guessed from fields": {v1.IPSpec{HostAddress: "mail"}, "spec.type is required: Host"},
		"an unknown type":                    {v1.IPSpec{Type: "Pool"}, `spec.type "Pool": Host or Provider`},
		"Host without hostAddress":           {v1.IPSpec{Type: v1.IPTypeHost}, "type Host needs hostAddress"},
		"Host with a region":                 {v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "mail", Region: "us-ord"}, "provider and region are for type Provider"},
		"Host with a provider":               {v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "mail", Provider: "linode"}, "provider and region are for type Provider"},
		"a bad host address name":            {v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "Mail"}, `spec.hostAddress "Mail"`},
		"Provider without a region":          {v1.IPSpec{Type: v1.IPTypeProvider, Provider: "linode"}, "type Provider needs provider and region"},
		"Provider without a provider":        {v1.IPSpec{Type: v1.IPTypeProvider, Region: "us-ord"}, "type Provider needs provider and region"},
		"Provider with a host address":       {v1.IPSpec{Type: v1.IPTypeProvider, Provider: "linode", Region: "us-ord", HostAddress: "mail"}, "hostAddress is for type Host"},
	} {
		t.Run(name, func(t *testing.T) { expect(t, checkIP(&v1.IP{Spec: tc.spec}), tc.want) })
	}
}

func TestIPTransition(t *testing.T) {
	o := &v1.IP{Spec: v1.IPSpec{Type: v1.IPTypeProvider, Provider: "linode", Region: "us-ord"}}
	expect(t, ipTransition(o, &v1.IP{Spec: o.Spec}), "")
	for name, next := range map[string]v1.IPSpec{
		"region":   {Type: v1.IPTypeProvider, Provider: "linode", Region: "ca-central"},
		"provider": {Type: v1.IPTypeProvider, Provider: "linode-work", Region: "us-ord"},
		"type":     {Type: v1.IPTypeHost, HostAddress: "mail"},
	} {
		t.Run(name, func(t *testing.T) { expect(t, ipTransition(o, &v1.IP{Spec: next}), "spec can't change") })
	}
}

func TestCheckIPSet(t *testing.T) {
	static := func(m ...v1.IPSetMember) v1.IPSetSpec { return v1.IPSetSpec{Type: v1.IPSetStatic, Members: m} }
	for name, tc := range map[string]struct {
		spec v1.IPSetSpec
		want string
	}{
		"Static":              {static(v1.IPSetMember{IP: "edge-a"}, v1.IPSetMember{HostAddress: "eth-1"}), ""},
		"Dynamic":             {v1.IPSetSpec{Type: v1.IPSetDynamic, Provider: "linode", Region: "us-ord", Max: 3}, ""},
		"no type":             {v1.IPSetSpec{Members: []v1.IPSetMember{{IP: "a"}}}, "spec.type is required: Static"},
		"an unknown type":     {v1.IPSetSpec{Type: "Pool"}, `spec.type "Pool": Static or Dynamic`},
		"Static with nothing": {static(), "type Static needs members"},
		"a member with both":  {static(v1.IPSetMember{IP: "a", HostAddress: "b"}), "exactly one of ip (an IP's name) and hostAddress"},
		"a member with none":  {static(v1.IPSetMember{}), "exactly one of ip"},
		"a member twice":      {static(v1.IPSetMember{IP: "a"}, v1.IPSetMember{IP: "a"}), "ip: a is members[0] already"},
		"a bad member name":   {static(v1.IPSetMember{IP: "A"}), `"A" isn't a name`},
		"Static with a provider": {v1.IPSetSpec{Type: v1.IPSetStatic, Members: []v1.IPSetMember{{IP: "a"}}, Provider: "linode", Region: "us-ord", Max: 2},
			"provider, region and max are for type Dynamic"},
		"Dynamic with a host": {v1.IPSetSpec{Type: v1.IPSetDynamic, Provider: "linode", Region: "us-ord", Max: 2, Members: []v1.IPSetMember{{HostAddress: "eth-0"}}},
			"type Dynamic reserves provider IPs, so it can't have a host's address"},
		"Dynamic with members": {v1.IPSetSpec{Type: v1.IPSetDynamic, Provider: "linode", Region: "us-ord", Max: 2, Members: []v1.IPSetMember{{IP: "a"}}},
			"type Dynamic has no members"},
		"Dynamic without max":    {v1.IPSetSpec{Type: v1.IPSetDynamic, Provider: "linode", Region: "us-ord"}, "needs provider, region and max (at least 1)"},
		"Dynamic without region": {v1.IPSetSpec{Type: v1.IPSetDynamic, Provider: "linode", Max: 2}, "needs provider, region and max"},
	} {
		t.Run(name, func(t *testing.T) { expect(t, checkIPSet(&v1.IPSet{Spec: tc.spec}), tc.want) })
	}
}

func TestIPSetTransition(t *testing.T) {
	a, b, c := v1.IPSetMember{IP: "a"}, v1.IPSetMember{IP: "b"}, v1.IPSetMember{HostAddress: "c"}
	old := &v1.IPSet{Spec: v1.IPSetSpec{Type: v1.IPSetStatic, Members: []v1.IPSetMember{a, b}}}
	for name, tc := range map[string]struct {
		next v1.IPSetSpec
		want string
	}{
		"unchanged":            {v1.IPSetSpec{Type: v1.IPSetStatic, Members: []v1.IPSetMember{a, b}}, ""},
		"one added at the end": {v1.IPSetSpec{Type: v1.IPSetStatic, Members: []v1.IPSetMember{a, b, c}}, ""},
		"one removed":          {v1.IPSetSpec{Type: v1.IPSetStatic, Members: []v1.IPSetMember{a}}, "members are only added at the end"},
		"renumbered":           {v1.IPSetSpec{Type: v1.IPSetStatic, Members: []v1.IPSetMember{b, a}}, "never changes, moves or goes"},
		"one inserted":         {v1.IPSetSpec{Type: v1.IPSetStatic, Members: []v1.IPSetMember{a, c, b}}, "members are only added at the end"},
		"another type":         {v1.IPSetSpec{Type: v1.IPSetDynamic, Provider: "linode", Region: "us-ord", Max: 2}, "spec.type can't change"},
	} {
		t.Run(name, func(t *testing.T) { expect(t, ipSetTransition(old, &v1.IPSet{Spec: tc.next}), tc.want) })
	}
	dyn := &v1.IPSet{Spec: v1.IPSetSpec{Type: v1.IPSetDynamic, Provider: "linode", Region: "us-ord", Max: 2}}
	expect(t, ipSetTransition(dyn, &v1.IPSet{Spec: v1.IPSetSpec{Type: v1.IPSetDynamic, Provider: "linode", Region: "us-ord", Max: 5}}), "")
	expect(t, ipSetTransition(dyn, &v1.IPSet{Spec: v1.IPSetSpec{Type: v1.IPSetDynamic, Provider: "linode", Region: "ca-central", Max: 2}}),
		"spec.provider and spec.region can't change")
}

func TestCheckHostAddressList(t *testing.T) {
	host := func(a ...v1.HostAddress) *v1.Host {
		return &v1.Host{Spec: v1.HostSpec{ExternalIP: "203.0.113.10", InternalIP: "10.0.0.5", Addresses: a}}
	}
	mail := v1.HostAddress{Name: "mail", Kind: v1.NetworkExternal, Address: "203.0.113.21"}
	for name, tc := range map[string]struct {
		h    *v1.Host
		want string
	}{
		"one":              {host(mail), ""},
		"an internal one":  {host(mail, v1.HostAddress{Name: "db", Kind: v1.NetworkInternal, Address: "10.0.0.9"}), ""},
		"a name twice":     {host(mail, v1.HostAddress{Name: "mail", Kind: v1.NetworkExternal, Address: "203.0.113.22"}), "mail is listed twice"},
		"an address twice": {host(mail, v1.HostAddress{Name: "smtp", Kind: v1.NetworkExternal, Address: "203.0.113.21"}), "203.0.113.21 is mail already"},
		"a main IP":        {host(v1.HostAddress{Name: "web", Kind: v1.NetworkExternal, Address: "203.0.113.10"}), "203.0.113.10 is its main IP already"},
		"a range":          {host(v1.HostAddress{Name: "pool", Kind: v1.NetworkExternal, Address: "203.0.113.20/30"}), "is a range: one address per name"},
		"IPv6":             {host(v1.HostAddress{Name: "six", Kind: v1.NetworkExternal, Address: "2001:db8::1"}), ""},
		"IPv6 link-local":  {host(v1.HostAddress{Name: "six", Kind: v1.NetworkExternal, Address: "fe80::1"}), "isn't a unicast address"},
		"its externalIPv6": {&v1.Host{Spec: v1.HostSpec{ExternalIP: "203.0.113.10", ExternalIPv6: "2001:db8::10", Addresses: []v1.HostAddress{{Name: "six", Kind: v1.NetworkExternal, Address: "2001:db8::10"}}}}, "2001:db8::10 is its main IP already"},
		"no kind":          {host(v1.HostAddress{Name: "mail", Address: "203.0.113.21"}), `kind "": external`},
		"a bad name":       {host(v1.HostAddress{Name: "Mail", Kind: v1.NetworkExternal, Address: "203.0.113.21"}), `name "Mail"`},
	} {
		t.Run(name, func(t *testing.T) { expect(t, checkHostAddressList(tc.h), tc.want) })
	}
}

func TestOwnedBySet(t *testing.T) {
	s := &v1.Silo{}
	if ownedBySet(s) {
		t.Fatal("a silo with no owner is a set's")
	}
	s.OwnerReferences = []meta.OwnerReference{{Kind: "SiloSet", Name: "edge", Controller: true}}
	if !ownedBySet(s) {
		t.Fatal("a SiloSet's instance isn't a set's")
	}
	s.OwnerReferences[0].Controller = false
	if ownedBySet(s) {
		t.Fatal("a reference that isn't the controller makes it a set's")
	}
}
