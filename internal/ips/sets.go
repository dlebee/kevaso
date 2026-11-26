package ips

import (
	"fmt"
	"strconv"

	v1 "kevaso.com/core/api/v1"
)

// ── IPSets: one member per SiloSet instance, by ordinal ──────────────────────

// MemberIP is the IP object a set's ordinal i is: a Static member's ip, or the set's own IP
// SET-i (a Static hostAddress member, which the set makes as an IP of type Host, or a Dynamic
// set's reservation). ok false: the set has no member i (a Static set that short, a Dynamic one
// past max).
func MemberIP(set *v1.IPSet, i int) (name string, ok bool) {
	if set == nil || i < 0 {
		return "", false
	}
	switch set.Spec.Type {
	case v1.IPSetStatic:
		if i >= len(set.Spec.Members) {
			return "", false
		}
		if m := set.Spec.Members[i]; m.IP != "" {
			return m.IP, true
		}
		return v1.DynamicMemberName(set.Name, i), true
	case v1.IPSetDynamic:
		if i >= set.Spec.Max {
			return "", false
		}
		return v1.DynamicMemberName(set.Name, i), true
	}
	return "", false
}

// Size is how many members the set can have now: a Static set's members, a Dynamic set's max.
func Size(set *v1.IPSet) int {
	if set.Spec.Type == v1.IPSetStatic {
		return len(set.Spec.Members)
	}
	return set.Spec.Max
}

// Made is the IP the set makes for its ordinal i (labelled with the set and the ordinal), or nil
// when member i is an IP of the namespace's own (a Static ip member) or there is none.
func Made(set *v1.IPSet, i int) *v1.IP {
	name, ok := MemberIP(set, i)
	if !ok {
		return nil
	}
	x := &v1.IP{}
	x.APIVersion, x.Kind = v1.APIVersion, "IP"
	x.Name, x.Namespace = name, set.Namespace
	x.Labels = map[string]string{v1.LabelIPSet: set.Name, v1.LabelIPSetOrdinal: strconv.Itoa(i)}
	switch set.Spec.Type {
	case v1.IPSetStatic:
		m := set.Spec.Members[i]
		if m.IP != "" {
			return nil
		}
		x.Spec = v1.IPSpec{Type: v1.IPTypeHost, HostAddress: m.HostAddress}
	case v1.IPSetDynamic:
		x.Spec = v1.IPSpec{Type: v1.IPTypeProvider, Provider: set.Spec.Provider, Region: set.Spec.Region}
	}
	return x
}

// MadeBy says whether x is the set's own IP for its ordinal i (it carries the set's labels).
func MadeBy(x *v1.IP, set string, i int) bool {
	return x.Labels[v1.LabelIPSet] == set && x.Labels[v1.LabelIPSetOrdinal] == strconv.Itoa(i)
}

// InstanceOf is the SiloSet s is an instance of and its ordinal ("" and -1 if it is none).
func InstanceOf(s *v1.Silo) (set string, ordinal int) {
	set = s.Labels[v1.LabelSiloSet]
	if set == "" {
		return "", -1
	}
	i := v1.InstanceIndex(set, s.Name)
	if i < 0 {
		return "", -1
	}
	return set, i
}

// OwnIP is the IP a SiloSet instance's own names (hostPort: { own: true }, egress.source:
// { own: true }): member N of its set's IPSet (spec.ips) for instance N. "" when s uses no own,
// isn't an instance of siloSet, or the set has no member N yet; why says which, for people.
func OwnIP(s *v1.Silo, siloSet *v1.SiloSet, set *v1.IPSet) (name, why string) {
	if !s.Spec.UsesOwn() {
		return "", ""
	}
	setName, i := InstanceOf(s)
	switch {
	case setName == "" || siloSet == nil || siloSet.Name != setName:
		return "", "own is a SiloSet instance's IPSet member, and " + s.Name + " is no instance"
	case siloSet.Spec.IPs == "":
		return "", "SiloSet " + setName + " names no IPSet (ips: SETNAME)"
	case set == nil || set.Name != siloSet.Spec.IPs:
		return "", "IPSet " + siloSet.Spec.IPs + " doesn't exist yet"
	}
	n, ok := MemberIP(set, i)
	if !ok {
		if set.Spec.Type == v1.IPSetDynamic {
			return "", fmt.Sprintf("IPSet %s is full: instance %d needs member %d, and max is %d", set.Name, i, i, set.Spec.Max)
		}
		return "", fmt.Sprintf("IPSet %s has %d member(s): instance %d needs member %d (add one at the end)", set.Name, len(set.Spec.Members), i, i)
	}
	return n, ""
}

// SiloSetsUsing are the SiloSets naming set (spec.ips), and the most instances any of them
// asks for: what a Dynamic set reserves up to.
func SiloSetsUsing(set *v1.IPSet, siloSets []*v1.SiloSet) (using []*v1.SiloSet, want int) {
	for _, ss := range siloSets {
		if ss.Namespace != set.Namespace || ss.Spec.IPs != set.Name || ss.DeletionTimestamp != nil {
			continue
		}
		using = append(using, ss)
		if n := ss.Spec.Instances + ss.Spec.Standby; n > want {
			want = n
		}
	}
	return using, want
}
