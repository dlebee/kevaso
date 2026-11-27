package kvo

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// What kvo shows about networking v2 (idealization/networking-v2.md): each silo's services and
// where they're reachable (whether it can move is the scheduler's status.movable), IPs and IP sets, a host's addresses and
// who reserves each. The layouts are pure: describe reads what they need into a netEnv, the
// golden tests hand one in.

// netEnv is what describing a silo, an IP, an IP set or a host reads beside the object itself.
// Any part may be missing (nil: not read, or not readable by this person): the layouts then say
// less, never something wrong.
type netEnv struct {
	ips      []*v1.IP
	ipsets   []*v1.IPSet
	hosts    []*v1.Host
	silos    []*v1.Silo
	silosets []*v1.SiloSet
}

func (e *netEnv) ip(ns, name string) *v1.IP {
	if e == nil {
		return nil
	}
	for _, x := range e.ips {
		if x.Namespace == ns && x.Name == name {
			return x
		}
	}
	return nil
}

// ipFamily is the family of the IP named name ("" if it isn't known).
func (e *netEnv) ipFamily(ns, name string) string {
	if x := e.ip(ns, name); x != nil {
		return x.Spec.FamilyOrDefault()
	}
	return ""
}

func (e *netEnv) host(name string) *v1.Host {
	if e == nil {
		return nil
	}
	for _, h := range e.hosts {
		if h.Name == name {
			return h
		}
	}
	return nil
}

// siloIPv6Line is a silo's IPv6 address for kvo describe, or why it has none.
func siloIPv6Line(s *v1.Silo, env *netEnv) string {
	if s.Status.SiloIPv6 != "" {
		return s.Status.SiloIPv6
	}
	if s.Status.Host == "" {
		return "-"
	}
	if h := env.host(s.Status.Host); h != nil && h.Status.Network.SiloSubnetIPv6 == "" {
		return "none: host " + h.Name + " has no IPv6 subnet (IPv4 only)"
	}
	return "-"
}

// hostSubnets is a host's silo subnets, both families.
func hostSubnets(h *v1.Host) string {
	n := h.Status.Network
	switch {
	case n.SiloSubnet == "" && n.SiloSubnetIPv6 == "":
		return "- (not on the mesh yet)"
	case n.SiloSubnetIPv6 == "":
		return n.SiloSubnet + " (no IPv6)"
	}
	return dash(n.SiloSubnet) + ", " + n.SiloSubnetIPv6
}

// addressHost is the host with the extra address named name ("" if none known).
func (e *netEnv) addressHost(name string) string {
	if e == nil {
		return ""
	}
	for _, h := range e.hosts {
		if _, ok := h.Address(name); ok {
			return h.Name
		}
	}
	return ""
}

func (e *netEnv) silo(ns, name string) *v1.Silo {
	if e == nil {
		return nil
	}
	for _, s := range e.silos {
		if s.Namespace == ns && s.Name == name {
			return s
		}
	}
	return nil
}

// loadNetEnv reads what describing obj needs. What this person can't read (hosts, other
// namespaces' IPs) is left out.
func loadNetEnv(ctx context.Context, c *client.Client, obj meta.Object) *netEnv {
	e := &netEnv{}
	ns := obj.GetObjectMeta().Namespace
	switch obj.(type) {
	case *v1.Silo:
		e.ips = listOf[*v1.IP](ctx, c, "IP", ns)
		e.hosts = listOf[*v1.Host](ctx, c, "Host", "")
	case *v1.SiloSet:
		e.ipsets = listOf[*v1.IPSet](ctx, c, "IPSet", ns)
	case *v1.IP:
		e.silos = listOf[*v1.Silo](ctx, c, "Silo", ns)
		e.hosts = listOf[*v1.Host](ctx, c, "Host", "")
	case *v1.IPSet:
		e.ips = listOf[*v1.IP](ctx, c, "IP", ns)
		e.silosets = listOf[*v1.SiloSet](ctx, c, "SiloSet", ns)
	case *v1.Host:
		e.ips = listOf[*v1.IP](ctx, c, "IP", "")
		e.silos = listOf[*v1.Silo](ctx, c, "Silo", "")
	default:
		return nil
	}
	return e
}

func listOf[T meta.Object](ctx context.Context, c *client.Client, kind, ns string) []T {
	l, err := c.List(ctx, kind, ns)
	if err != nil {
		return nil
	}
	out := []T{} // read, maybe empty: not nil, which is "not read"
	for _, raw := range l.Items {
		if obj, _, err := v1.Decode(raw); err == nil {
			if t, ok := obj.(T); ok {
				out = append(out, t)
			}
		}
	}
	return out
}

// ── IPs ──────────────────────────────────────────────────────────────────────

var ipHead = []string{"TYPE", "FAMILY", "ADDRESS", "WHERE", "SET", "USED BY", "MOVES"}

func ipRow(x *v1.IP) []string {
	return []string{x.Spec.Type, x.Spec.FamilyOrDefault(), dash(x.Status.Address), dash(ipWhere(x)), dash(ipSet(x)), dash(x.Status.Holders()), ipMoves(x)}
}

// ipWhere is where the address can be: the status's, else what the spec says.
func ipWhere(x *v1.IP) string {
	if x.Status.Where != "" {
		return x.Status.Where
	}
	switch x.Spec.Type {
	case v1.IPTypeHost:
		if x.Status.Host != "" {
			return "host " + x.Status.Host
		}
	case v1.IPTypeProvider:
		return strings.TrimSpace(x.Spec.Provider + " " + x.Spec.Region)
	}
	return ""
}

// ipSet is the IP's set and ordinal (SET#N), when it's a member of one.
func ipSet(x *v1.IP) string {
	set := x.Labels[v1.LabelIPSet]
	if set == "" {
		return ""
	}
	if o := x.Labels[v1.LabelIPSetOrdinal]; o != "" {
		return set + "#" + o
	}
	return set
}

// ipMoves says whether the address goes with its holder when the holder moves.
func ipMoves(x *v1.IP) string {
	switch x.Spec.Type {
	case v1.IPTypeHost:
		return "no: pinned to its host"
	case v1.IPTypeProvider:
		return "within " + strings.TrimSpace(x.Spec.Provider+" "+x.Spec.Region)
	}
	return "-"
}

// ipFrom is where an IP comes from, as its spec says it.
func ipFrom(x *v1.IP) string {
	switch x.Spec.Type {
	case v1.IPTypeHost:
		return "Host (host address " + x.Spec.HostAddress + ")"
	case v1.IPTypeProvider:
		return "Provider (" + x.Spec.Provider + ", region " + x.Spec.Region + ")"
	}
	return dash(x.Spec.Type)
}

func describeIPInto(kv func(int, string, any), x *v1.IP, env *netEnv) {
	if x.DeletionTimestamp != nil {
		kv(0, "Releasing", "its address goes back once it's deleted")
	}
	kv(0, "Type", ipFrom(x))
	kv(0, "Family", x.Spec.FamilyOrDefault())
	kv(0, "Address", dash(x.Status.Address))
	where := dash(ipWhere(x))
	if x.Spec.Type == v1.IPTypeHost && x.Status.Host == "" {
		if h := env.addressHost(x.Spec.HostAddress); h != "" {
			where = "host " + h
		} else if env != nil && env.hosts != nil {
			where = "no host has an address named " + x.Spec.HostAddress + " (kvoadm host addresses HOST add " + x.Spec.HostAddress + " ADDRESS --external)"
		}
	}
	kv(0, "Where", where)
	switch x.Spec.Type {
	case v1.IPTypeHost:
		kv(0, "Moves", "no: a host's address stays on its host, so its holder runs there")
	case v1.IPTypeProvider:
		kv(0, "Moves", "with its holder, within "+x.Spec.Provider+" "+x.Spec.Region+" (the new worker announces it)")
	}
	if set := ipSet(x); set != "" {
		kv(0, "Set", set+" (kvo describe ipset "+x.Labels[v1.LabelIPSet]+")")
	}
	kv(0, "Used by", dash(x.Status.Holders()))
	if h := x.Status.Holder; h != nil && strings.HasPrefix(h.Holder, v1.HolderSiloPrefix) {
		if s := env.silo(x.Namespace, strings.TrimPrefix(h.Holder, v1.HolderSiloPrefix)); s != nil {
			kv(1, "In and out", s.Status.Service.AddressesLine())
		}
	}
	for _, w := range x.Status.Waiting {
		kv(0, "Waiting", w.Holder+": "+w.Reason)
	}
	if x.Status.Holder != nil {
		kv(0, "Deleting", "refused while "+x.Status.Holder.Holder+" uses it: delete that one first, or have it name no IP")
	} else {
		kv(0, "Deleting", "releases the address (kvo delete ip "+x.Name+")")
	}
}

// ── IP sets ──────────────────────────────────────────────────────────────────

var ipsetHead = []string{"TYPE", "MEMBERS", "USED", "MAX"}

func ipsetRow(x *v1.IPSet) []string {
	members, used := len(x.Spec.Members), 0
	if x.Spec.Type == v1.IPSetDynamic {
		members = len(x.Status.Members)
	}
	for _, m := range x.Status.Members {
		if m.UsedBy != "" {
			used++
		}
	}
	limit := strconv.Itoa(len(x.Spec.Members))
	if x.Spec.Type == v1.IPSetDynamic {
		limit = strconv.Itoa(x.Spec.Max)
	}
	return []string{dash(x.Spec.Type), strconv.Itoa(members), strconv.Itoa(used), limit}
}

func describeIPSetInto(kv func(int, string, any), tw io.Writer, x *v1.IPSet, env *netEnv) func() {
	switch x.Spec.Type {
	case v1.IPSetStatic:
		kv(0, "Type", "Static (the members listed: it never grows on its own; add members at the end)")
	case v1.IPSetDynamic:
		kv(0, "Type", fmt.Sprintf("Dynamic (%s IPs in %s, reserved as instances need them, up to %d)", x.Spec.Provider, x.Spec.Region, x.Spec.Max))
	default:
		kv(0, "Type", dash(x.Spec.Type))
	}
	if env != nil && env.silosets != nil {
		var by []string
		for _, ss := range env.silosets {
			if ss.Namespace == x.Namespace && ss.Spec.IPs == x.Name {
				by = append(by, "siloset/"+ss.Name)
			}
		}
		kv(0, "Used by", dash(strings.Join(by, ", ")))
	}
	got := map[int]v1.IPSetMemberStatus{}
	n := len(x.Spec.Members)
	for _, m := range x.Status.Members {
		got[m.Ordinal] = m
		n = max(n, m.Ordinal+1)
	}
	if n == 0 {
		return func() {
			_, _ = fmt.Fprintln(tw, "Members:\tnone yet")
		}
	}
	return func() {
		_, _ = fmt.Fprintln(tw, "Members:")
		_, _ = fmt.Fprintln(tw, "  ORDINAL\tMEMBER\tIP\tADDRESS\tUSED BY")
		for i := range n {
			member := "-"
			if i < len(x.Spec.Members) {
				member = x.Spec.Members[i].String()
			} else if x.Spec.Type == v1.IPSetDynamic {
				member = "reserved"
			}
			st := got[i]
			ipName := st.IP
			if ipName == "" {
				switch {
				case i < len(x.Spec.Members) && x.Spec.Members[i].IP != "":
					ipName = x.Spec.Members[i].IP
				case x.Spec.Type == v1.IPSetDynamic:
					ipName = v1.DynamicMemberName(x.Name, i)
				}
			}
			addr := st.Address
			if addr == "" {
				if ip := env.ip(x.Namespace, ipName); ip != nil {
					addr = ip.Status.Address
				}
			}
			_, _ = fmt.Fprintf(tw, "  %d\t%s\t%s\t%s\t%s\n", i, member, dash(ipName), dash(addr), dash(st.UsedBy))
		}
	}
}

// ── a silo's services ────────────────────────────────────────────────────────

// writeSiloServices is a silo's services, one per row: its type and way in, its ports (PORT or
// PORT→AS) and where each is reachable.
func writeSiloServices(w io.Writer, s *v1.Silo, env *netEnv) {
	_, _ = fmt.Fprintln(w, "Services:")
	_, _ = fmt.Fprintln(w, "  NAME\tTYPE\tWAY IN\tPORTS\tREACHABLE AT")
	for _, sv := range s.Spec.Services {
		var ports []string
		for _, p := range sv.Ports {
			if p.As != 0 {
				ports = append(ports, fmt.Sprintf("%s→%d", p.Port, p.As))
			} else {
				ports = append(ports, p.Port)
			}
		}
		_, _ = fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n", v1.ServiceNameOf(sv, s.Name), sv.TypeOrDefault(), wayIn(sv),
			dash(strings.Join(ports, ", ")), dash(strings.Join(reachable(s, sv, env), ", ")))
	}
}

// wayIn is the service's way in as a person writes it.
func wayIn(sv v1.SiloService) string {
	switch sv.TypeOrDefault() {
	case v1.ServiceHostPort:
		return sv.Way().String()
	case v1.ServiceLoadBalancer:
		if l := sv.LoadBalancer; l != nil {
			if l.IP != "" {
				return "provider: " + l.Provider + ", ip: " + l.IP
			}
			return "provider: " + l.Provider
		}
	}
	return "mesh"
}

// reachable says where each of a service's ports is reachable: ADDRESS:PORT once known, else
// what it waits for.
func reachable(s *v1.Silo, sv v1.SiloService, env *netEnv) []string {
	st := map[string]v1.ServicePortStatus{}
	for _, p := range s.Status.Service.Ports {
		st[p.Port] = p
	}
	number := func(p v1.ServicePort) int {
		if p.As != 0 {
			return p.As
		}
		if d, ok := s.Spec.Declared(p.Port); ok {
			return d.Port
		}
		return 0
	}
	var out []string
	add := func(s string) {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	for _, p := range sv.Ports {
		n := number(p)
		switch sv.TypeOrDefault() {
		case v1.ServiceInternal:
			who := "no silo allowed (allowFrom is empty)"
			if len(p.AllowFrom) > 0 {
				who = "from " + strings.Join(p.AllowFrom, ", ")
			}
			at := "silo IP"
			if s.Status.SiloIP != "" {
				at = fmt.Sprintf("%s:%d", s.Status.SiloIP, n)
			}
			add(at + " " + who)
		case v1.ServiceHostPort:
			way := sv.Way()
			switch {
			case way.Worker != "":
				got := st[p.Port].External
				if way.Worker == v1.NetworkInternal {
					got = st[p.Port].Internal
				}
				if got != "" {
					add(got)
				} else {
					add(fmt.Sprintf("the worker's %s IP :%d (when placed)", way.Worker, n))
				}
			case way.IP != "":
				x := env.ip(s.Namespace, way.IP)
				switch {
				case x != nil && x.Status.Address != "":
					add(fmt.Sprintf("%s:%d", x.Status.Address, n))
				case x != nil:
					add(fmt.Sprintf("ip %s :%d (not reserved yet)", way.IP, n))
				case env != nil && env.ips != nil:
					add(fmt.Sprintf("ip %s :%d (no such IP yet: kvo create ip %s --type …)", way.IP, n, way.IP))
				default:
					add(fmt.Sprintf("ip %s :%d", way.IP, n))
				}
			case way.Own:
				add(fmt.Sprintf("the instance's IPSet member :%d", n))
			}
		case v1.ServiceLoadBalancer:
			addr := s.Status.Service.LoadBalancerIP
			if addr == "" && sv.LoadBalancer != nil && sv.LoadBalancer.IP != "" {
				if x := env.ip(s.Namespace, sv.LoadBalancer.IP); x != nil {
					addr = x.Status.Address
				}
			}
			if addr != "" {
				add(fmt.Sprintf("%s:%d", addr, n))
			} else {
				prov := "the provider"
				if sv.LoadBalancer != nil {
					prov = sv.LoadBalancer.Provider
				}
				add(fmt.Sprintf("the balancer :%d (once %s makes it)", n, prov))
			}
		}
	}
	return out
}

// ── a host's addresses ───────────────────────────────────────────────────────

// writeHostAddresses is a host's main and extra addresses, and who reserves or uses each.
func writeHostAddresses(w io.Writer, h *v1.Host, env *netEnv) {
	_, _ = fmt.Fprintln(w, "Addresses:")
	_, _ = fmt.Fprintln(w, "  NAME\tKIND\tFAMILY\tADDRESS\tRESERVED BY")
	usedBy := func(kind string) string {
		if env == nil || env.silos == nil {
			return "-"
		}
		var who []string
		for _, s := range env.silos {
			if s.Status.Host != h.Name {
				continue
			}
			for _, sv := range s.Spec.Services {
				if sv.Way().Worker == kind {
					who = append(who, s.Namespace+"/"+s.Name+" ("+v1.ServiceNameOf(sv, s.Name)+")")
				}
			}
		}
		if len(who) == 0 {
			return "-"
		}
		return "used by " + strings.Join(who, ", ") + " (worker: " + kind + ")"
	}
	_, _ = fmt.Fprintf(w, "  (main)\t%s\t%s\t%s\t%s\n", v1.NetworkExternal, v1.FamilyIPv4, dash(h.External()), usedBy(v1.NetworkExternal))
	if v6 := h.ExternalIPv6(); v6 != "" {
		_, _ = fmt.Fprintf(w, "  (main)\t%s\t%s\t%s\t%s\n", v1.NetworkExternal, v1.FamilyIPv6, v6, usedBy(v1.NetworkExternal))
	}
	_, _ = fmt.Fprintf(w, "  (main)\t%s\t%s\t%s\t%s\n", v1.NetworkInternal, v1.FamilyIPv4, dash(h.Internal()), usedBy(v1.NetworkInternal))
	for _, a := range h.Spec.Addresses {
		_, _ = fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n", a.Name, a.Kind, dash(a.Family()), a.Address, reservedBy(a.Name, env))
	}
}

// reservedBy is the IP reserving a host's extra address, and who uses it ("-" for none; empty
// when the IPs couldn't be read).
func reservedBy(name string, env *netEnv) string {
	if env == nil || env.ips == nil {
		return "-"
	}
	for _, x := range env.ips {
		if x.Spec.Type == v1.IPTypeHost && x.Spec.HostAddress == name {
			who := "ip " + x.Namespace + "/" + x.Name
			if x.Status.Holder != nil {
				who += ", used by " + x.Status.Holders()
			}
			return who
		}
	}
	return "- (free: an IP with type: Host, hostAddress: " + name + " reserves it)"
}
