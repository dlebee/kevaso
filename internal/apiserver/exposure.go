package apiserver

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/names"
)

// exposureRelevant is an object whose write can make a silo reachable from outside, or point an
// Ingress at a port that opens only on a lease.
func exposureRelevant(obj meta.Object) bool {
	switch obj.(type) {
	case *v1.Silo, *v1.SiloSet, *v1.Service, *v1.Ingress:
		return true
	default:
		return false
	}
}

// facet is one outside port, as the permission compares it. sources empty, or 0.0.0.0/0, is the
// world. lease is the port opening only on a lease; approval is that lease needing a yes.
type facet struct {
	proto, class        string
	number              int
	nets                []string
	lb, lease, approval bool
	sources             []string
}

func specOf(obj meta.Object) (v1.SiloSpec, bool) {
	switch o := obj.(type) {
	case *v1.Silo:
		return o.Spec, true
	case *v1.SiloSet:
		return o.Spec.Template.SiloSpec, true
	default:
		return v1.SiloSpec{}, false
	}
}

func facetsOf(spec v1.SiloSpec) map[string]facet {
	out := map[string]facet{}
	for _, p := range spec.Open() {
		if !p.Outside() {
			continue
		}
		f := facet{
			proto:    p.Protocol,
			number:   p.HostNumber(),
			lb:       p.LoadBalancer,
			lease:    p.Lease != nil,
			approval: p.Lease != nil && p.Lease.Approval != nil && p.Lease.Approval.Required,
			sources:  append([]string(nil), p.Sources...),
		}
		for _, sv := range spec.Services {
			if v1.ServiceNameOf(sv, "") == p.Service && sv.LoadBalancer != nil && p.LoadBalancer {
				f.class = sv.LoadBalancer.Provider + "/" + sv.LoadBalancer.IP
			}
		}
		if p.Type == v1.ServiceHostPort {
			f.nets = []string{p.Way.String()} // the address it arrives on: worker, an IP, own
		}
		out[p.Service+"/"+p.Name] = f
	}
	return out
}

// exposureLoosened reports whether obj reaches further outside than prev (nil prev: a create).
// Removing or tightening does not. silos, svcs and ings are the namespace's, for selectors and
// Ingress backends.
func exposureLoosened(prev, obj meta.Object, silos []*v1.Silo, svcs []*v1.Service, ings []*v1.Ingress) bool {
	if spec, ok := specOf(obj); ok {
		var old v1.SiloSpec
		if prev != nil {
			old, _ = specOf(prev)
		}
		if specLoosened(old, spec) { // a new or widened outside port
			return true
		}
	}
	if siloNewlyOnBalancer(prev, obj, silos, svcs, ings) { // a load balancer's selector newly matches this silo or set
		return true
	}
	if serviceLoosened(prev, obj, silos) { // a load balancer opens more, or its selector matches a new silo
		return true
	}
	if ingressOnLeasedPort(prev, obj, silos, svcs) { // an Ingress backend on a port that opens only on a lease
		return true
	}
	if serviceOpensLeasedIngress(prev, obj, silos, svcs, ings) { // a service an Ingress already names, on a leased port
		return true
	}
	return false
}

func specLoosened(old, next v1.SiloSpec) bool {
	return facetsLoosened(facetsOf(old), facetsOf(next))
}

func facetsLoosened(old, next map[string]facet) bool {
	for name, n := range next {
		o, ok := old[name]
		if !ok { // an outside port the stored object does not open
			return true
		}
		if facetLoosened(o, n) {
			return true
		}
	}
	return false
}

func facetLoosened(o, n facet) bool {
	if o.proto == "" {
		return false // a port the stored object does not open is decided above, not as a protocol change
	}
	if o.proto != n.proto || o.number != n.number { // protocol or the number on the host changed
		return true
	}
	if facetNetworkAdded(o, n) { // a host network the stored port did not open on
		return true
	}
	if facetBalancerAdded(o, n) { // load balancer newly set, or its class changed
		return true
	}
	if sourcesWider(o.sources, n.sources) { // a source removed, or a wider one added
		return true
	}
	if o.lease && !n.lease || o.approval && !n.approval { // a lease removed, or one that needed a yes made automatic
		return true
	}
	return false
}

func facetNetworkAdded(o, n facet) bool {
	have := map[string]bool{}
	for _, x := range o.nets {
		have[x] = true
	}
	for _, x := range n.nets {
		if !have[x] {
			return true
		}
	}
	return false
}

func facetBalancerAdded(o, n facet) bool {
	if !n.lb {
		return false
	}
	return !o.lb || o.class != n.class
}

// sourcesWider reports whether next lets in something old did not. Empty, and 0.0.0.0/0, are the
// world. A source that does not parse is not a widening: the port check refuses it.
func sourcesWider(old, next []string) bool {
	if world(next) {
		return !world(old)
	}
	if world(old) {
		return false
	}
	for _, n := range next {
		np, err := v1.ParseSource(n)
		if err != nil {
			continue
		}
		if !sourceHeld(old, np) {
			return true
		}
	}
	return false
}

func world(sources []string) bool {
	if len(sources) == 0 {
		return true
	}
	for _, s := range sources {
		p, err := v1.ParseSource(s)
		if err == nil && p.Bits() == 0 {
			return true
		}
	}
	return false
}

func sourceHeld(old []string, np netip.Prefix) bool {
	for _, o := range old {
		op, err := v1.ParseSource(o)
		if err != nil {
			continue
		}
		if op.Bits() <= np.Bits() && op.Contains(np.Addr()) {
			return true
		}
	}
	return false
}

func siloNewlyOnBalancer(prev, obj meta.Object, silos []*v1.Silo, svcs []*v1.Service, ings []*v1.Ingress) bool {
	nextLabels, ok := selectorLabels(obj)
	if !ok {
		return false
	}
	var oldLabels map[string]string
	if prev != nil {
		oldLabels, _ = selectorLabels(prev)
	}
	judged := silosWith(silos, obj)
	for _, sv := range svcs {
		if sv.DeletionTimestamp != nil {
			continue
		}
		if !v1.Selects(sv.Spec.Selector, nextLabels) || v1.Selects(sv.Spec.Selector, oldLabels) {
			continue
		}
		if sv.Spec.Type == v1.ServiceLoadBalancer { // this silo's or set's labels newly match a load balancer
			return true
		}
		if ingressNamesLeased(sv, judged, ings) { // a plain service an ingress already names, on a leased port
			return true
		}
	}
	return false
}

// silosWith is silos with the object being written in place of the stored copy, so a lease and
// the new labels are what the check sees. A SiloSet's instances are seen with the template
// labels being written: the stored ones still carry the previous labels.
func silosWith(silos []*v1.Silo, obj meta.Object) []*v1.Silo {
	switch o := obj.(type) {
	case *v1.Silo:
		out := append([]*v1.Silo{}, silos...)
		for i, cur := range out {
			if cur.Namespace == o.Namespace && cur.Name == o.Name {
				out[i] = o
				return out
			}
		}
		return append(out, o)
	case *v1.SiloSet:
		return silosWithSetTemplate(silos, o)
	default:
		return silos
	}
}

// silosWithSetTemplate is silos with this set's instances carrying the template labels being
// written. A service an ingress names is judged on those labels.
func silosWithSetTemplate(silos []*v1.Silo, set *v1.SiloSet) []*v1.Silo {
	labels := map[string]string{}
	for k, v := range set.Spec.Template.Labels {
		labels[k] = v
	}
	labels[v1.LabelSiloSet] = set.Name
	out := append([]*v1.Silo{}, silos...)
	for i, cur := range out {
		if cur.Namespace != set.Namespace || cur.Labels[v1.LabelSiloSet] != set.Name {
			continue
		}
		cp := *cur
		cp.Labels = labels // the template labels being written
		out[i] = &cp
	}
	return out
}

// ingressNamesLeased reports whether an Ingress already names sv and that backend is a leased port.
func ingressNamesLeased(sv *v1.Service, silos []*v1.Silo, ings []*v1.Ingress) bool {
	for _, ing := range ings {
		if ing.Namespace != sv.Namespace || ing.DeletionTimestamp != nil {
			continue
		}
		for _, rule := range ing.Spec.Rules {
			if rule.Service.Name != sv.Name {
				continue
			}
			if backendLeased(sv.Namespace, rule.Service, silos, []*v1.Service{sv}) {
				return true
			}
		}
	}
	return false
}

// selectorLabels are the labels a service matches: a Silo's own, or a SiloSet's template plus
// the set's own name (the labels its instances carry).
func selectorLabels(obj meta.Object) (map[string]string, bool) {
	switch o := obj.(type) {
	case *v1.Silo:
		return o.Labels, true
	case *v1.SiloSet:
		labels := map[string]string{}
		for k, v := range o.Spec.Template.Labels { // instances carry the template's labels
			labels[k] = v
		}
		labels[v1.LabelSiloSet] = o.Name
		return labels, true
	default:
		return nil, false
	}
}

func serviceLoosened(prev, obj meta.Object, silos []*v1.Silo) bool {
	next, ok := obj.(*v1.Service)
	if !ok || next.Spec.Type != v1.ServiceLoadBalancer {
		return false
	}
	old, _ := prev.(*v1.Service)
	if old == nil || old.Spec.Type != v1.ServiceLoadBalancer { // a new load balancer, or a service that became one
		return true
	}
	if serviceSelectorLoosened(old, next, silos) || servicePortsLoosened(old, next) || fmt.Sprint(old.Spec.LoadBalancer) != fmt.Sprint(next.Spec.LoadBalancer) { // a load balancer opens more, or its selector matches a new silo
		return true
	}
	return false
}

func serviceSelectorLoosened(old, next *v1.Service, silos []*v1.Silo) bool {
	if old == nil || next == nil {
		return false
	}
	for _, s := range silos {
		if v1.Selects(next.Spec.Selector, s.Labels) && !v1.Selects(old.Spec.Selector, s.Labels) {
			return true
		}
	}
	return false
}

func servicePortsLoosened(old, next *v1.Service) bool {
	if old == nil || next == nil {
		return false
	}
	have := map[string]v1.ServicePortSpec{}
	for _, p := range old.Spec.Ports {
		have[p.Name] = p
	}
	for _, p := range next.Spec.Ports {
		o, ok := have[p.Name]
		if !ok || o.Port != p.Port || protoName(o.Protocol) != protoName(p.Protocol) || o.TargetPort != p.TargetPort {
			return true
		}
	}
	return false
}

func protoName(p string) string {
	if strings.EqualFold(p, "UDP") {
		return "UDP"
	}
	return "TCP"
}

func ingressOnLeasedPort(prev, obj meta.Object, silos []*v1.Silo, svcs []*v1.Service) bool {
	next, ok := obj.(*v1.Ingress)
	if !ok {
		return false
	}
	oldSet := map[string]bool{}
	if p, ok := prev.(*v1.Ingress); ok {
		for _, r := range p.Spec.Rules {
			oldSet[r.Service.Name+"/"+r.Service.Port] = true
		}
	}
	for _, r := range next.Spec.Rules {
		key := r.Service.Name + "/" + r.Service.Port
		if oldSet[key] {
			continue
		}
		if backendLeased(next.Namespace, r.Service, silos, svcs) { // a backend the stored Ingress did not already target, on a leased port
			return true
		}
	}
	return false
}

// serviceOpensLeasedIngress reports whether creating a service, or changing its selector, makes
// an Ingress that already names it send traffic to a port that opens only on a lease. The Ingress
// may have been written while the service did not exist yet; this is that write's check, done
// when the service arrives or its selector changes.
func serviceOpensLeasedIngress(prev, obj meta.Object, silos []*v1.Silo, svcs []*v1.Service, ings []*v1.Ingress) bool {
	next, ok := obj.(*v1.Service)
	if !ok {
		return false
	}
	if old, _ := prev.(*v1.Service); old != nil && maps.Equal(old.Spec.Selector, next.Spec.Selector) {
		return false // the selector is unchanged: an Ingress of it was judged when it was written
	}
	with := append([]*v1.Service{}, svcs...)
	replaced := false
	for i, sv := range with {
		if sv.Namespace == next.Namespace && sv.Name == next.Name {
			with[i] = next
			replaced = true
			break
		}
	}
	if !replaced {
		with = append(with, next)
	}
	for _, ing := range ings {
		if ing.Namespace != next.Namespace || ing.DeletionTimestamp != nil {
			continue
		}
		for _, rule := range ing.Spec.Rules {
			if rule.Service.Name != next.Name {
				continue
			}
			if backendLeased(next.Namespace, rule.Service, silos, with) { // an ingress already names this service, on a leased port
				return true
			}
		}
	}
	return false
}

func backendLeased(ns string, tgt v1.IngressTarget, silos []*v1.Silo, svcs []*v1.Service) bool {
	silo, svc := names.Owner(ns, tgt.Name, silos, svcs)
	if silo != nil {
		p, ok := silo.Spec.OpenPort(tgt.Port)
		return ok && p.Lease != nil
	}
	if svc == nil {
		return false
	}
	var spec v1.ServicePortSpec
	found := false
	for _, p := range svc.Spec.Ports {
		if p.Name == tgt.Port {
			spec, found = p, true
			break
		}
	}
	if !found {
		return false
	}
	name := spec.TargetPort
	if name == "" {
		name = spec.Name
	}
	for _, s := range silos {
		if s.Namespace != ns || !v1.Selects(svc.Spec.Selector, s.Labels) {
			continue
		}
		if p, ok := s.Spec.OpenPort(name); ok && p.Lease != nil {
			return true
		}
	}
	return false
}

// exposureFacts is the part of a write a mutation policy must not widen on a caller the guards
// don't ask: each outside port's number, networks, sources and lease, a silo's labels, a load
// balancer's selector and ports, an Ingress's backends. Stable, so an unchanged object compares
// equal.
func exposureFacts(obj meta.Object) string {
	var b strings.Builder
	if spec, ok := specOf(obj); ok {
		fs := facetsOf(spec)
		names := make([]string, 0, len(fs))
		for n := range fs {
			names = append(names, n)
		}
		slices.Sort(names)
		for _, n := range names {
			f := fs[n]
			src := append([]string(nil), f.sources...)
			slices.Sort(src)
			fmt.Fprintf(&b, "%s:%s/%d:nets=%s:lb=%t:%s:src=%s:lease=%t:approval=%t;",
				n, f.proto, f.number, strings.Join(f.nets, "+"), f.lb, f.class, strings.Join(src, "+"), f.lease, f.approval)
		}
	}
	switch o := obj.(type) {
	case *v1.Silo:
		b.WriteString(labelFacts(o.Labels))
	case *v1.Service:
		if o.Spec.Type == v1.ServiceLoadBalancer {
			fmt.Fprintf(&b, "svc:%s:%v:", o.Spec.Type, o.Spec.LoadBalancer)
			b.WriteString(labelFacts(o.Spec.Selector))
			ports := append([]v1.ServicePortSpec(nil), o.Spec.Ports...)
			slices.SortFunc(ports, func(a, c v1.ServicePortSpec) int { return strings.Compare(a.Name, c.Name) })
			for _, p := range ports {
				fmt.Fprintf(&b, "%s/%d/%s/%s,", p.Name, p.Port, p.Protocol, p.TargetPort)
			}
		}
	case *v1.Ingress:
		keys := make([]string, 0, len(o.Spec.Rules))
		for _, r := range o.Spec.Rules {
			keys = append(keys, r.Service.Name+"/"+r.Service.Port)
		}
		slices.Sort(keys)
		fmt.Fprintf(&b, "ing:%s", strings.Join(keys, ","))
	}
	return b.String()
}

func labelFacts(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s,", k, m[k])
	}
	return b.String()
}
