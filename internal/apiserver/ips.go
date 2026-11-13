package apiserver

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/ips"
	"kevaso.com/core/internal/rbac"
	"kevaso.com/core/internal/store"
)

// IP objects (design §7.2c-1) at admission. A guard, so it runs on the object as stored (after
// mutation policies):
//   - naming an IP (a silo's loadBalancer.ip or egress.ip, a Service's loadBalancerIP) needs use on
//     ips/NAME, like a secret, the first time an object names it, and its class must be the
//     service's; on any IP a service would be on (named, or the namespace's default for its class),
//     a port another holder has there is refused, saying who has it, and so is an exclusive address
//     (one host's at a time) someone else holds;
//   - egress.source sameAsService is refused for a class whose address is on no host (a balancer
//     in front), when the class is known (otherwise the silo says so and it's never applied);
//   - an IP's class, and its placement once it has an address, never change (one of a class that
//     can't reserve gets its address from the balancer when a service first holds it);
//   - a host's extra addresses in use by an IP stay, and no address is routed to two hosts.
//
// Deleting a bound IP is refused in delete (checkDeleteIP).

func (s *Server) checkIPs(ctx context.Context, t target, obj meta.Object) error {
	if t.status {
		return nil
	}
	classes := s.classMap()
	excl := func(class string) bool { return class == v1.LBIPPool || classes[class].Exclusive }
	switch o := obj.(type) {
	case *v1.Silo:
		if err := s.checkSameAsService(t, o); err != nil {
			return err
		}
		var named []namedIP
		if sv := o.Spec.Service; sv != nil && sv.LoadBalancer != nil {
			class := sv.LoadBalancer.Class
			if n, way := v1.SiloServiceIP(o, excl(class)); way == v1.IPNamed || way == v1.IPDefault {
				named = append(named, namedIP{n, class, "service.loadBalancer.ip", way == v1.IPNamed, excl(class), v1.SiloPorts(o)})
			}
		}
		if n := o.Spec.Network.Egress.IP; n != "" {
			named = append(named, namedIP{n, v1.LBIPPool, "network.egress.ip", true, true, nil})
		}
		return s.checkNamedIPs(ctx, t, v1.HolderSiloPrefix+o.Name, o.UID, named)
	case *v1.SiloSet:
		return s.checkSameAsService(t, o.Instance(0, false))
	case *v1.Service:
		class := o.Spec.LoadBalancerClass
		n, way := v1.ServiceIP(o, excl(class))
		if way != v1.IPNamed && way != v1.IPDefault {
			return nil
		}
		return s.checkNamedIPs(ctx, t, v1.HolderServicePrefix+o.Name, o.UID,
			[]namedIP{{n, class, "spec.loadBalancerIP", way == v1.IPNamed, excl(class), v1.ServicePorts(o)}})
	case *v1.Host:
		return s.checkHostAddresses(ctx, t, o)
	}
	return nil
}

// namedIP is an IP a service would be on: named (needs use), or its class's default.
type namedIP struct {
	name, class, field string
	named, exclusive   bool
	ports              []string
}

// previousIPs are the IP names the stored version of the object already names.
func (s *Server) previousIPs(ctx context.Context, t target) []string {
	cur, err := s.store.Get(ctx, t.key())
	if err != nil {
		return nil
	}
	prev, _, err := v1.Decode(cur.Data)
	if err != nil {
		return nil
	}
	switch o := prev.(type) {
	case *v1.Silo:
		var out []string
		if sv := o.Spec.Service; sv != nil && sv.LoadBalancer != nil && sv.LoadBalancer.IP != "" {
			out = append(out, sv.LoadBalancer.IP)
		}
		if n := o.Spec.Network.Egress.IP; n != "" {
			out = append(out, n)
		}
		return out
	case *v1.Service:
		return []string{o.Spec.LoadBalancerIP}
	}
	return nil
}

func (s *Server) checkNamedIPs(ctx context.Context, t target, holder, uid string, named []namedIP) error {
	if len(named) == 0 {
		return nil
	}
	had := s.previousIPs(ctx, t)
	user, isPerson := person(ctx)
	var p *rbac.Policy
	if isPerson && s.auth != nil {
		var err error
		if p, err = s.policy.Policy(ctx); err != nil {
			return err
		}
	}
	for _, n := range named {
		if p != nil && n.named && !slices.Contains(had, n.name) {
			d := p.Authorize(rbac.Attributes{User: user, Groups: GroupsFrom(ctx), Verb: v1.VerbUse, Resource: "ips", Namespace: t.namespace, Name: n.name})
			if !d.Allowed {
				return errf(http.StatusForbidden, "Forbidden", "%s may not use IP %s (needs use on ips): %s", user, n.name, d.Reason)
			}
		}
		cur, err := s.store.Get(ctx, store.Key{Kind: "IP", Namespace: t.namespace, Name: n.name})
		if errors.Is(err, store.ErrNotFound) {
			continue // not made yet: the holder waits for it, and says so
		}
		if err != nil {
			return err
		}
		obj, _, err := v1.Decode(cur.Data)
		if err != nil {
			return err
		}
		x := obj.(*v1.IP)
		if x.Spec.Class != n.class {
			return errf(http.StatusUnprocessableEntity, "Invalid", "%s %s: %s %s is IP of class %s, not %s", t.kind.Kind, t.name, n.field, n.name, x.Spec.Class, n.class)
		}
		if why := ips.CanName(x, n.exclusive, holder, uid, n.ports); why != "" {
			return errf(http.StatusConflict, "Conflict", "%s %s: %s", t.kind.Kind, t.name, why)
		}
	}
	return nil
}

// checkSameAsService refuses egress.source sameAsService where the address is on no host: a
// plugin's class that says it can't be sent from (a balancer in front). A class no plugin serves
// now is let through; the silo's status says out is the host's until a plugin says otherwise.
func (s *Server) checkSameAsService(t target, silo *v1.Silo) error {
	if silo == nil || silo.Spec.Network.Egress.Source != v1.EgressSameAsService {
		return nil
	}
	class := v1.PluginLB(silo)
	if class == "" {
		return nil
	}
	c, ok := s.classMap()[class]
	if !ok || c.SendsFrom {
		return nil
	}
	return errf(http.StatusUnprocessableEntity, "Invalid",
		"%s %s: egress.source sameAsService: %s's address is its balancer's, on no host, so nothing can send from it (use host, or pool with an IP of class ip-pool; design §7.2b)",
		t.kind.Kind, t.name, class)
}

// ipTransition: an IP's class, and its placement once it has an address, never change.
func ipTransition(o, x *v1.IP) []string {
	if o.Spec.Class != x.Spec.Class {
		return []string{"spec.class can't change (it's " + o.Spec.Class + "): make another IP"}
	}
	if o.Status.Address != "" && (o.Spec.Host != x.Spec.Host || o.Spec.Region != x.Spec.Region || o.Spec.Address != x.Spec.Address) {
		return []string{"spec.host, spec.region and spec.address can't change once it has its address (" + o.Status.Address + ")"}
	}
	return nil
}

func (s *Server) checkHostAddresses(ctx context.Context, t target, h *v1.Host) error {
	cur, err := s.store.Get(ctx, t.key())
	if err != nil {
		return nil //nolint:nilerr // a new host holds nothing yet; the overlap check needs no old one
	}
	prev, _, err := v1.Decode(cur.Data)
	if err != nil {
		return err
	}
	if slices.Equal(prev.(*v1.Host).Spec.Network.Addresses, h.Spec.Network.Addresses) {
		return nil
	}
	all, err := listAs[*v1.IP](ctx, s.store, "IP")
	if err != nil {
		return err
	}
	if why := ips.CheckHostAddresses(h.Name, h.Spec.Network.Addresses, all); why != "" {
		return errf(http.StatusConflict, "Conflict", "host %s: %s", h.Name, why)
	}
	hosts, err := listAs[*v1.Host](ctx, s.store, "Host")
	if err != nil {
		return err
	}
	for i, o := range hosts {
		if o.Name == h.Name {
			hosts[i] = h
		}
	}
	if why := ips.Overlap(hosts); why != "" {
		return errf(http.StatusConflict, "Conflict", "host %s: %s", h.Name, why)
	}
	return nil
}

// checkDeleteIP refuses deleting an IP someone holds: the address would go from under it.
func checkDeleteIP(obj meta.Object) error {
	x, ok := obj.(*v1.IP)
	if !ok || x.DeletionTimestamp != nil {
		return nil
	}
	if why := ips.CanDelete(x); why != "" {
		return errf(http.StatusConflict, "Conflict", "%s", why)
	}
	return nil
}
