package apiserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/ips"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/internal/rbac"
	"kevaso.com/core/internal/store"
)

// IP objects at admission (networking v2). A guard, so it runs on the object as stored (after
// mutation policies), reading the store for what the pure checks can't see:
//   - naming an IP (hostPort.ip, loadBalancer.ip, egress.source.ip, a Service's loadBalancer.ip)
//     needs use on ips/NAME, like a secret, the first time an object names it; a SiloSet's
//     spec.ips needs use on ipsets/NAME;
//   - a balancer's kept IP (loadBalancer.ip) is a Provider IP of the balancer's provider (and
//     checkProviders: only where the provider lets a kept IP front a balancer);
//   - the Host IPs a silo names are all one host's (each is pinned to its host);
//   - a host's extra addresses have names unique in the cluster, addresses on one host, and the
//     ones reserved by an IP stay.
//
// An IP that doesn't exist yet, or one held by another silo, could work later: the holder waits,
// and says why. Deleting a held IP is refused in delete (checkDeleteIP).

func (s *Server) checkIPs(ctx context.Context, t target, obj meta.Object) error {
	if t.status {
		return nil
	}
	switch o := obj.(type) {
	case *v1.Silo:
		named := o.Spec.NamedIPs()
		balancer := map[string]string{} // IP → the provider of the balancer naming it
		for _, sv := range o.Spec.Balancers() {
			if sv.LoadBalancer != nil && sv.LoadBalancer.IP != "" {
				balancer[sv.LoadBalancer.IP] = sv.LoadBalancer.Provider
			}
		}
		return s.checkNamedIPs(ctx, t, named, balancer)
	case *v1.SiloSet:
		if n := o.Spec.IPs; n != "" {
			return s.checkUse(ctx, t, "ipsets", n, "IPSet")
		}
	case *v1.Service:
		if l := o.Spec.LoadBalancer; l != nil && l.IP != "" {
			return s.checkNamedIPs(ctx, t, []v1.NamedIP{{Name: l.IP, Field: "spec.loadBalancer.ip"}}, map[string]string{l.IP: l.Provider})
		}
	case *v1.Host:
		return s.checkHostAddresses(ctx, t, o)
	}
	return nil
}

// previousNames are the IP (or IPSet) names the stored version of the object already names.
func (s *Server) previousNames(ctx context.Context, t target) []string {
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
		return v1.SiloIPs(o)
	case *v1.SiloSet:
		return []string{o.Spec.IPs}
	case *v1.Service:
		return []string{o.Spec.LoadBalancerIP()}
	}
	return nil
}

// checkUse: naming resource/name the first time needs use on it.
func (s *Server) checkUse(ctx context.Context, t target, resource, name, kind string) error {
	user, isPerson := person(ctx)
	if !isPerson || s.auth == nil || slices.Contains(s.previousNames(ctx, t), name) {
		return nil
	}
	p, err := s.policy.Policy(ctx)
	if err != nil {
		return err
	}
	d := p.Authorize(rbac.Attributes{User: user, Groups: GroupsFrom(ctx), Verb: v1.VerbUse, Resource: resource, Namespace: t.namespace, Name: name})
	if !d.Allowed {
		return errf(http.StatusForbidden, "Forbidden", "%s may not use %s %s (needs use on %s): %s", user, kind, name, resource, d.Reason)
	}
	return nil
}

func (s *Server) checkNamedIPs(ctx context.Context, t target, named []v1.NamedIP, balancer map[string]string) error {
	if len(named) == 0 {
		return nil
	}
	var found []*v1.IP
	for _, n := range named {
		if err := s.checkUse(ctx, t, "ips", n.Name, "IP"); err != nil {
			return err
		}
		cur, err := s.store.Get(ctx, store.Key{Kind: "IP", Namespace: t.namespace, Name: n.Name})
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
		found = append(found, x)
		if prov, ok := balancer[n.Name]; ok {
			switch {
			case x.Spec.Type != v1.IPTypeProvider:
				return errf(http.StatusUnprocessableEntity, "Invalid", "%s %s: loadBalancer.ip %s is a host's address (type Host): a balancer is the provider's, so it can only take a Provider IP of %s; leave ip out (the balancer has its own address) or use a HostPort service on it",
					t.kind.Kind, t.name, n.Name, prov)
			case x.Spec.Provider != prov:
				return errf(http.StatusUnprocessableEntity, "Invalid", "%s %s: loadBalancer.ip %s is %s's, and the balancer is %s's: name an IP of %s, or the provider %s",
					t.kind.Kind, t.name, n.Name, x.Spec.Provider, prov, prov, x.Spec.Provider)
			}
		}
	}
	if t.kind.Kind != "Silo" {
		return nil
	}
	hosts, err := listAs[*v1.Host](ctx, s.store, "Host")
	if err != nil {
		return err
	}
	if why := ips.Together(found, hosts); why != "" {
		return errf(http.StatusUnprocessableEntity, "Invalid", "%s %s: %s", t.kind.Kind, t.name, why)
	}
	return nil
}

// SetNetworking gives the server the providers' declared networking (the plugin registry):
// admission checks balancers, Provider IPs and their annotations against it. nil: unchecked.
func (s *Server) SetNetworking(n plugins.Networking) { s.networking = n }

// checkProviders: what a provider must say yes to, or it can never work. A LoadBalancer
// service needs a provider that makes balancers, annotations it declares, and a kept IP in
// front only where the provider allows one; a Provider IP needs a provider that makes them in
// its region, and annotations it declares. A provider not installed is refused too, naming the
// installed ones (a plugin restarting is held by the registry, not dropped).
func (s *Server) checkProviders(_ context.Context, t target, obj meta.Object) error {
	if t.status || s.networking == nil {
		return nil
	}
	n := s.networking
	refuse := func(err error) error {
		return errf(http.StatusUnprocessableEntity, "Invalid", "%s %s: %v", t.kind.Kind, t.name, err)
	}
	balancer := func(field string, l *v1.LoadBalancerSpec, annotations map[string]string) error {
		if err := n.ValidateLoadBalancer(l.Provider); err != nil {
			return refuse(fmt.Errorf("%s: %w", field, err))
		}
		if err := n.ValidateServiceAnnotations(l.Provider, annotations); err != nil {
			return refuse(fmt.Errorf("%s: %w", field, err))
		}
		if l.IP != "" && !n.CanFrontWithIP(l.Provider) {
			return refuse(fmt.Errorf("%s.ip %s: %s's balancer has an address of its own, so a kept IP can't front it: leave ip out (the balancer's address comes with the service), or use a HostPort service on the IP", field, l.IP, l.Provider))
		}
		return nil
	}
	services := func(prefix string, svs []v1.SiloService) error {
		for i, sv := range svs {
			if sv.TypeOrDefault() == v1.ServiceLoadBalancer && sv.LoadBalancer != nil {
				if err := balancer(fmt.Sprintf("%sservices[%d].loadBalancer", prefix, i), sv.LoadBalancer, sv.Annotations); err != nil {
					return err
				}
			}
		}
		return nil
	}
	switch o := obj.(type) {
	case *v1.Silo:
		return services("", o.Spec.Services)
	case *v1.SiloSet:
		return services("template.", o.Spec.Template.Services)
	case *v1.Service:
		if o.Spec.TypeOrDefault() == v1.ServiceLoadBalancer && o.Spec.LoadBalancer != nil {
			return balancer("spec.loadBalancer", o.Spec.LoadBalancer, o.Annotations)
		}
	case *v1.IP:
		if o.Spec.Type != v1.IPTypeProvider {
			return nil
		}
		if err := n.ValidateProviderIP(o.Spec.Provider, o.Spec.Region); err != nil {
			return refuse(fmt.Errorf("spec: %w", err))
		}
		if err := n.ValidateIPAnnotations(o.Spec.Provider, o.Annotations); err != nil {
			return refuse(err)
		}
	}
	return nil
}

func (s *Server) checkHostAddresses(ctx context.Context, t target, h *v1.Host) error {
	var prev []v1.HostAddress
	if cur, err := s.store.Get(ctx, t.key()); err == nil {
		o, _, err := v1.Decode(cur.Data)
		if err != nil {
			return err
		}
		prev = o.(*v1.Host).Spec.Addresses
		if slices.Equal(prev, h.Spec.Addresses) {
			return nil
		}
	}
	if len(prev) > 0 {
		all, err := listAs[*v1.IP](ctx, s.store, "IP")
		if err != nil {
			return err
		}
		if why := ips.CheckHostAddresses(h.Name, h.Spec.Addresses, all); why != "" {
			return errf(http.StatusConflict, "Conflict", "host %s: %s", h.Name, why)
		}
	}
	hosts, err := listAs[*v1.Host](ctx, s.store, "Host")
	if err != nil {
		return err
	}
	mine := false
	for i, o := range hosts {
		if o.Name == h.Name {
			hosts[i], mine = h, true
		}
	}
	if !mine {
		hosts = append(hosts, h)
	}
	if why := ips.Duplicates(hosts); why != "" {
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
