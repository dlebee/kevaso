package apiserver

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	kicdrivers "kevaso.com/core/builtin/kic"
	"kevaso.com/core/internal/audit"
	"kevaso.com/core/internal/controllers/certificate"
	"kevaso.com/core/internal/ingress"
	"kevaso.com/core/internal/rbac"
	"kevaso.com/core/internal/store"
)

// checkPublishPublic: putting an Ingress on a public class (reachable from the internet) is its
// own permission, create on ingresses/publish-public in the namespace, on top of writing the
// Ingress (design §7.3), so nobody exposes something to the internet by accident.
func (s *Server) checkPublishPublic(ctx context.Context, t target, obj meta.Object) error {
	ing, ok := obj.(*v1.Ingress)
	if !ok || t.status {
		return nil
	}
	o, err := s.store.Get(ctx, store.Key{Kind: "IngressClass", Name: ing.Spec.IngressClass})
	if err != nil {
		return errf(http.StatusUnprocessableEntity, "Invalid", "Ingress %s: ingress class %q doesn't exist", ing.Name, ing.Spec.IngressClass)
	}
	c, _, err := v1.Decode(o.Data)
	if err != nil {
		return err
	}
	public := c.(*v1.IngressClass).Spec.Public
	if public && ing.Spec.TLS.None {
		return errf(http.StatusUnprocessableEntity, "Invalid", "Ingress %s: tls.none (plain HTTP) is for private classes; %s is public", ing.Name, ing.Spec.IngressClass)
	}
	user, isPerson := person(ctx)
	if !isPerson || s.auth == nil || !public {
		return nil
	}
	if old, err := s.store.Get(ctx, t.key()); err == nil { // already on this class: nothing new
		if prev, _, err := v1.Decode(old.Data); err == nil && prev.(*v1.Ingress).Spec.IngressClass == ing.Spec.IngressClass {
			return nil
		}
	}
	p, err := s.policy.Policy(ctx)
	if err != nil {
		return err
	}
	d := p.Authorize(rbac.Attributes{User: user, Groups: GroupsFrom(ctx), Verb: "create", Resource: "ingresses/publish-public", Namespace: t.namespace})
	if !d.Allowed {
		return errf(http.StatusForbidden, "Forbidden", "%s may not publish on the public class %s (needs create on ingresses/publish-public): %s", user, ing.Spec.IngressClass, d.Reason)
	}
	return nil
}

// agentIngress answers a host's agent with the desired state of an ingress controller silo placed
// on it (design §7.3): the routes, certificates (keys included) and ACME challenges of its class,
// for the agent to render with the class's driver and apply to the stock proxy from outside. Only
// the silo's own host gets it, as the broker gives secrets only to a silo's host; every answer
// carrying keys is audited.
func (s *Server) agentIngress(w http.ResponseWriter, r *http.Request) {
	id, ok := IdentityFrom(r.Context())
	if s.auth == nil { // kevasod dev: no authentication, it's all one process
		id, ok = Component, true
	}
	if !ok || (id.Type != "host" && id != Component) || r.Method != http.MethodGet {
		writeErr(w, errf(http.StatusForbidden, "Forbidden", "only hosts get ingress controllers' configuration"))
		return
	}
	ctx := r.Context()
	ns, name := r.URL.Query().Get("namespace"), r.URL.Query().Get("name")
	o, err := s.store.Get(ctx, store.Key{Kind: "Silo", Namespace: ns, Name: name})
	if err != nil {
		writeErr(w, errf(http.StatusNotFound, "NotFound", "silo %s/%s: %v", ns, name, err))
		return
	}
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		writeErr(w, err)
		return
	}
	silo := obj.(*v1.Silo)
	if id != Component && silo.Status.Host != id.Name {
		writeErr(w, errf(http.StatusForbidden, "Forbidden", "silo %s/%s isn't placed on host %s", ns, name, id.Name))
		return
	}
	d, err := s.ingressDesired(ctx, silo)
	if err != nil {
		writeErr(w, err)
		return
	}
	if s.auth != nil && s.auth.Audit != nil && len(d.State.Certificates) > 0 {
		names := make([]string, 0, len(d.State.Certificates))
		for _, c := range d.State.Certificates {
			names = append(names, c.Name)
		}
		s.auth.Audit.Record(audit.Entry{Time: s.clock.Now(), Event: "ingress", User: "system:host:" + id.Name, Type: "host", Verb: "get",
			Resource: "secrets", Namespace: ns, Name: name, Allowed: true,
			Reason: "ingress class " + d.Class + " certificates for its controller silo: " + strings.Join(names, ", ")})
	}
	writeJSON(w, http.StatusOK, d)
}

// ingressDesired is the desired state of the class silo is the controller of.
func (s *Server) ingressDesired(ctx context.Context, silo *v1.Silo) (ingress.Desired, error) {
	classes, _, err := s.store.List(ctx, store.Selector{Kind: "IngressClass"})
	if err != nil {
		return ingress.Desired{}, err
	}
	var mine []*v1.IngressClass
	for _, o := range classes {
		if c, _, err := v1.Decode(o.Data); err == nil && c.(*v1.IngressClass).Spec.Controller.Runs(silo) {
			mine = append(mine, c.(*v1.IngressClass))
		}
	}
	switch len(mine) {
	case 0:
		return ingress.Desired{}, errf(http.StatusNotFound, "NotFound", "silo %s/%s isn't the controller of any ingress class", silo.Namespace, silo.Name)
	case 1:
	default:
		sort.Slice(mine, func(i, j int) bool { return mine[i].Name < mine[j].Name })
		return ingress.Desired{Class: mine[0].Name, Driver: mine[0].Spec.Controller.Driver,
			Problem: fmt.Sprintf("silo %s/%s is the controller of classes %s and %s: one class per controller", silo.Namespace, silo.Name, mine[0].Name, mine[1].Name)}, nil
	}
	class := mine[0]
	objs, _, err := s.store.List(ctx, store.Selector{Kind: "Ingress"})
	if err != nil {
		return ingress.Desired{}, err
	}
	var ings []*v1.Ingress
	for _, o := range objs {
		if obj, _, err := v1.Decode(o.Data); err == nil {
			ings = append(ings, obj.(*v1.Ingress))
		}
	}
	challenges, err := certificate.Pending(ctx, s.store, s.clock.Now())
	if err != nil {
		return ingress.Desired{}, err
	}
	in := ingress.Inputs{Class: class, Ingresses: ings, Challenges: challenges,
		Silo: func(ns, name string) *v1.Silo {
			o, err := s.store.Get(ctx, store.Key{Kind: "Silo", Namespace: ns, Name: name})
			if err != nil {
				return nil
			}
			obj, _, err := v1.Decode(o.Data)
			if err != nil {
				return nil
			}
			return obj.(*v1.Silo)
		},
		// Routed: nil, the default (running, with an address). Probes put routeWhen's decision here.
	}
	if d, err := kicdrivers.Builtin().Get(class.Spec.Controller.Driver); err == nil {
		in.Driver = d
	}
	if s.vault != nil {
		in.Bundle = func(ns, name string) []byte {
			o, err := s.store.Get(ctx, store.Key{Kind: "Secret", Namespace: ns, Name: name})
			if err != nil {
				return nil
			}
			obj, _, err := v1.Decode(o.Data)
			if err != nil {
				return nil
			}
			value, _, err := s.vault.Value(ctx, obj.(*v1.Secret))
			if err != nil {
				return nil // not issued yet
			}
			return value
		}
	}
	return ingress.Desire(in), nil
}
