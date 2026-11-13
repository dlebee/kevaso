package apiserver

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/certificate"
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

// ingressConfig is what an ingress controller silo serves: the routes of every Ingress of the
// classes it's the controller of, their certificates, and pending ACME answers. A silo that
// controls no class gets nothing.
func (s *Server) ingressConfig(ctx context.Context, silo *v1.Silo) (*client.IngressConfig, int, error) {
	classes, _, err := s.store.List(ctx, store.Selector{Kind: "IngressClass"})
	if err != nil {
		return nil, 0, err
	}
	mine := map[string]*v1.IngressClass{}
	for _, o := range classes {
		if c, _, err := v1.Decode(o.Data); err == nil {
			ic := c.(*v1.IngressClass)
			if ic.Spec.Controller.Namespace == silo.Namespace && ic.Spec.Controller.Silo == silo.Name {
				mine[ic.Name] = ic
			}
		}
	}
	if len(mine) == 0 {
		return nil, 0, fmt.Errorf("silo %s/%s isn't the controller of any ingress class", silo.Namespace, silo.Name)
	}
	cfg := &client.IngressConfig{Challenges: map[string]string{}}
	ingresses, _, err := s.store.List(ctx, store.Selector{Kind: "Ingress"})
	if err != nil {
		return nil, 0, err
	}
	for _, o := range ingresses {
		obj, _, err := v1.Decode(o.Data)
		if err != nil {
			continue
		}
		ing := obj.(*v1.Ingress)
		if _, ok := mine[ing.Spec.IngressClass]; !ok || ing.DeletionTimestamp != nil {
			continue
		}
		tls := !ing.Spec.TLS.None
		for _, r := range ing.Spec.Rules {
			backend, ok := s.backend(ctx, ing.Namespace, r.Silo)
			if !ok {
				continue // the target or its port isn't there (yet)
			}
			path := r.Path
			if path == "" {
				path = "/"
			}
			for _, h := range ing.Spec.Hosts {
				cfg.Routes = append(cfg.Routes, client.IngressRoute{Host: strings.ToLower(h), Path: path, Backend: backend, TLS: tls, Ingress: ing.Namespace + "/" + ing.Name})
			}
		}
		if !tls || s.vault == nil {
			continue
		}
		cert := s.secretNamed(ctx, ing.Namespace, v1.TLSSecret(ing))
		if cert == nil {
			continue
		}
		bundle, _, err := s.vault.Value(ctx, cert)
		if err != nil {
			continue // not issued yet
		}
		cfg.Certs = append(cfg.Certs, client.IngressCert{Hosts: ing.Spec.Hosts, Bundle: bundle})
	}
	if cfg.Challenges, err = certificate.Pending(ctx, s.store, s.clock.Now()); err != nil {
		return nil, 0, err
	}
	sort.Slice(cfg.Routes, func(i, j int) bool {
		a, b := cfg.Routes[i], cfg.Routes[j]
		return a.Host < b.Host || (a.Host == b.Host && len(a.Path) > len(b.Path))
	})
	return cfg, len(mine), nil
}

// backend is a target silo's private name and the number of its named port.
func (s *Server) backend(ctx context.Context, ns string, t v1.IngressTarget) (string, bool) {
	o, err := s.store.Get(ctx, store.Key{Kind: "Silo", Namespace: ns, Name: t.Name})
	if err != nil {
		return "", false
	}
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		return "", false
	}
	sv := obj.(*v1.Silo).Spec.Service
	if sv == nil {
		return "", false
	}
	for _, p := range sv.Ports {
		if p.Name == t.Port {
			return fmt.Sprintf("%s.%s.kevaso:%d", t.Name, ns, p.Port), true
		}
	}
	return "", false
}
