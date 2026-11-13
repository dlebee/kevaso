// Package service is the controller of standalone Services (design §7.1): it gives each one a
// virtual IP from v1.ServiceCIDR and, for type LoadBalancer, a node port per port (cluster-wide,
// above the silos' own range), and keeps its endpoints: the silos its selector picks in its
// namespace, standby instances excluded, each with every port's target there; the ones routeWhen
// holds back are listed apart (held), with why (design §0.6). Every worker turns
// that status into rules (builtin/kni); the provider controllers give it its outside address.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/routing"
)

// Endpoints are the silos svc sends to now. Pure.
func Endpoints(svc *v1.Service, silos []*v1.Silo) []v1.ServiceEndpoint {
	routed, _ := Split(svc, silos)
	return routed
}

// Split is the silos svc selects, routed (its endpoints: what every path to it sends to) and held
// (selected, running somewhere, but routeWhen says no, or routeWhen isn't stated where it must
// be), each held one with why and since when (design §0.6). A held endpoint has no rule on any
// host and is no load-balancer backend; connections it already has are left alone. Pure.
func Split(svc *v1.Service, silos []*v1.Silo) (routed, held []v1.ServiceEndpoint) {
	for _, s := range silos {
		if s.Namespace != svc.Namespace || s.DeletionTimestamp != nil || s.Labels[v1.LabelStandby] == "true" ||
			!v1.Selects(svc.Spec.Selector, s.Labels) || s.Status.SiloIP == "" || s.Status.Host == "" {
			continue
		}
		ep := v1.ServiceEndpoint{Silo: s.Name, Host: s.Status.Host, SiloIP: s.Status.SiloIP}
		for _, p := range svc.Spec.Ports {
			if t := v1.TargetPort(p, s); t > 0 {
				ep.Ports = append(ep.Ports, v1.NodePort{Name: p.Name, Port: p.Port, NodePort: t})
			}
		}
		if len(ep.Ports) == 0 {
			continue
		}
		if r := routing.Endpoint(svc, s); r.Routed {
			routed = append(routed, ep)
		} else {
			ep.Reason, ep.Since = r.Reason, r.Since
			held = append(held, ep)
		}
	}
	v1.SortEndpoints(routed)
	v1.SortEndpoints(held)
	return routed, held
}

// ClusterIP keeps svc's virtual IP, or gives it the lowest free one. Pure.
func ClusterIP(svc *v1.Service, all []*v1.Service) (string, error) {
	cidr := netip.MustParsePrefix(v1.ServiceCIDR)
	taken := map[string]bool{}
	for _, o := range all {
		if o.UID != svc.UID && o.Status.ClusterIP != "" {
			taken[o.Status.ClusterIP] = true
		}
	}
	if cur := svc.Status.ClusterIP; cur != "" && !taken[cur] {
		if a, err := netip.ParseAddr(cur); err == nil && cidr.Contains(a) {
			return cur, nil
		}
	}
	for a := cidr.Addr().Next(); cidr.Contains(a); a = a.Next() {
		if a.As4()[3] == 0 || a.As4()[3] == 255 {
			continue
		}
		if !taken[a.String()] {
			return a.String(), nil
		}
	}
	return "", fmt.Errorf("no free address in %s", v1.ServiceCIDR)
}

// NodePorts keeps a LoadBalancer service's node ports, or gives each port the lowest free one in
// NodePortSiloMax+1…NodePortMax, among all services. Pure.
func NodePorts(svc *v1.Service, all []*v1.Service) ([]v1.NodePort, error) {
	if svc.Spec.Type != v1.ServiceLoadBalancer {
		return nil, nil
	}
	taken := map[int]bool{}
	for _, o := range all {
		if o.UID != svc.UID {
			for _, p := range o.Status.NodePorts {
				taken[p.NodePort] = true
			}
		}
	}
	had := map[string]int{}
	for _, p := range svc.Status.NodePorts {
		if !taken[p.NodePort] {
			had[p.Name] = p.NodePort
			taken[p.NodePort] = true
		}
	}
	var out []v1.NodePort
	next := v1.NodePortSiloMax + 1
	for _, p := range svc.Spec.Ports {
		np, ok := had[p.Name]
		if !ok {
			for next <= v1.NodePortMax && taken[next] {
				next++
			}
			if next > v1.NodePortMax {
				return nil, errors.New("no free service node port")
			}
			np, taken[next] = next, true
		}
		out = append(out, v1.NodePort{Name: p.Name, Port: p.Port, NodePort: np})
	}
	return out, nil
}

// Controller keeps every Service's status.
type Controller struct {
	Client   *client.Client
	Services *informer.Informer
	Silos    *informer.Informer
	Clock    clock.Clock
}

// Name implements engine.Controller.
func (c *Controller) Name() string { return "service" }

// Kind implements engine.Controller.
func (c *Controller) Kind() string { return "Service" }

func (c *Controller) now() time.Time {
	if c.Clock == nil {
		return time.Now().UTC().Truncate(time.Second)
	}
	return c.Clock.Now().UTC().Truncate(time.Second)
}

// Reconcile implements engine.Controller.
func (c *Controller) Reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	o, ok := c.Services.Get(k.Namespace, k.Name)
	if !ok {
		return engine.Result{}, nil
	}
	svc := o.(*v1.Service)
	if svc.DeletionTimestamp != nil {
		return engine.Result{}, nil
	}
	var all []*v1.Service
	for _, x := range c.Services.List() {
		all = append(all, x.(*v1.Service))
	}
	var silos []*v1.Silo
	for _, x := range c.Silos.List() {
		silos = append(silos, x.(*v1.Silo))
	}
	ip, err := ClusterIP(svc, all)
	if err != nil {
		return engine.Result{}, err
	}
	nps, err := NodePorts(svc, all)
	if err != nil {
		return engine.Result{}, err
	}
	eps, held := Split(svc, silos)
	cond := meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: "Endpoints", ObservedGeneration: svc.Generation,
		Message: fmt.Sprintf("%d endpoint(s) at %s", len(eps), ip)}
	if len(held) > 0 {
		cond.Message += fmt.Sprintf(", %d held", len(held))
	}
	if len(eps) == 0 {
		cond.Status, cond.Reason, cond.Message = meta.ConditionFalse, "NoEndpoints", "no running silo matches the selector"
		if len(held) > 0 {
			cond.Message = fmt.Sprintf("every selected silo is held (%d): %s", len(held), held[0].Reason)
		}
	}
	for attempt := 0; attempt < 5; attempt++ {
		var cur v1.Service
		if err := c.Client.Get(ctx, "Service", svc.Namespace, svc.Name, &cur); err != nil {
			return engine.Result{}, client.IgnoreNotFound(err)
		}
		before := jsonOf(cur.Status)
		cur.Status.ClusterIP, cur.Status.Name, cur.Status.Endpoints, cur.Status.Held, cur.Status.NodePorts = ip, svc.Name+"."+svc.Namespace+".kevaso", eps, held, nps
		if svc.Spec.Type != v1.ServiceLoadBalancer {
			cur.Status.LoadBalancerIP, cur.Status.IP, cur.Status.SourceRanges = "", "", nil
		}
		meta.SetCondition(&cur.Status.Conditions, cond, c.now())
		if jsonOf(cur.Status) == before {
			return engine.Result{}, nil
		}
		err := c.Client.UpdateStatus(ctx, &cur)
		if client.IsConflict(err) {
			continue
		}
		return engine.Result{}, err
	}
	return engine.Result{}, errors.New("service kept changing; will retry")
}

func jsonOf(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Map implements engine.Mapper: a silo's change reaches the services that select it, or did.
func (c *Controller) Map(changed engine.Key) []engine.Key {
	if changed.Kind != "Silo" {
		return nil
	}
	var labels map[string]string
	if o, ok := c.Silos.Get(changed.Namespace, changed.Name); ok {
		labels = o.(*v1.Silo).Labels
	}
	var keys []engine.Key
	for _, o := range c.Services.List() {
		svc := o.(*v1.Service)
		if svc.Namespace != changed.Namespace {
			continue
		}
		was := false
		for _, ep := range append(append([]v1.ServiceEndpoint(nil), svc.Status.Endpoints...), svc.Status.Held...) {
			was = was || ep.Silo == changed.Name
		}
		if was || v1.Selects(svc.Spec.Selector, labels) {
			keys = append(keys, engine.Key{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name})
		}
	}
	return keys
}

var (
	_ engine.Controller = (*Controller)(nil)
	_ engine.Mapper     = (*Controller)(nil)
)
