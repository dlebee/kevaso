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
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/claims"
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
		if why := unpublished(svc, s); why != "" {
			ep.Reason = why
			held = append(held, ep)
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

// unpublished says why a LoadBalancer Service may not publish s's ports ("" when it may): each of
// its ports must target one s opens itself (spec.service.ports) and not only on a lease (K-061).
// Else anyone who may create a Service would open outside a port the silo keeps closed, or opens
// only on an approved lease. A ClusterIP Service stays on the mesh: not judged here.
func unpublished(svc *v1.Service, s *v1.Silo) string {
	if svc.Spec.Type != v1.ServiceLoadBalancer {
		return ""
	}
	var why []string
	for _, p := range svc.Spec.Ports {
		if v1.TargetPort(p, s) == 0 {
			continue // not served by this silo at all
		}
		name := p.TargetPort
		if name == "" {
			name = p.Name
		}
		op, ok := s.Spec.OpenPort(name)
		switch {
		case !ok:
			why = append(why, fmt.Sprintf("port %s isn't one silo %s opens (open it in its spec.service.ports)", name, s.Name))
		case op.Lease != nil:
			why = append(why, fmt.Sprintf("port %s of silo %s opens outside only on a lease (kvo open; a LoadBalancer Service can't publish it)", name, s.Name))
		}
	}
	if len(why) == 0 {
		return ""
	}
	return "a LoadBalancer Service publishes only ports the silo opens itself, not on a lease: " + strings.Join(why, "; ") + "; or leave that port out of Service " + svc.Name
}

// ClusterIP keeps svc's virtual IP, or gives it the lowest free one. Pure.
func ClusterIP(svc *v1.Service, all []*v1.Service) (string, error) {
	return clusterIP(svc, all, nil)
}

// clusterIP is ClusterIP, also avoiding the addresses in avoid (claimed by others in the store).
func clusterIP(svc *v1.Service, all []*v1.Service, avoid map[string]bool) (string, error) {
	cidr := netip.MustParsePrefix(v1.ServiceCIDR)
	taken := maps.Clone(avoid)
	if taken == nil {
		taken = map[string]bool{}
	}
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
	return nodePorts(svc, all, nil)
}

// nodePorts is NodePorts, also avoiding the ports in avoid (claimed by others in the store).
func nodePorts(svc *v1.Service, all []*v1.Service, avoid map[int]bool) ([]v1.NodePort, error) {
	if svc.Spec.Type != v1.ServiceLoadBalancer {
		return nil, nil
	}
	taken := maps.Clone(avoid)
	if taken == nil {
		taken = map[int]bool{}
	}
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
	// Claims make each cluster IP and node port one Service's in the store (K-028).
	Claims *claims.Claims

	mine sync.Map // POOL/VALUE → UID: claimed by this controller, so not claimed again
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
	eps, held := Split(svc, silos)
	for attempt := 0; attempt < 5; attempt++ {
		var cur v1.Service
		if err := c.Client.Get(ctx, "Service", svc.Namespace, svc.Name, &cur); err != nil {
			return engine.Result{}, client.IgnoreNotFound(err)
		}
		ip, nps, err := c.allocate(ctx, &cur, all)
		if err != nil {
			return engine.Result{}, err
		}
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
		before := jsonOf(cur.Status)
		hadIP, hadPorts := cur.Status.ClusterIP, cur.Status.NodePorts
		cur.Status.ClusterIP, cur.Status.Name, cur.Status.Endpoints, cur.Status.Held, cur.Status.NodePorts = ip, svc.Name+"."+svc.Namespace+".kevaso", eps, held, nps
		if svc.Spec.Type != v1.ServiceLoadBalancer {
			cur.Status.LoadBalancerIP, cur.Status.IP, cur.Status.SourceRanges = "", "", nil
		}
		meta.SetCondition(&cur.Status.Conditions, cond, c.now())
		if jsonOf(cur.Status) == before {
			return engine.Result{}, nil
		}
		err = c.Client.UpdateStatus(ctx, &cur)
		if client.IsConflict(err) {
			continue
		}
		if err == nil {
			err = c.letGo(ctx, &cur, hadIP, hadPorts)
		}
		return engine.Result{}, err
	}
	return engine.Result{}, errors.New("service kept changing; will retry")
}

// The pools a Service's values are claimed in (claims.Claims, K-028).
const (
	PoolClusterIP = "service-cluster-ip"
	PoolNodePort  = "service-node-port"
)

// UsesClusterIP and UsesNodePort say whether a stored Service still has the value.
func UsesClusterIP(obj []byte, value string) bool {
	var s v1.Service
	return json.Unmarshal(obj, &s) == nil && s.Status.ClusterIP == value
}

func UsesNodePort(obj []byte, value string) bool {
	var s v1.Service
	if json.Unmarshal(obj, &s) != nil {
		return false
	}
	return slices.ContainsFunc(s.Status.NodePorts, func(p v1.NodePort) bool { return strconv.Itoa(p.NodePort) == value })
}

// allocate picks cur's cluster IP and node ports (kept, or the lowest free in the cache), each
// claimed in the store for cur at its version before it is written: one another Service holds
// already is avoided, and the next is tried. Without Claims (tests), the cache alone decides.
func (c *Controller) allocate(ctx context.Context, cur *v1.Service, all []*v1.Service) (string, []v1.NodePort, error) {
	if c.Claims == nil {
		ip, err := ClusterIP(cur, all)
		if err != nil {
			return "", nil, err
		}
		nps, err := NodePorts(cur, all)
		return ip, nps, err
	}
	h := claims.Holder{Kind: "Service", Namespace: cur.Namespace, Name: cur.Name, UID: cur.UID, Version: cur.ResourceVersion}
	// A value cur already has, claimed by this controller: still its own (the claim is only taken
	// over once the stored Service stops having it). Anything else is claimed now.
	take := func(pool, value string, has bool, uses claims.Uses) (bool, error) {
		if u, ok := c.mine.Load(pool + "/" + value); has && ok && u == h.UID {
			return true, nil
		}
		ok, _, err := c.Claims.Take(ctx, pool, value, h, uses)
		if ok {
			c.mine.Store(pool+"/"+value, h.UID)
		}
		return ok, err
	}
	avoidIP := map[string]bool{}
	var ip string
	for {
		var err error
		if ip, err = clusterIP(cur, all, avoidIP); err != nil {
			return "", nil, err
		}
		ok, err := take(PoolClusterIP, ip, ip == cur.Status.ClusterIP, UsesClusterIP)
		if err != nil {
			return "", nil, err
		}
		if ok {
			break
		}
		avoidIP[ip] = true
	}
	avoidPort := map[int]bool{}
	for {
		nps, err := nodePorts(cur, all, avoidPort)
		if err != nil {
			return "", nil, err
		}
		taken := false
		for _, p := range nps {
			has := slices.ContainsFunc(cur.Status.NodePorts, func(q v1.NodePort) bool { return q.NodePort == p.NodePort })
			ok, err := take(PoolNodePort, strconv.Itoa(p.NodePort), has, UsesNodePort)
			if err != nil {
				return "", nil, err
			}
			if !ok {
				avoidPort[p.NodePort], taken = true, true
			}
		}
		if !taken {
			return ip, nps, nil
		}
	}
}

// letGo gives back the claims of values svc had and has no more.
func (c *Controller) letGo(ctx context.Context, svc *v1.Service, hadIP string, hadPorts []v1.NodePort) error {
	if c.Claims == nil {
		return nil
	}
	var errs []error
	if hadIP != "" && hadIP != svc.Status.ClusterIP {
		errs = append(errs, c.Claims.LetGo(ctx, PoolClusterIP, svc.UID, svc.Status.ClusterIP))
	}
	if fmt.Sprint(hadPorts) != fmt.Sprint(svc.Status.NodePorts) {
		var keep []string
		for _, p := range svc.Status.NodePorts {
			keep = append(keep, strconv.Itoa(p.NodePort))
		}
		errs = append(errs, c.Claims.LetGo(ctx, PoolNodePort, svc.UID, keep...))
	}
	return errors.Join(errs...)
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
