package provider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/sdk/kplugin"
)

// ServiceLoadBalancers gives standalone Services of type LoadBalancer their outside address from
// a plugin's class: one load balancer whose backends are the hosts with endpoints, on the
// service's node ports (each such host sends them to its own endpoints, so client addresses are
// kept). The finalizer lb.kevaso.com/CLASS on the Service deletes it first. Only node-port classes
// fit: an address announced to one host can't spread over several.
type ServiceLoadBalancers struct {
	Client   *client.Client
	Services *informer.Informer
	Hosts    *informer.Informer
	Plugins  *plugins.Registry
	Clock    clock.Clock
	Resync   time.Duration // default 10m

	mu      sync.Mutex
	ensured map[string]asked
}

// Name implements engine.Controller.
func (c *ServiceLoadBalancers) Name() string { return "service-load-balancers" }

// Kind implements engine.Controller.
func (c *ServiceLoadBalancers) Kind() string { return "Service" }

func svcLBFinalizer(s *v1.Service) string {
	for _, f := range s.Finalizers {
		if strings.HasPrefix(f, FinalizerLBPrefix) {
			return f
		}
	}
	return ""
}

// Reconcile implements engine.Controller.
func (c *ServiceLoadBalancers) Reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	o, ok := c.Services.Get(k.Namespace, k.Name)
	if !ok {
		return engine.Result{}, nil
	}
	svc := o.(*v1.Service)
	class := ""
	if svc.Spec.Type == v1.ServiceLoadBalancer && svc.DeletionTimestamp == nil {
		class = svc.Spec.LoadBalancerClass
	}
	fin := svcLBFinalizer(svc)
	if fin != "" && fin != FinalizerLBPrefix+class {
		old := strings.TrimPrefix(fin, FinalizerLBPrefix)
		p, _, ok := c.Plugins.LoadBalancer(old)
		if !ok {
			return c.condition(ctx, svc, meta.ConditionFalse, "PluginMissing", "deleting its "+old+" load balancer needs the plugin serving "+old, 30*time.Second)
		}
		forget(&c.mu, &c.ensured, svc.UID)
		err := p.Conn.DeleteLoadBalancer(ctx, kplugin.LoadBalancerRef{Class: old, ID: svc.UID, Address: svc.Status.PublicIP})
		if err != nil && !errors.Is(err, kplugin.ErrNotFound) {
			return engine.Result{}, fmt.Errorf("delete %s load balancer: %w", old, err)
		}
		if class == "" && svc.DeletionTimestamp == nil {
			if err := c.status(ctx, svc, func(st *v1.ServiceStatus) { st.PublicIP, st.SourceRanges = "", nil }); err != nil {
				return engine.Result{}, err
			}
		}
		return engine.Result{}, c.finalizers(ctx, svc, fin, "")
	}
	if class == "" {
		return engine.Result{}, nil
	}
	if fin == "" {
		return engine.Result{}, c.finalizers(ctx, svc, "", FinalizerLBPrefix+class)
	}
	p, pc, ok := c.Plugins.LoadBalancer(class)
	if !ok {
		return c.condition(ctx, svc, meta.ConditionFalse, "PluginMissing", "no plugin serves load-balancer class "+class, 30*time.Second)
	}
	if !pc.NodePorts {
		return c.condition(ctx, svc, meta.ConditionFalse, "ClassUnsuitable", class+" routes one address to one host: a Service of several silos needs a class with node ports (e.g. linode-nodebalancer)", 0)
	}
	if len(svc.Status.NodePorts) < len(svc.Spec.Ports) {
		return engine.Result{}, nil // the service controller gives node ports first
	}
	lb := kplugin.LoadBalancer{Class: class, ID: svc.UID, Namespace: svc.Namespace, Name: svc.Name}
	seen := map[string]bool{}
	var off []string
	for _, ep := range svc.Status.Endpoints {
		if seen[ep.Host] {
			continue
		}
		seen[ep.Host] = true
		ho, ok := c.Hosts.Get("", ep.Host)
		if !ok {
			continue
		}
		h := ho.(*v1.Host)
		if h.Status.Provider == nil || h.Status.Provider.Name != p.Info.Name {
			off = append(off, ep.Host)
			continue
		}
		lb.Backends = append(lb.Backends, info(h))
	}
	sort.Slice(lb.Backends, func(i, j int) bool { return lb.Backends[i].Name < lb.Backends[j].Name })
	if len(lb.Backends) == 0 {
		msg := "no endpoints on " + p.Info.Name + " machines yet"
		if len(off) > 0 {
			msg += " (" + strings.Join(off, ", ") + " aren't)"
		}
		return c.condition(ctx, svc, meta.ConditionFalse, "NoBackends", msg, 0)
	}
	for _, o := range c.Hosts.List() {
		if x := o.(*v1.Host); x.Status.Provider != nil && x.Status.Provider.Name == p.Info.Name {
			lb.Hosts = append(lb.Hosts, info(x))
		}
	}
	sort.Slice(lb.Hosts, func(i, j int) bool { return lb.Hosts[i].Name < lb.Hosts[j].Name })
	nps := map[string]int{}
	for _, np := range svc.Status.NodePorts {
		nps[np.Name] = np.NodePort
	}
	for _, sp := range svc.Spec.Ports {
		proto := "TCP"
		if strings.EqualFold(sp.Protocol, "UDP") {
			proto = "UDP"
		}
		lb.Ports = append(lb.Ports, kplugin.Port{Name: sp.Name, Protocol: proto, Port: sp.Port, NodePort: nps[sp.Name]})
	}
	reqKey := fmt.Sprintf("%+v", lb)
	resync := c.Resync
	if resync <= 0 {
		resync = 10 * time.Minute
	}
	if svc.Status.PublicIP != "" && remember(&c.mu, &c.ensured, svc.UID, reqKey, resync) {
		return engine.Result{}, nil
	}
	st, err := p.Conn.EnsureLoadBalancer(ctx, lb)
	if errors.Is(err, kplugin.ErrInProgress) {
		_, _ = c.condition(ctx, svc, meta.ConditionFalse, "Provisioning", err.Error(), 0)
		return engine.Result{RequeueAfter: 10 * time.Second}, nil
	}
	if err != nil {
		_, _ = c.condition(ctx, svc, meta.ConditionFalse, "Failed", err.Error(), 0)
		return engine.Result{}, err
	}
	msg := class + " at " + st.Address
	if len(off) > 0 {
		msg += "; endpoints on " + strings.Join(off, ", ") + " aren't " + p.Info.Name + " machines, so it can't reach them"
	}
	if err := c.status(ctx, svc, func(ss *v1.ServiceStatus) {
		ss.PublicIP, ss.SourceRanges = st.Address, st.SourceRanges
		meta.SetCondition(&ss.Conditions, meta.Condition{Type: "LoadBalancer", Status: meta.ConditionTrue, Reason: "Ready",
			Message: msg, ObservedGeneration: svc.Generation}, c.now())
	}); err != nil {
		return engine.Result{}, err
	}
	record(&c.mu, &c.ensured, svc.UID, reqKey)
	return engine.Result{RequeueAfter: resync}, nil
}

func (c *ServiceLoadBalancers) now() time.Time {
	if c.Clock == nil {
		return time.Now().UTC().Truncate(time.Second)
	}
	return c.Clock.Now().UTC().Truncate(time.Second)
}

func (c *ServiceLoadBalancers) condition(ctx context.Context, svc *v1.Service, status meta.ConditionStatus, reason, msg string, again time.Duration) (engine.Result, error) {
	err := c.status(ctx, svc, func(st *v1.ServiceStatus) {
		meta.SetCondition(&st.Conditions, meta.Condition{Type: "LoadBalancer", Status: status, Reason: reason, Message: msg, ObservedGeneration: svc.Generation}, c.now())
	})
	return engine.Result{RequeueAfter: again}, err
}

func (c *ServiceLoadBalancers) status(ctx context.Context, svc *v1.Service, mutate func(*v1.ServiceStatus)) error {
	for attempt := 0; attempt < 5; attempt++ {
		var cur v1.Service
		if err := c.Client.Get(ctx, "Service", svc.Namespace, svc.Name, &cur); err != nil {
			return client.IgnoreNotFound(err)
		}
		before := statusKey(cur.Status)
		mutate(&cur.Status)
		if statusKey(cur.Status) == before {
			return nil
		}
		err := c.Client.UpdateStatus(ctx, &cur)
		if client.IsConflict(err) {
			continue
		}
		return err
	}
	return errors.New("service kept changing; will retry")
}

func (c *ServiceLoadBalancers) finalizers(ctx context.Context, svc *v1.Service, remove, add string) error {
	for attempt := 0; attempt < 5; attempt++ {
		var cur v1.Service
		if err := c.Client.Get(ctx, "Service", svc.Namespace, svc.Name, &cur); err != nil {
			return client.IgnoreNotFound(err)
		}
		var fs []string
		has := false
		for _, f := range cur.Finalizers {
			if f == remove {
				continue
			}
			has = has || f == add
			fs = append(fs, f)
		}
		if add != "" && !has {
			if cur.DeletionTimestamp != nil {
				return nil
			}
			fs = append(fs, add)
		}
		cur.Finalizers = fs
		err := c.Client.Update(ctx, &cur)
		if client.IsConflict(err) {
			continue
		}
		return client.IgnoreNotFound(err)
	}
	return errors.New("service kept changing; will retry")
}

// Map implements engine.Mapper: a host's provider details reach the services with endpoints on it.
func (c *ServiceLoadBalancers) Map(changed engine.Key) []engine.Key {
	if changed.Kind != "Host" {
		return nil
	}
	var keys []engine.Key
	for _, o := range c.Services.List() {
		svc := o.(*v1.Service)
		if svc.Spec.Type != v1.ServiceLoadBalancer {
			continue
		}
		for _, ep := range svc.Status.Endpoints {
			if ep.Host == changed.Name {
				keys = append(keys, engine.Key{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name})
				break
			}
		}
	}
	return keys
}

var (
	_ engine.Controller = (*ServiceLoadBalancers)(nil)
	_ engine.Mapper     = (*ServiceLoadBalancers)(nil)
)
