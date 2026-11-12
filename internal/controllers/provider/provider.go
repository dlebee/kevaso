// Package provider holds the control plane's controllers for provider plugins (design §12): which
// hosts are a plugin's own machines, load balancers from a plugin's class, volumes from a plugin's
// storage class, and DNS records for Ingress host names. The plugins hold the cloud token and call
// the cloud's API; these controllers decide when, and keep the API's objects saying what is where.
//
// Every cloud resource a silo gets carries a finalizer on the silo, so deleting the silo deletes
// the resource first: a load balancer (lb.kevaso.com/CLASS) and volumes (kevaso.com/volumes).
package provider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/sdk/kplugin"
)

// Finalizers.
const (
	FinalizerLBPrefix = "lb.kevaso.com/"
	FinalizerVolumes  = "kevaso.com/volumes"
)

// Classes are the registered plugins' classes, for the scheduler.
func Classes(r *plugins.Registry) map[string]scheduler.Class {
	out := map[string]scheduler.Class{}
	for _, p := range r.All() {
		for _, c := range p.Info.LoadBalancers {
			out[c.Name] = scheduler.Class{Plugin: p.Info.Name, OwnHostsOnly: c.OwnHostsOnly, NodePorts: c.NodePorts}
		}
		for _, c := range p.Info.Storage {
			out[c.Name] = scheduler.Class{Plugin: p.Info.Name, OwnHostsOnly: c.OwnHostsOnly}
		}
	}
	return out
}

// ── Hosts ────────────────────────────────────────────────────────────────────

// Hosts records, on each Host, whether it's one of a plugin's machines (status.provider).
type Hosts struct {
	Client  *client.Client
	Hosts   *informer.Informer
	Plugins *plugins.Registry
	Every   time.Duration // look again this often (default 5m)
}

// Name implements engine.Controller.
func (c *Hosts) Name() string { return "provider-hosts" }

// Kind implements engine.Controller.
func (c *Hosts) Kind() string { return "Host" }

// Reconcile implements engine.Controller.
func (c *Hosts) Reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	every := c.Every
	if every <= 0 {
		every = 5 * time.Minute
	}
	o, ok := c.Hosts.Get("", k.Name)
	if !ok {
		return engine.Result{}, nil
	}
	h := o.(*v1.Host)
	var want *v1.HostProvider
	for _, p := range c.Plugins.All() {
		if !p.Info.Hosts {
			continue
		}
		infos, err := p.Conn.DescribeHosts(ctx, []kplugin.Host{{Name: h.Name, Address: h.Spec.Address}})
		if err != nil {
			return engine.Result{}, fmt.Errorf("plugin %s: %w", p.Info.Name, err)
		}
		for _, i := range infos {
			if i.Name == h.Name {
				want = &v1.HostProvider{Name: p.Info.Name, ID: i.ID, Region: i.Region, PrivateAddress: i.PrivateAddress}
			}
		}
		if want != nil {
			break
		}
	}
	if same(h.Status.Provider, want) {
		return engine.Result{RequeueAfter: every}, nil
	}
	h.Status.Provider = want
	return engine.Result{RequeueAfter: every}, c.Client.UpdateStatus(ctx, h)
}

func same(a, b *v1.HostProvider) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// ── Load balancers ───────────────────────────────────────────────────────────

// LoadBalancers gives silos exposed on a plugin's load-balancer class their address.
type LoadBalancers struct {
	Client  *client.Client
	Silos   *informer.Informer
	Hosts   *informer.Informer
	Plugins *plugins.Registry
	Clock   clock.Clock
}

// Name implements engine.Controller.
func (c *LoadBalancers) Name() string { return "load-balancers" }

// Kind implements engine.Controller.
func (c *LoadBalancers) Kind() string { return "Silo" }

func lbFinalizer(s *v1.Silo) string {
	for _, f := range s.Finalizers {
		if strings.HasPrefix(f, FinalizerLBPrefix) {
			return f
		}
	}
	return ""
}

// Reconcile implements engine.Controller.
func (c *LoadBalancers) Reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	o, ok := c.Silos.Get(k.Namespace, k.Name)
	if !ok {
		return engine.Result{}, nil
	}
	s := o.(*v1.Silo)
	class := v1.PluginLB(s)
	fin := lbFinalizer(s)
	if s.DeletionTimestamp != nil {
		class = ""
	}
	// No (more) plugin load balancer, or a different class: delete the one it had.
	if fin != "" && fin != FinalizerLBPrefix+class {
		old := strings.TrimPrefix(fin, FinalizerLBPrefix)
		p, _, ok := c.Plugins.LoadBalancer(old)
		if !ok {
			return c.condition(ctx, s, meta.ConditionFalse, "PluginMissing", "deleting its "+old+" load balancer needs the plugin serving "+old, 30*time.Second)
		}
		err := p.Conn.DeleteLoadBalancer(ctx, kplugin.LoadBalancerRef{Class: old, ID: s.UID, Address: s.Status.Service.PublicIP})
		if err != nil && !errors.Is(err, kplugin.ErrNotFound) {
			return engine.Result{}, fmt.Errorf("delete %s load balancer: %w", old, err)
		}
		if class == "" && s.DeletionTimestamp == nil {
			if err := c.status(ctx, s, func(st *v1.SiloStatus) {
				st.Service.PublicIP, st.Service.SourceRanges, st.Service.Announce = "", nil, false
			}); err != nil {
				return engine.Result{}, err
			}
		}
		return engine.Result{}, c.finalizers(ctx, s, fin, "")
	}
	if class == "" {
		return engine.Result{}, nil
	}
	if fin == "" {
		return engine.Result{}, c.finalizers(ctx, s, "", FinalizerLBPrefix+class)
	}
	p, pc, ok := c.Plugins.LoadBalancer(class)
	if !ok {
		return c.condition(ctx, s, meta.ConditionFalse, "PluginMissing", "no plugin serves load-balancer class "+class, 30*time.Second)
	}
	if s.Status.Host == "" {
		return engine.Result{}, nil // the scheduler first
	}
	ho, ok := c.Hosts.Get("", s.Status.Host)
	if !ok {
		return engine.Result{}, nil
	}
	h := ho.(*v1.Host)
	if h.Status.Provider == nil || h.Status.Provider.Name != p.Info.Name {
		return c.condition(ctx, s, meta.ConditionFalse, "NotOnProvider", s.Status.Host+" isn't a "+p.Info.Name+" machine", time.Minute)
	}
	if pc.NodePorts && len(s.Status.Service.NodePorts) == 0 {
		return engine.Result{}, nil // the scheduler gives node ports first
	}
	lb := kplugin.LoadBalancer{Class: class, ID: s.UID, Namespace: s.Namespace, Name: s.Name,
		Address: s.Spec.Service.LoadBalancer.Address, Backends: []kplugin.HostInfo{info(h)}}
	for _, o := range c.Hosts.List() {
		if x := o.(*v1.Host); x.Status.Provider != nil && x.Status.Provider.Name == p.Info.Name {
			lb.Hosts = append(lb.Hosts, info(x))
		}
	}
	sort.Slice(lb.Hosts, func(i, j int) bool { return lb.Hosts[i].Name < lb.Hosts[j].Name })
	nps := map[string]int{}
	for _, np := range s.Status.Service.NodePorts {
		nps[np.Name] = np.NodePort
	}
	for _, sp := range s.Spec.Service.Ports {
		proto := "TCP"
		if strings.EqualFold(sp.Protocol, "UDP") {
			proto = "UDP"
		}
		lb.Ports = append(lb.Ports, kplugin.Port{Name: sp.Name, Protocol: proto, Port: sp.Port, NodePort: nps[sp.Name]})
	}
	st, err := p.Conn.EnsureLoadBalancer(ctx, lb)
	if errors.Is(err, kplugin.ErrInProgress) {
		_, _ = c.condition(ctx, s, meta.ConditionFalse, "Provisioning", err.Error(), 0)
		return engine.Result{RequeueAfter: 10 * time.Second}, nil
	}
	if err != nil {
		_, _ = c.condition(ctx, s, meta.ConditionFalse, "Failed", err.Error(), 0)
		return engine.Result{}, err
	}
	if err := c.status(ctx, s, func(ss *v1.SiloStatus) {
		ss.Service.PublicIP, ss.Service.SourceRanges, ss.Service.Announce = st.Address, st.SourceRanges, pc.Announce
		if s.Spec.Network.Egress.Source == v1.EgressSameAsService {
			ss.Service.EgressIP = st.Address
		}
		meta.SetCondition(&ss.Conditions, meta.Condition{Type: "LoadBalancer", Status: meta.ConditionTrue, Reason: "Ready",
			Message: class + " at " + st.Address, ObservedGeneration: s.Generation}, c.now())
	}); err != nil {
		return engine.Result{}, err
	}
	return engine.Result{RequeueAfter: 10 * time.Minute}, nil // and again now and then: someone may change it outside
}

func info(h *v1.Host) kplugin.HostInfo {
	p := h.Status.Provider
	return kplugin.HostInfo{Name: h.Name, ID: p.ID, Region: p.Region, PrivateAddress: p.PrivateAddress}
}

func (c *LoadBalancers) now() time.Time {
	if c.Clock == nil {
		return time.Now().UTC().Truncate(time.Second)
	}
	return c.Clock.Now().UTC().Truncate(time.Second)
}

func (c *LoadBalancers) condition(ctx context.Context, s *v1.Silo, status meta.ConditionStatus, reason, msg string, again time.Duration) (engine.Result, error) {
	err := c.status(ctx, s, func(st *v1.SiloStatus) {
		meta.SetCondition(&st.Conditions, meta.Condition{Type: "LoadBalancer", Status: status, Reason: reason, Message: msg, ObservedGeneration: s.Generation}, c.now())
	})
	return engine.Result{RequeueAfter: again}, err
}

func (c *LoadBalancers) status(ctx context.Context, s *v1.Silo, mutate func(*v1.SiloStatus)) error {
	return updateStatus(ctx, c.Client, s, mutate)
}

func (c *LoadBalancers) finalizers(ctx context.Context, s *v1.Silo, remove, add string) error {
	return setFinalizers(ctx, c.Client, s, remove, add)
}

// Map implements engine.Mapper: a host's provider details reach the silos on it.
func (c *LoadBalancers) Map(changed engine.Key) []engine.Key {
	if changed.Kind != "Host" {
		return nil
	}
	var keys []engine.Key
	for _, o := range c.Silos.List() {
		if s := o.(*v1.Silo); v1.PluginLB(s) != "" || lbFinalizer(s) != "" {
			keys = append(keys, engine.Key{Kind: "Silo", Namespace: s.Namespace, Name: s.Name})
		}
	}
	return keys
}

// ── Shared helpers ───────────────────────────────────────────────────────────

// updateStatus applies mutate to the latest copy of s's status (retrying conflicts).
func updateStatus(ctx context.Context, c *client.Client, s *v1.Silo, mutate func(*v1.SiloStatus)) error {
	for attempt := 0; attempt < 5; attempt++ {
		var cur v1.Silo
		if err := c.Get(ctx, "Silo", s.Namespace, s.Name, &cur); err != nil {
			return err
		}
		if cur.UID != s.UID {
			return nil
		}
		before := fmt.Sprintf("%+v", cur.Status)
		mutate(&cur.Status)
		if fmt.Sprintf("%+v", cur.Status) == before {
			return nil
		}
		err := c.UpdateStatus(ctx, &cur)
		if client.IsConflict(err) {
			continue
		}
		return err
	}
	return errors.New("status kept changing; will retry")
}

// setFinalizers removes one finalizer and/or adds one on the latest copy of s.
func setFinalizers(ctx context.Context, c *client.Client, s *v1.Silo, remove, add string) error {
	for attempt := 0; attempt < 5; attempt++ {
		var cur v1.Silo
		if err := c.Get(ctx, "Silo", s.Namespace, s.Name, &cur); err != nil {
			if client.IsNotFound(err) {
				return nil
			}
			return err
		}
		if cur.UID != s.UID {
			return nil
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
				return nil // being deleted: no new finalizers
			}
			fs = append(fs, add)
		}
		if len(fs) == len(cur.Finalizers) && (add == "" || has) {
			return nil
		}
		cur.Finalizers = fs
		err := c.Update(ctx, &cur)
		if client.IsConflict(err) {
			continue
		}
		if client.IsNotFound(err) {
			return nil
		}
		return err
	}
	return errors.New("silo kept changing; will retry")
}

var (
	_ engine.Controller = (*Hosts)(nil)
	_ engine.Controller = (*LoadBalancers)(nil)
	_ engine.Mapper     = (*LoadBalancers)(nil)
)
