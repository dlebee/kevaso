// Package ip holds the controllers of IP objects (design §7.2c-1). Controller gives each IP its
// address (from a host's extra addresses for ip-pool, from the plugin for a class that reserves),
// binds it to the one silo or Service holding it, lets go when that goes (a plugin's address is
// unshared from the host, a balancer that is the IP's address parked), deletes it when its reclaim
// says so, and releases the address when the IP is deleted (finalizer kevaso.com/ip). Made makes
// the IP of a load-balancer service that names none: named after it, owned by it, reclaim Delete.
//
// The decisions are internal/ips's; this only reads and writes the API and calls the plugins.
package ip

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/ips"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/sdk/kplugin"
)

// Controller reconciles IP objects.
type Controller struct {
	Client   *client.Client
	IPs      *informer.Informer
	Silos    *informer.Informer
	Services *informer.Informer
	Hosts    *informer.Informer
	Plugins  *plugins.Registry // nil: only ip-pool
	Clock    clock.Clock
}

// Name implements engine.Controller.
func (c *Controller) Name() string { return "ips" }

// Kind implements engine.Controller.
func (c *Controller) Kind() string { return "IP" }

func (c *Controller) now() time.Time {
	if c.Clock == nil {
		return time.Now().UTC().Truncate(time.Second)
	}
	return c.Clock.Now().UTC().Truncate(time.Second)
}

func (c *Controller) plugin(class string) (*plugins.Plugin, kplugin.Class, bool) {
	if c.Plugins == nil {
		return nil, kplugin.Class{}, false
	}
	return c.Plugins.LoadBalancer(class)
}

func (c *Controller) lists(ns string) ([]*v1.Silo, []*v1.Service) {
	var silos []*v1.Silo
	for _, o := range c.Silos.List() {
		if s := o.(*v1.Silo); s.Namespace == ns {
			silos = append(silos, s)
		}
	}
	var svcs []*v1.Service
	if c.Services != nil {
		for _, o := range c.Services.List() {
			if s := o.(*v1.Service); s.Namespace == ns {
				svcs = append(svcs, s)
			}
		}
	}
	return silos, svcs
}

// Reconcile implements engine.Controller.
func (c *Controller) Reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	o, ok := c.IPs.Get(k.Namespace, k.Name)
	if !ok {
		return engine.Result{}, nil
	}
	x := o.(*v1.IP)
	silos, svcs := c.lists(x.Namespace)
	claims := ips.Claims(x, silos, svcs)

	if x.DeletionTimestamp != nil {
		return c.release(ctx, x)
	}
	if !slices.Contains(x.Finalizers, v1.FinalizerIP) {
		x.Finalizers = append(x.Finalizers, v1.FinalizerIP)
		return engine.Result{}, c.Client.Update(ctx, x) // and here again, with the new version
	}
	d := ips.Decide(x, claims)
	st := x.Status
	st.Conditions = slices.Clone(st.Conditions)

	// Let go of the old holder first: the address leaves its host before anyone else gets it.
	if st.BoundUID != "" && (!d.Bound || d.Holder.UID != st.BoundUID) {
		if again, err := c.letGo(ctx, x); err != nil || again > 0 {
			return engine.Result{RequeueAfter: again}, err
		}
		st.BoundTo, st.BoundUID = "", ""
	}
	if d.Delete {
		if x.Status.BoundUID != "" || x.Status.BoundTo != "" {
			x.Status.BoundTo, x.Status.BoundUID = "", ""
			if err := c.Client.UpdateStatus(ctx, x); err != nil {
				return engine.Result{}, err
			}
		}
		return engine.Result{}, client.IgnoreNotFound(c.Client.Delete(ctx, "IP", x.Namespace, x.Name))
	}
	if d.Bound {
		st.BoundTo, st.BoundUID = d.Holder.Holder, d.Holder.UID
	}
	bound := meta.Condition{Type: "Bound", Status: meta.ConditionFalse, Reason: "Reserved", Message: "held by nobody", ObservedGeneration: x.Generation}
	if d.Bound {
		bound.Status, bound.Reason, bound.Message = meta.ConditionTrue, "Bound", "held by "+st.BoundTo
		if waiting := len(claims) - 1; waiting > 0 {
			bound.Message += fmt.Sprintf(" (%d more name it and wait)", waiting)
		}
	}
	meta.SetCondition(&st.Conditions, bound, c.now())

	again := c.reserve(ctx, x, &st, d)
	if !statusEqual(x.Status, st) {
		x.Status = st
		if err := c.Client.UpdateStatus(ctx, x); err != nil {
			return engine.Result{}, err
		}
	}
	return engine.Result{RequeueAfter: again}, nil
}

// reserve gives x its address if it has none yet, into st, with the Reserved condition.
func (c *Controller) reserve(ctx context.Context, x *v1.IP, st *v1.IPStatus, d ips.Decision) time.Duration {
	cond := meta.Condition{Type: "Reserved", Status: meta.ConditionTrue, Reason: "Reserved", ObservedGeneration: x.Generation}
	defer func() {
		if cond.Message == "" && st.Address != "" {
			cond.Message = st.Address
		}
		meta.SetCondition(&st.Conditions, cond, c.now())
	}()
	placed := ""
	if d.Bound {
		placed = d.Holder.Host
	}
	if x.Spec.Class == v1.LBIPPool {
		st.Follows = kplugin.FollowsHost
		if st.Address != "" {
			return 0
		}
		if x.Spec.Host == "" && d.Bound && placed == "" {
			cond.Status, cond.Reason, cond.Message = meta.ConditionFalse, "WaitingForPlacement", "reserved on the host "+st.BoundTo+" lands on"
			return 0
		}
		var hosts []*v1.Host
		for _, o := range c.Hosts.List() {
			hosts = append(hosts, o.(*v1.Host))
		}
		var all []*v1.IP
		for _, o := range c.IPs.List() {
			all = append(all, o.(*v1.IP))
		}
		h, addr, err := ips.Allocate(x, hosts, all, placed)
		if err != nil {
			cond.Status, cond.Reason, cond.Message = meta.ConditionFalse, "NoAddress", err.Error()
			return time.Minute
		}
		st.Host, st.Address = h, addr
		return 0
	}
	p, pc, ok := c.plugin(x.Spec.Class)
	if !ok {
		if st.Address == "" {
			cond.Status, cond.Reason, cond.Message = meta.ConditionFalse, "PluginMissing", "no plugin serves load-balancer class "+x.Spec.Class
		}
		return 30 * time.Second
	}
	st.Follows = pc.Follows
	if st.Follows == "" {
		st.Follows = kplugin.FollowsRegion
	}
	if st.Follows == kplugin.FollowsHost && st.Host == "" && placed != "" {
		st.Host = placed // it stays where it was first used
	}
	if st.Address != "" {
		return 0
	}
	if !pc.Reserve {
		cond.Status, cond.Reason = meta.ConditionFalse, "FromLoadBalancer"
		cond.Message = x.Spec.Class + "'s address is its load balancer's: it comes when a service holds this IP, and stays as long as the IP does"
		return 0
	}
	region := x.Spec.Region
	if region == "" && placed != "" {
		if ho, ok := c.Hosts.Get("", placed); ok {
			if pr := ho.(*v1.Host).Status.Provider; pr != nil {
				region = pr.Region
			}
		}
	}
	if region == "" {
		cond.Status, cond.Reason = meta.ConditionFalse, "WaitingForRegion"
		cond.Message = "set spec.region, or let a silo hold it: the address is reserved in the region it lands in"
		return 0
	}
	as, err := p.Conn.ReserveAddress(ctx, kplugin.AddressReservation{Class: x.Spec.Class, ID: x.UID, Namespace: x.Namespace, Name: x.Name,
		Region: region, Address: x.Spec.Address})
	if errors.Is(err, kplugin.ErrInProgress) {
		cond.Status, cond.Reason, cond.Message = meta.ConditionFalse, "Reserving", err.Error()
		return 10 * time.Second
	}
	if err != nil {
		cond.Status, cond.Reason, cond.Message = meta.ConditionFalse, "Failed", err.Error()
		return 30 * time.Second
	}
	st.Address, st.Region, st.Handle = as.Address, as.Region, as.Handle
	return 0
}

// letGo takes x's address from its old holder: unshared from the host (a class that reserves), or
// the balancer that is its address parked (no backends: it keeps the address, sends nowhere).
// ip-pool needs nothing here: the host drops the address when the silo leaves it.
func (c *Controller) letGo(ctx context.Context, x *v1.IP) (time.Duration, error) {
	if x.Spec.Class == v1.LBIPPool {
		return 0, nil
	}
	p, pc, ok := c.plugin(x.Spec.Class)
	if !ok {
		return 30 * time.Second, c.condition(ctx, x, "Bound", meta.ConditionFalse, "PluginMissing", "letting go of "+x.Status.BoundTo+" needs the plugin serving "+x.Spec.Class)
	}
	var err error
	if pc.Reserve {
		err = p.Conn.DeleteLoadBalancer(ctx, kplugin.LoadBalancerRef{Class: x.Spec.Class, ID: x.UID, Address: x.Status.Address})
	} else {
		_, err = p.Conn.EnsureLoadBalancer(ctx, kplugin.LoadBalancer{Class: x.Spec.Class, ID: x.UID, Namespace: x.Namespace, Name: x.Name})
	}
	switch {
	case err == nil, errors.Is(err, kplugin.ErrNotFound):
		return 0, nil
	case errors.Is(err, kplugin.ErrInProgress):
		return 10 * time.Second, nil
	}
	return 0, fmt.Errorf("IP %s/%s: letting go of %s: %w", x.Namespace, x.Name, x.Status.BoundTo, err)
}

// release gives the address back (the IP is being deleted, and nothing holds it).
func (c *Controller) release(ctx context.Context, x *v1.IP) (engine.Result, error) {
	if !slices.Contains(x.Finalizers, v1.FinalizerIP) {
		return engine.Result{}, nil
	}
	if x.Spec.Class != v1.LBIPPool && (x.Status.Address != "" || x.Status.Handle != "") {
		p, _, ok := c.plugin(x.Spec.Class)
		if !ok {
			return engine.Result{RequeueAfter: 30 * time.Second},
				c.condition(ctx, x, "Reserved", meta.ConditionFalse, "PluginMissing", "releasing "+x.Status.Address+" needs the plugin serving "+x.Spec.Class)
		}
		err := p.Conn.ReleaseAddress(ctx, kplugin.AddressRef{Class: x.Spec.Class, ID: x.UID, Address: x.Status.Address, Handle: x.Status.Handle})
		switch {
		case errors.Is(err, kplugin.ErrInProgress):
			return engine.Result{RequeueAfter: 10 * time.Second}, nil
		case err != nil && !errors.Is(err, kplugin.ErrNotFound):
			_ = c.condition(ctx, x, "Reserved", meta.ConditionFalse, "Releasing", err.Error())
			return engine.Result{}, fmt.Errorf("release %s: %w", x.Status.Address, err)
		}
	}
	x.Finalizers = slices.DeleteFunc(x.Finalizers, func(f string) bool { return f == v1.FinalizerIP })
	return engine.Result{}, client.IgnoreNotFound(c.Client.Update(ctx, x))
}

func (c *Controller) condition(ctx context.Context, x *v1.IP, typ string, status meta.ConditionStatus, reason, msg string) error {
	if !meta.SetCondition(&x.Status.Conditions, meta.Condition{Type: typ, Status: status, Reason: reason, Message: msg, ObservedGeneration: x.Generation}, c.now()) {
		return nil
	}
	return client.IgnoreNotFound(c.Client.UpdateStatus(ctx, x))
}

func statusEqual(a, b v1.IPStatus) bool {
	if a.Address != b.Address || a.Host != b.Host || a.Region != b.Region || a.Handle != b.Handle || a.BoundTo != b.BoundTo ||
		a.BoundUID != b.BoundUID || a.Follows != b.Follows || len(a.Conditions) != len(b.Conditions) {
		return false
	}
	for i := range a.Conditions {
		x, y := a.Conditions[i], b.Conditions[i]
		if x.Type != y.Type || x.Status != y.Status || x.Reason != y.Reason || x.Message != y.Message || x.ObservedGeneration != y.ObservedGeneration {
			return false
		}
	}
	return true
}

// Map implements engine.Mapper: a silo or Service that names an IP, or held one, reaches it; a
// host's addresses reach the ip-pool IPs still waiting for one.
func (c *Controller) Map(changed engine.Key) []engine.Key {
	var keys []engine.Key
	add := func(ns, name string) {
		if name != "" {
			keys = append(keys, engine.Key{Kind: "IP", Namespace: ns, Name: name})
		}
	}
	switch changed.Kind {
	case "Silo":
		if o, ok := c.Silos.Get(changed.Namespace, changed.Name); ok {
			for _, n := range v1.SiloIPs(o.(*v1.Silo)) {
				add(changed.Namespace, n)
			}
		}
		c.heldBy(changed.Namespace, v1.HolderSiloPrefix+changed.Name, add)
	case "Service":
		if c.Services != nil {
			if o, ok := c.Services.Get(changed.Namespace, changed.Name); ok {
				n, _ := v1.ServiceIP(o.(*v1.Service))
				add(changed.Namespace, n)
			}
		}
		c.heldBy(changed.Namespace, v1.HolderServicePrefix+changed.Name, add)
	case "Host":
		for _, o := range c.IPs.List() {
			if x := o.(*v1.IP); x.Spec.Class == v1.LBIPPool && x.Status.Address == "" {
				add(x.Namespace, x.Name)
			}
		}
	}
	return keys
}

// heldBy calls add for the IPs held by holder in ns, or owned by an object of that name.
func (c *Controller) heldBy(ns, holder string, add func(ns, name string)) {
	for _, o := range c.IPs.List() {
		x := o.(*v1.IP)
		if x.Namespace != ns {
			continue
		}
		owned := slices.ContainsFunc(x.OwnerReferences, func(r meta.OwnerReference) bool {
			return (r.Kind == "Silo" && v1.HolderSiloPrefix+r.Name == holder) || (r.Kind == "Service" && v1.HolderServicePrefix+r.Name == holder)
		})
		if x.Status.BoundTo == holder || owned {
			add(x.Namespace, x.Name)
		}
	}
}

// ── Made: the IP of a service that names none ────────────────────────────────

// Made makes the IP a load-balancer service needs when it names none: named after it, of its
// class, owned by it, with reclaim Delete (so it goes when the service goes, unless kept). One
// for silos (Kind Silo) and one for Services (Kind Service).
type Made struct {
	Client  *client.Client
	IPs     *informer.Informer
	For     *informer.Informer // Silos or Services
	ForKind string             // Silo | Service
}

// Name implements engine.Controller.
func (m *Made) Name() string { return "ips-made-for-" + m.ForKind }

// Kind implements engine.Controller.
func (m *Made) Kind() string { return m.ForKind }

// Reconcile implements engine.Controller.
func (m *Made) Reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	o, ok := m.For.Get(k.Namespace, k.Name)
	if !ok {
		return engine.Result{}, nil
	}
	om := o.GetObjectMeta()
	if om.DeletionTimestamp != nil || om.UID == "" {
		return engine.Result{}, nil
	}
	var name, class string
	var made bool
	switch x := o.(type) {
	case *v1.Silo:
		name, made = v1.SiloServiceIP(x)
		if made {
			class = x.Spec.Service.LoadBalancer.Class
		}
	case *v1.Service:
		name, made = v1.ServiceIP(x)
		class = x.Spec.LoadBalancerClass
	}
	if !made {
		return engine.Result{}, nil
	}
	if _, exists := m.IPs.Get(om.Namespace, name); exists {
		return engine.Result{}, nil // its own (or someone else's, which it won't take: the scheduler says so)
	}
	ip := &v1.IP{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "IP"},
		ObjectMeta: meta.ObjectMeta{Name: name, Namespace: om.Namespace,
			OwnerReferences: []meta.OwnerReference{{APIVersion: v1.APIVersion, Kind: m.ForKind, Name: om.Name, UID: om.UID, Controller: true}}},
		Spec: v1.IPSpec{Class: class, Reclaim: v1.ReclaimDelete}}
	err := m.Client.Create(ctx, ip)
	if client.IsAlreadyExists(err) {
		return engine.Result{}, nil
	}
	return engine.Result{}, err
}

var (
	_ engine.Controller = (*Controller)(nil)
	_ engine.Mapper     = (*Controller)(nil)
	_ engine.Controller = (*Made)(nil)
)
