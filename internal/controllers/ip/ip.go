// Package ip holds the controllers of IP objects (design §7.2c-1). Controller gives each IP its
// address (from a host's extra addresses for ip-pool, from the plugin for a class that reserves),
// binds it to the services on it (any number, each on its own ports; one silo for an exclusive
// class), lets go when the last goes (a plugin's address is unshared from the host, a balancer
// that is the IP's address parked), deletes it when its reclaim says so, and releases the address
// when the IP is deleted (finalizer kevaso.com/ip). The balancer itself is provider.Balancers'.
// Made makes the IPs services need: the namespace's default for a class (shared), or one of a
// service's own (dedicated, or an exclusive class), named after it and owned by it.
//
// The decisions are internal/ips's; this only reads and writes the API and calls the plugins.
package ip

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
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

	// ip-pool addresses are handed out one at a time, and each is "assumed" (like the silo
	// controller's placements) until the informer shows it: otherwise the next IP, decided before
	// the watch brings the last one's address, would be given the same address.
	pool    sync.Mutex
	assumed map[string]v1.IPStatus // by NAMESPACE/NAME
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

// exclusive reports whether class's address is one host's at a time (never shared).
func exclusive(reg *plugins.Registry, class string) bool {
	if class == v1.LBIPPool {
		return true
	}
	if reg == nil {
		return false
	}
	_, pc, ok := reg.LoadBalancer(class)
	return ok && pc.Exclusive
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
	if x.Spec.Class == v1.LBIPPool {
		c.pool.Lock()
		defer c.pool.Unlock()
	}
	silos, svcs := c.lists(x.Namespace)
	excl := exclusive(c.Plugins, x.Spec.Class)
	claims := ips.Claims(x, excl, silos, svcs)

	if x.DeletionTimestamp != nil {
		return c.release(ctx, x)
	}
	if !slices.Contains(x.Finalizers, v1.FinalizerIP) {
		x.Finalizers = append(x.Finalizers, v1.FinalizerIP)
		return engine.Result{}, c.Client.Update(ctx, x) // and here again, with the new version
	}
	d := ips.Decide(x, excl, claims)
	st := x.Status
	st.Conditions = slices.Clone(st.Conditions)

	// Let go first (the address leaves its old host before anyone else gets it): when the last
	// holder goes, or an exclusive address's holder changes.
	now := map[string]bool{}
	for _, h := range d.Holders {
		now[h.UID] = true
	}
	if len(st.BoundTo) > 0 && (len(d.Holders) == 0 || (excl && !now[st.BoundTo[0].UID])) {
		if again, err := c.letGo(ctx, x); err != nil || again > 0 {
			return engine.Result{RequeueAfter: again}, err
		}
		st.BoundTo = nil
	}
	if d.Delete {
		if len(x.Status.BoundTo) > 0 {
			x.Status.BoundTo, x.Status.Waiting = nil, nil
			if err := c.Client.UpdateStatus(ctx, x); err != nil {
				return engine.Result{}, err
			}
		}
		return engine.Result{}, client.IgnoreNotFound(c.Client.Delete(ctx, "IP", x.Namespace, x.Name))
	}
	st.BoundTo, st.Waiting = d.BoundTo(), d.Waiting
	bound := meta.Condition{Type: "Bound", Status: meta.ConditionFalse, Reason: "Reserved", Message: "held by nobody", ObservedGeneration: x.Generation}
	if len(d.Holders) > 0 {
		bound.Status, bound.Reason, bound.Message = meta.ConditionTrue, "Bound", "held by "+st.Holders()
		if len(d.Waiting) > 0 {
			bound.Message += fmt.Sprintf(" (%d more name it and wait)", len(d.Waiting))
		}
	}
	meta.SetCondition(&st.Conditions, bound, c.now())

	again := c.reserve(ctx, x, &st, d)
	if !statusEqual(x.Status, st) {
		x.Status = st
		if err := c.Client.UpdateStatus(ctx, x); err != nil {
			return engine.Result{}, err
		}
		if x.Spec.Class == v1.LBIPPool && st.Address != "" {
			if c.assumed == nil {
				c.assumed = map[string]v1.IPStatus{}
			}
			c.assumed[x.Namespace+"/"+x.Name] = st
		}
	}
	return engine.Result{RequeueAfter: again}, nil
}

// poolIPs are the IPs as the informer has them, with the addresses this controller handed out and
// the informer hasn't shown yet (called with c.pool held).
func (c *Controller) poolIPs() []*v1.IP {
	var all []*v1.IP
	seen := map[string]bool{}
	for _, o := range c.IPs.List() {
		x := o.(*v1.IP)
		key := x.Namespace + "/" + x.Name
		seen[key] = true
		if st, ok := c.assumed[key]; ok {
			if x.Status.Address == st.Address {
				delete(c.assumed, key) // the informer caught up
			} else {
				y := *x
				y.Status = st
				x = &y
			}
		}
		all = append(all, x)
	}
	for key := range c.assumed {
		if !seen[key] {
			delete(c.assumed, key) // gone
		}
	}
	return all
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
	if len(d.Holders) > 0 {
		placed = d.Holders[0].Host
	}
	if x.Spec.Class == v1.LBIPPool {
		st.Follows = kplugin.FollowsHost
		if st.Address != "" {
			return 0
		}
		if x.Spec.Host == "" && len(d.Holders) > 0 && placed == "" {
			cond.Status, cond.Reason, cond.Message = meta.ConditionFalse, "WaitingForPlacement", "reserved on the host "+d.Holders[0].Holder+" lands on"
			return 0
		}
		var hosts []*v1.Host
		for _, o := range c.Hosts.List() {
			hosts = append(hosts, o.(*v1.Host))
		}
		h, addr, err := ips.Allocate(x, hosts, c.poolIPs(), placed)
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
		return 30 * time.Second, c.condition(ctx, x, "Bound", meta.ConditionFalse, "PluginMissing", "letting go of "+x.Status.Holders()+" needs the plugin serving "+x.Spec.Class)
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
	return 0, fmt.Errorf("IP %s/%s: letting go of %s: %w", x.Namespace, x.Name, x.Status.Holders(), err)
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
	if a.Address != b.Address || a.Host != b.Host || a.Region != b.Region || a.Handle != b.Handle || a.Follows != b.Follows ||
		len(a.Conditions) != len(b.Conditions) || fmt.Sprint(a.BoundTo) != fmt.Sprint(b.BoundTo) || fmt.Sprint(a.Waiting) != fmt.Sprint(b.Waiting) {
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
			for _, n := range v1.SiloIPs(o.(*v1.Silo), func(cl string) bool { return exclusive(c.Plugins, cl) }) {
				add(changed.Namespace, n)
			}
		}
		c.heldBy(changed.Namespace, v1.HolderSiloPrefix+changed.Name, add)
	case "Service":
		if c.Services != nil {
			if o, ok := c.Services.Get(changed.Namespace, changed.Name); ok {
				svc := o.(*v1.Service)
				n, _ := v1.ServiceIP(svc, exclusive(c.Plugins, svc.Spec.LoadBalancerClass))
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
		held := slices.ContainsFunc(x.Status.BoundTo, func(h v1.IPHolder) bool { return h.Holder == holder }) ||
			slices.ContainsFunc(x.Status.Waiting, func(h v1.IPWaiting) bool { return h.Holder == holder })
		if held || owned {
			add(x.Namespace, x.Name)
		}
	}
}

// ── Made: the IPs services need ──────────────────────────────────────────────

// Made makes the IP a load-balancer service needs when it names none: the namespace's default for
// its class (DefaultIPName: shared by every such service, reclaim Delete, gone with the last one
// unless kept), or with dedicated (or an exclusive class) one of its own, named after it, owned by
// it, reclaim Delete. One for silos (ForKind Silo) and one for Services (ForKind Service). A class
// no plugin serves yet waits: whether its address can be shared is the plugin's to say.
type Made struct {
	Client  *client.Client
	IPs     *informer.Informer
	For     *informer.Informer // Silos or Services
	ForKind string             // Silo | Service
	Plugins *plugins.Registry  // nil: only ip-pool
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
	way := v1.IPNone
	switch x := o.(type) {
	case *v1.Silo:
		if sv := x.Spec.Service; sv != nil && sv.LoadBalancer != nil {
			class = sv.LoadBalancer.Class
			name, way = v1.SiloServiceIP(x, exclusive(m.Plugins, class))
		}
	case *v1.Service:
		class = x.Spec.LoadBalancerClass
		name, way = v1.ServiceIP(x, exclusive(m.Plugins, class))
	}
	if way != v1.IPMade && way != v1.IPDefault {
		return engine.Result{}, nil
	}
	if class != v1.LBIPPool && (m.Plugins == nil || !known(m.Plugins, class)) {
		return engine.Result{}, nil // the plugin says whether it's shared; it's looked at again when one comes
	}
	if _, exists := m.IPs.Get(om.Namespace, name); exists {
		return engine.Result{}, nil // its own, the default, or someone else's (which it won't take: the scheduler says so)
	}
	ip := &v1.IP{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "IP"},
		ObjectMeta: meta.ObjectMeta{Name: name, Namespace: om.Namespace},
		Spec:       v1.IPSpec{Class: class, Reclaim: v1.ReclaimDelete}}
	if way == v1.IPDefault {
		ip.Labels = map[string]string{v1.LabelDefaultIP: class}
	} else {
		ip.OwnerReferences = []meta.OwnerReference{{APIVersion: v1.APIVersion, Kind: m.ForKind, Name: om.Name, UID: om.UID, Controller: true}}
	}
	err := m.Client.Create(ctx, ip)
	if client.IsAlreadyExists(err) {
		return engine.Result{}, nil
	}
	return engine.Result{}, err
}

func known(reg *plugins.Registry, class string) bool {
	_, _, ok := reg.LoadBalancer(class)
	return ok
}

var (
	_ engine.Controller = (*Controller)(nil)
	_ engine.Mapper     = (*Controller)(nil)
	_ engine.Controller = (*Made)(nil)
)
