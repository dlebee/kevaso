// Package ip holds the controller of IP objects (networking v2). It gives each IP its address
// (type Host: the host's extra address it names; type Provider: reserved from the provider's
// plugin), binds it to one holder at a time (the oldest silo or Service naming it), lets go when
// that one goes, and releases the address when the IP is deleted (finalizer kevaso.com/ip). An IP
// is kept until it is deleted. The balancer itself is provider.Balancers'.
//
// The decisions are internal/ips's; this only reads and writes the API and calls the plugins.
//
// TODO(net-v2 wave 2): IPSet members (Static: their IPs; Dynamic: SET-N reserved per ordinal),
// a Provider IP announced by the new worker after a move, and the plugin's provider lookup by
// name with its declared capabilities instead of its load-balancer classes.
package ip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/claims"
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
	Plugins  *plugins.Registry // nil: only type Host
	Clock    clock.Clock
	// Claims make each host address one IP's, by the store: of two IPs naming it, the second
	// waits (Reserved False, Taken) until the first is deleted.
	Claims *claims.Claims
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

// provider is the plugin named provider and its load-balancer class that reserves addresses.
// TODO(net-v2 wave 2): the plugin session's provider lookup and capabilities.
func (c *Controller) provider(name string) (*plugins.Plugin, kplugin.Class, bool) {
	if c.Plugins == nil {
		return nil, kplugin.Class{}, false
	}
	for _, p := range c.Plugins.All() {
		if p.Info.Name != name {
			continue
		}
		for _, cl := range p.Info.LoadBalancers {
			if cl.Reserve {
				return p, cl, true
			}
		}
	}
	return nil, kplugin.Class{}, false
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
	if !informer.AllSynced(c.IPs, c.Silos, c.Services, c.Hosts) {
		return engine.Result{RequeueAfter: time.Second}, nil // no claimant seen is not no claimant
	}
	o, ok := c.IPs.Get(k.Namespace, k.Name)
	if !ok {
		return engine.Result{}, nil
	}
	x := o.(*v1.IP)
	silos, svcs := c.lists(x.Namespace)
	claimants := ips.Claims(x, silos, svcs)

	if x.DeletionTimestamp != nil {
		return c.release(ctx, x)
	}
	if !slices.Contains(x.Finalizers, v1.FinalizerIP) {
		x.Finalizers = append(x.Finalizers, v1.FinalizerIP)
		return engine.Result{}, c.Client.Update(ctx, x) // and here again, with the new version
	}
	d := ips.Decide(x, claimants)
	st := x.Status
	st.Conditions = slices.Clone(st.Conditions)

	// Let go first (the address leaves its old holder before anyone else gets it), decided again
	// on a fresh read of the claimants, so one that claimed it since keeps it.
	if h := st.Holder; h != nil && (d.Holder == nil || d.Holder.UID != h.UID) {
		same, err := c.stillDecided(ctx, x, d)
		if err != nil {
			return engine.Result{}, err
		}
		if !same {
			return engine.Result{RequeueAfter: time.Second}, nil // the caches catch up; decided again
		}
		st.Holder = nil
	}
	st.Holder, st.Waiting = d.StatusHolder(), d.Waiting
	bound := meta.Condition{Type: "Bound", Status: meta.ConditionFalse, Reason: "Reserved", Message: "held by nobody", ObservedGeneration: x.Generation}
	if d.Holder != nil {
		bound.Status, bound.Reason, bound.Message = meta.ConditionTrue, "Bound", "held by "+st.Holders()
		if len(d.Waiting) > 0 {
			bound.Message += fmt.Sprintf(" (%d more name it and wait)", len(d.Waiting))
		}
	}
	meta.SetCondition(&st.Conditions, bound, c.now())

	again := c.reserve(ctx, x, &st)
	if !statusEqual(x.Status, st) {
		x.Status = st
		if err := c.Client.UpdateStatus(ctx, x); err != nil {
			return engine.Result{}, err
		}
	}
	return engine.Result{RequeueAfter: again}, nil
}

// HostAddressPool is the claims pool of host addresses (by NAME): one IP each.
const HostAddressPool = "host-address"

// UsesAddress says whether a stored IP still names the host address.
func UsesAddress(obj []byte, value string) bool {
	var x v1.IP
	return json.Unmarshal(obj, &x) == nil && x.Spec.Type == v1.IPTypeHost && x.Spec.HostAddress == value
}

// reserve gives x its address if it has none yet, into st, with the Reserved condition.
func (c *Controller) reserve(ctx context.Context, x *v1.IP, st *v1.IPStatus) time.Duration {
	cond := meta.Condition{Type: "Reserved", Status: meta.ConditionTrue, Reason: "Reserved", ObservedGeneration: x.Generation}
	defer func() {
		if cond.Message == "" && st.Address != "" {
			cond.Message = st.Address
		}
		meta.SetCondition(&st.Conditions, cond, c.now())
	}()
	switch x.Spec.Type {
	case v1.IPTypeHost:
		var hosts []*v1.Host
		for _, o := range c.Hosts.List() {
			hosts = append(hosts, o.(*v1.Host))
		}
		h, a, ok := ips.FindAddress(hosts, x.Spec.HostAddress)
		if !ok {
			st.Address, st.Host, st.Where = "", "", ""
			cond.Status, cond.Reason, cond.Message = meta.ConditionFalse, "NoAddress",
				"no host has address "+x.Spec.HostAddress+" (kvoadm host addresses HOST add "+x.Spec.HostAddress+" ADDRESS)"
			return 0 // a host's change maps here
		}
		if c.Claims != nil && st.Address == "" {
			ok, _, err := c.Claims.Take(ctx, HostAddressPool, x.Spec.HostAddress, claims.Holder{Kind: "IP", Namespace: x.Namespace, Name: x.Name, UID: x.UID, Version: x.ResourceVersion}, UsesAddress)
			if err != nil {
				cond.Status, cond.Reason, cond.Message = meta.ConditionFalse, "NoAddress", err.Error()
				return 10 * time.Second
			}
			if !ok {
				cond.Status, cond.Reason, cond.Message = meta.ConditionFalse, "Taken", "address "+x.Spec.HostAddress+" is another IP's: one IP per host address"
				return time.Minute
			}
		}
		st.Address, st.Host, st.Where = a.Address, h.Name, "host "+h.Name
		return 0
	case v1.IPTypeProvider:
		st.Where = x.Spec.Provider + " " + x.Spec.Region
		if st.Address != "" {
			return 0
		}
		p, pc, ok := c.provider(x.Spec.Provider)
		if !ok {
			cond.Status, cond.Reason, cond.Message = meta.ConditionFalse, "PluginMissing", "no plugin named "+x.Spec.Provider+" reserves addresses"
			return 30 * time.Second
		}
		as, err := p.Conn.ReserveAddress(ctx, kplugin.AddressReservation{Class: pc.Name, ID: x.UID, Namespace: x.Namespace, Name: x.Name, Region: x.Spec.Region})
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
	return 0
}

// release gives the address back (the IP is being deleted, and nothing holds it).
func (c *Controller) release(ctx context.Context, x *v1.IP) (engine.Result, error) {
	if !slices.Contains(x.Finalizers, v1.FinalizerIP) {
		return engine.Result{}, nil
	}
	if x.Spec.Type == v1.IPTypeProvider && (x.Status.Address != "" || x.Status.Handle != "") {
		p, pc, ok := c.provider(x.Spec.Provider)
		if !ok {
			return engine.Result{RequeueAfter: 30 * time.Second},
				c.condition(ctx, x, "Reserved", meta.ConditionFalse, "PluginMissing", "releasing "+x.Status.Address+" needs the plugin named "+x.Spec.Provider)
		}
		err := p.Conn.ReleaseAddress(ctx, kplugin.AddressRef{Class: pc.Name, ID: x.UID, Address: x.Status.Address, Handle: x.Status.Handle})
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
	if a.Address != b.Address || a.Host != b.Host || a.Region != b.Region || a.Handle != b.Handle || a.Where != b.Where ||
		len(a.Conditions) != len(b.Conditions) || fmt.Sprint(a.Holder) != fmt.Sprint(b.Holder) || fmt.Sprint(a.Waiting) != fmt.Sprint(b.Waiting) {
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
// host's addresses reach the IPs of type Host.
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
				add(changed.Namespace, o.(*v1.Service).Spec.LoadBalancerIP())
			}
		}
		c.heldBy(changed.Namespace, v1.HolderServicePrefix+changed.Name, add)
	case "Host":
		for _, o := range c.IPs.List() {
			if x := o.(*v1.IP); x.Spec.Type == v1.IPTypeHost {
				add(x.Namespace, x.Name)
			}
		}
	}
	return keys
}

// heldBy calls add for the IPs held by holder in ns, or waited for.
func (c *Controller) heldBy(ns, holder string, add func(ns, name string)) {
	for _, o := range c.IPs.List() {
		x := o.(*v1.IP)
		if x.Namespace != ns {
			continue
		}
		held := (x.Status.Holder != nil && x.Status.Holder.Holder == holder) ||
			slices.ContainsFunc(x.Status.Waiting, func(h v1.IPWaiting) bool { return h.Holder == holder })
		if held {
			add(x.Namespace, x.Name)
		}
	}
}

var (
	_ engine.Controller = (*Controller)(nil)
	_ engine.Mapper     = (*Controller)(nil)
)

// stillDecided reports whether the decision d, made from the caches, is the one a fresh read of
// x's claimants makes: the same holder.
func (c *Controller) stillDecided(ctx context.Context, x *v1.IP, d ips.Decision) (bool, error) {
	var silos []*v1.Silo
	var svcs []*v1.Service
	l, err := c.Client.List(ctx, "Silo", x.Namespace)
	if err != nil {
		return false, err
	}
	for _, raw := range l.Items {
		if o, _, err := v1.Decode(raw); err == nil {
			silos = append(silos, o.(*v1.Silo))
		}
	}
	if c.Services != nil {
		l, err := c.Client.List(ctx, "Service", x.Namespace)
		if err != nil {
			return false, err
		}
		for _, raw := range l.Items {
			if o, _, err := v1.Decode(raw); err == nil {
				svcs = append(svcs, o.(*v1.Service))
			}
		}
	}
	fresh := ips.Decide(x, ips.Claims(x, silos, svcs))
	if (fresh.Holder == nil) != (d.Holder == nil) {
		return false, nil
	}
	return fresh.Holder == nil || fresh.Holder.UID == d.Holder.UID, nil
}
