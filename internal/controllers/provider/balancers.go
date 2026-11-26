package provider

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
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
	"kevaso.com/core/internal/routing"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/sdk/kplugin"
)

// Balancers runs the providers' balancers (networking v2): one per service of type LoadBalancer,
// keyed by the service (a silo's: the silo's UID and the service's name; a standalone Service's:
// its UID), made through the plugin installed under the service's loadBalancer.provider.
//
//   - Sharing and tuning are the provider's annotations, declared by its plugin and checked at
//     apply (PROVIDER.kevaso.com/…): they go to the plugin untouched, on the balancer and on each
//     of its ports, and the plugin packs the services naming one shared balancer together. Core
//     never reads them.
//   - Created with its service: a finalizer per balancer (kevaso.com/balancer-PROVIDER.SERVICE on
//     the silo, kevaso.com/balancer-PROVIDER on a Service) is put on before the first ensure, so a
//     balancer is never left behind. Removed when its service goes, its silo or Service is
//     deleted, or it is no longer a LoadBalancer: DeleteLoadBalancer, then the finalizer. The
//     plugin removes a shared balancer with the last service on it. A failed delete keeps the
//     finalizer and is tried again (the namespace cascade waits on it).
//   - Backends are the ready silos (routeWhen) on the provider's own machines: a silo's host, a
//     Service's endpoints' hosts. A balancer whose silos are all held keeps its address, parked.
//   - Node ports: the balancer sends to each backend host on the node port of each port (the
//     silo's status.service.nodePorts, allocated by the scheduler; a Service's status.nodePorts,
//     by the service controller); the host opens them only to the balancer's addresses, which go
//     on the same status as sourceRanges.
//   - loadBalancer.ip: where the provider can front a balancer with a kept IP, the balancer
//     answers on that IP's address once the service holds it.
//
// The address goes on the silo's status.service (loadBalancerIP and each load-balanced port's
// loadBalancer, in one write) or the Service's status.loadBalancerIP, with a LoadBalancer
// condition on each.
type Balancers struct {
	Client   *client.Client
	IPs      *informer.Informer
	Silos    *informer.Informer
	Services *informer.Informer
	Hosts    *informer.Informer
	Plugins  *plugins.Registry
	Clock    clock.Clock
	// Providers are the hosts' provider details as the plugins said (K-037); nil: their status.
	Providers *Providers
	// Resync is how often an unchanged balancer is ensured anyway, to repair changes made outside
	// Kevaso (default 10m).
	Resync time.Duration

	mu        sync.Mutex
	ensured   map[string]asked  // balancer ID → the request last ensured
	hostsSeen map[string]string // host → what balancers depend on, last seen
}

// Name implements engine.Controller.
func (c *Balancers) Name() string { return "balancers" }

// Kind implements engine.Controller: a silo's services. Services' are ServiceBalancers'.
func (c *Balancers) Kind() string { return "Silo" }

// Domain is the annotation prefix a plugin reads: NAME.kevaso.com/.
func Domain(plugin string) string { return kplugin.Domain(plugin) }

// FinalizerBalancerPrefix starts each balancer's finalizer: kevaso.com/balancer-PROVIDER.SERVICE
// on a silo, kevaso.com/balancer-PROVIDER on a Service.
const FinalizerBalancerPrefix = "kevaso.com/balancer-"

func (c *Balancers) now() time.Time {
	if c.Clock == nil {
		return time.Now().UTC().Truncate(time.Second)
	}
	return c.Clock.Now().UTC().Truncate(time.Second)
}

// annotations are m's annotations in the plugin's domain, untouched (nil if none).
func annotations(m map[string]string, plugin string) map[string]string {
	var out map[string]string
	for k, v := range m {
		if strings.HasPrefix(k, Domain(plugin)) {
			if out == nil {
				out = map[string]string{}
			}
			out[k] = v
		}
	}
	return out
}

// SiloBalancerID is the balancer of a silo's service: the silo's UID and the service's name.
func SiloBalancerID(s *v1.Silo, service string) string { return s.UID + "/" + service }

// siloFinalizer is the finalizer of a silo's balancer.
func siloFinalizer(provider, service string) string {
	return FinalizerBalancerPrefix + provider + "." + service
}

// balancerClass is the class of provider p a balancer is made in: for one fronted by a kept IP,
// the class that reserves addresses; else the first that doesn't (a balancer with its own
// address), else the first; the zero Class for a plugin that declares only networking v2.
func balancerClass(p *plugins.Plugin, fronted bool) kplugin.Class {
	for _, cl := range p.Info.LoadBalancers {
		if cl.Reserve == fronted {
			return cl
		}
	}
	if len(p.Info.LoadBalancers) > 0 {
		return p.Info.LoadBalancers[0]
	}
	return kplugin.Class{}
}

// plugin is the plugin installed as name that makes balancers.
func (c *Balancers) plugin(name string) (*plugins.Plugin, bool) {
	if c.Plugins == nil {
		return nil, false
	}
	for _, p := range c.Plugins.All() {
		if p.Info.Name == name && (len(p.Info.LoadBalancers) > 0 || (p.Info.Networking != nil && p.Info.Networking.LoadBalancers)) {
			return p, true
		}
	}
	return nil, false
}

// providerHosts are every host of plugin's, by what the plugins said; ok false while one isn't
// described yet.
func (c *Balancers) providerHosts(plugin string) ([]kplugin.HostInfo, bool) {
	var out []kplugin.HostInfo
	for _, ho := range c.Hosts.List() {
		h := ho.(*v1.Host)
		hp, known := c.Providers.Of(h)
		if !known {
			return nil, false
		}
		if hp != nil && hp.Name == plugin {
			out = append(out, info(h.Name, hp))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, true
}

// outcome is one balancer's: its address, or why it has none yet.
type outcome struct {
	service, provider string
	addr              string
	ranges            []string
	announce          bool
	ready             bool
	reason, msg       string
	again             time.Duration
}

// frontIP is the kept IP fronting a balancer, when the holder (silo/NAME, uid) holds it: its
// address, or why it waits.
func (c *Balancers) frontIP(ns, name, uid string) (string, string) {
	o, ok := c.IPs.Get(ns, name)
	if !ok {
		return "", "IP " + name + " doesn't exist"
	}
	x := o.(*v1.IP)
	switch {
	case !x.Status.Holds(uid):
		if why := x.Status.WaitingReason(uid); why != "" {
			return "", why
		}
		return "", "waiting to hold IP " + name
	case x.Status.Address == "":
		return "", "IP " + name + " has no address yet"
	}
	return x.Status.Address, ""
}

// ensure makes or updates the balancer lb (no ports: parked, kept if it exists), remembering
// what it asked so an unchanged one isn't asked again before resync.
func (c *Balancers) ensure(ctx context.Context, p *plugins.Plugin, lb kplugin.LoadBalancer, extra string) (kplugin.LoadBalancerStatus, bool, error) {
	resync := c.Resync
	if resync <= 0 {
		resync = 10 * time.Minute
	}
	key := fmt.Sprintf("%+v|%s", lb, extra)
	c.mu.Lock()
	last, seen := c.ensured[lb.ID]
	c.mu.Unlock()
	if seen && last.key == key && time.Since(last.at) < resync && last.st != nil {
		return *last.st, true, nil
	}
	st, err := p.Conn.EnsureLoadBalancer(ctx, lb)
	if len(lb.Ports) == 0 && errors.Is(err, kplugin.ErrNotFound) {
		return kplugin.LoadBalancerStatus{}, false, nil // nothing to park yet
	}
	if err != nil {
		return st, false, err
	}
	c.mu.Lock()
	if c.ensured == nil {
		c.ensured = map[string]asked{}
	}
	c.ensured[lb.ID] = asked{key: key, at: time.Now(), st: &st}
	c.mu.Unlock()
	return st, true, nil
}

// remove deletes the balancer id of provider (gone already is done).
func (c *Balancers) remove(ctx context.Context, provider, id string) error {
	p, ok := c.plugin(provider)
	if !ok {
		return fmt.Errorf("removing balancer %s needs the plugin named %s", id, provider)
	}
	err := p.Conn.DeleteLoadBalancer(ctx, kplugin.LoadBalancerRef{Class: balancerClass(p, false).Name, ID: id})
	if err != nil && !errors.Is(err, kplugin.ErrNotFound) {
		return fmt.Errorf("remove balancer %s: %w", id, err)
	}
	c.mu.Lock()
	delete(c.ensured, id)
	c.mu.Unlock()
	return nil
}

// ── A silo's services ────────────────────────────────────────────────────────

// Reconcile implements engine.Controller.
func (c *Balancers) Reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	if !informer.AllSynced(c.IPs, c.Silos, c.Hosts) {
		return engine.Result{RequeueAfter: time.Second}, nil
	}
	o, ok := c.Silos.Get(k.Namespace, k.Name)
	if !ok {
		return engine.Result{}, nil
	}
	s := o.(*v1.Silo)
	want := map[string]v1.SiloService{} // finalizer → its service
	if s.DeletionTimestamp == nil {
		for _, sv := range s.Spec.Balancers() {
			if sv.LoadBalancer != nil && sv.LoadBalancer.Provider != "" {
				want[siloFinalizer(sv.LoadBalancer.Provider, v1.ServiceNameOf(sv, s.Name))] = sv
			}
		}
	}
	// Gone first: a balancer whose service went, or the silo's (deleting it removes them all).
	for _, f := range s.Finalizers {
		rest, ok := strings.CutPrefix(f, FinalizerBalancerPrefix)
		if !ok {
			continue
		}
		if _, keep := want[f]; keep {
			continue
		}
		provider, service, _ := strings.Cut(rest, ".")
		if err := c.remove(ctx, provider, SiloBalancerID(s, service)); err != nil {
			c.condition(ctx, s, meta.ConditionFalse, "Removing", err.Error())
			return engine.Result{}, err
		}
		if err := setFinalizers(ctx, c.Client, s, f, ""); err != nil {
			return engine.Result{}, err
		}
	}
	if len(want) == 0 {
		if s.DeletionTimestamp == nil && meta.FindCondition(s.Status.Conditions, "LoadBalancer") != nil && !s.Spec.LoadBalanced() {
			return engine.Result{}, updateSiloStatus(ctx, c.Client, s, func(cur *v1.Silo) {
				scheduler.SetLoadBalancerIP(cur, &cur.Status.Service, "")
				cur.Status.Service.SourceRanges, cur.Status.Service.Announce = nil, false
				cur.Status.Conditions = slices.DeleteFunc(cur.Status.Conditions, func(c meta.Condition) bool { return c.Type == "LoadBalancer" })
			})
		}
		return engine.Result{}, nil
	}
	var outs []outcome
	for _, sv := range s.Spec.Balancers() {
		f := siloFinalizer(sv.LoadBalancer.Provider, v1.ServiceNameOf(sv, s.Name))
		if _, ok := want[f]; !ok {
			continue
		}
		out, err := c.siloService(ctx, s, sv, f)
		if err != nil {
			return engine.Result{}, err
		}
		outs = append(outs, out)
	}
	if err := c.siloDone(ctx, s, outs); err != nil {
		return engine.Result{}, err
	}
	return engine.Result{RequeueAfter: soonest(outs, c.Resync)}, nil
}

// soonest is when to look again: the soonest any outcome asks, else the resync.
func soonest(outs []outcome, resync time.Duration) time.Duration {
	if resync <= 0 {
		resync = 10 * time.Minute
	}
	again := resync
	for _, o := range outs {
		if o.again > 0 && o.again < again {
			again = o.again
		}
	}
	return again
}

// siloService ensures the balancer of one of s's LoadBalancer services.
func (c *Balancers) siloService(ctx context.Context, s *v1.Silo, sv v1.SiloService, finalizer string) (outcome, error) {
	name := v1.ServiceNameOf(sv, s.Name)
	out := outcome{service: name, provider: sv.LoadBalancer.Provider}
	wait := func(reason, msg string, again time.Duration) (outcome, error) {
		out.reason, out.msg, out.again = reason, msg, again
		return out, nil
	}
	p, ok := c.plugin(sv.LoadBalancer.Provider)
	if !ok {
		return wait("PluginMissing", "no plugin named "+sv.LoadBalancer.Provider+" makes balancers", 30*time.Second)
	}
	fronted := sv.LoadBalancer.IP != ""
	pc := balancerClass(p, fronted)
	lb := kplugin.LoadBalancer{Class: pc.Name, ID: SiloBalancerID(s, name), Namespace: s.Namespace, Name: name,
		Annotations: annotations(sv.Annotations, p.Info.Name)}
	if fronted {
		addr, why := c.frontIP(s.Namespace, sv.LoadBalancer.IP, s.UID)
		if addr == "" {
			// Not (or no longer) its: a balancer it had lets the address go, for its holder's.
			if slices.Contains(s.Finalizers, finalizer) {
				if err := c.remove(ctx, p.Info.Name, lb.ID); err != nil {
					return out, err
				}
				if err := setFinalizers(ctx, c.Client, s, finalizer, ""); err != nil {
					return out, err
				}
			}
			return wait("WaitingForIP", why, 0)
		}
		lb.Address = addr
	}
	hosts, known := c.providerHosts(p.Info.Name)
	if !known {
		return wait("Pending", "waiting for the plugins to describe the hosts", 5*time.Second)
	}
	lb.Hosts = hosts

	// Its backend: the silo's host, while it's routed (routeWhen), with its node ports.
	ports, unenforced, why, reason := c.siloPorts(s, name, sv, p, pc)
	if why != "" {
		ports = nil
	}
	lb.Ports = ports
	if len(ports) > 0 {
		lb.Backends = ports[0].Backends
	}
	made := slices.Contains(s.Finalizers, finalizer)
	if len(lb.Ports) == 0 && !made {
		if why == "" {
			why, reason = "no port it can open", "NoPorts"
		}
		return wait(reason, why, 0) // nothing to make yet, nothing to park
	}
	if !made { // the finalizer first: a balancer is never made without one
		if err := setFinalizers(ctx, c.Client, s, "", finalizer); err != nil {
			return out, err
		}
	}
	st, exists, err := c.ensure(ctx, p, lb, why+fmt.Sprint(unenforced))
	if errors.Is(err, kplugin.ErrInProgress) {
		return wait("Provisioning", err.Error(), 10*time.Second)
	}
	if err != nil {
		out.reason, out.msg = "Failed", err.Error()
		c.condition(ctx, s, meta.ConditionFalse, "Failed", name+": "+err.Error())
		return out, fmt.Errorf("silo %s/%s service %s: %s balancer: %w", s.Namespace, s.Name, name, p.Info.Name, err)
	}
	if !exists {
		return wait(reason, why, 0)
	}
	out.addr, out.ranges, out.announce = st.Address, st.SourceRanges, pc.Announce
	if out.addr == "" {
		out.addr = lb.Address
	}
	switch {
	case why != "":
		out.reason, out.msg = reason, why+" (the balancer is kept, sending nowhere)"
	case len(unenforced) > 0:
		out.reason = "SourcesNotEnforced"
		out.msg = fmt.Sprintf("%s without %s: %s's balancer can't limit client sources (sources), and the host only sees the balancer's address; use a HostPort service, or drop sources",
			out.addr, strings.Join(unenforced, ", "), p.Info.Name)
	default:
		out.ready, out.reason = true, "Ready"
		out.msg = fmt.Sprintf("%s at %s: %d port(s)", p.Info.Name, out.addr, len(lb.Ports))
	}
	return out, nil
}

// siloPorts are the ports of s's service name on its balancer, to its host, or why it has none
// now: not placed, not routed (routeWhen), not on the provider's machine, no node ports yet.
// Ports whose sources the class can't enforce are left out (never open wider than asked).
func (c *Balancers) siloPorts(s *v1.Silo, name string, sv v1.SiloService, p *plugins.Plugin, pc kplugin.Class) (ports []kplugin.Port, unenforced []string, why, reason string) {
	if s.Status.Host == "" {
		return nil, nil, "waiting to be placed", "Pending"
	}
	if r := routing.Silo(s.Spec, s.Status); r != nil && !r.Routed {
		return nil, nil, "held back: " + r.Reason, "NotRouted"
	}
	ho, ok := c.Hosts.Get("", s.Status.Host)
	if !ok {
		return nil, nil, "its host " + s.Status.Host + " is gone", "Pending"
	}
	h := ho.(*v1.Host)
	hp, known := c.Providers.Of(h)
	if !known {
		return nil, nil, "waiting for the plugins to describe " + h.Name, "Pending"
	}
	if hp == nil || hp.Name != p.Info.Name {
		return nil, nil, s.Status.Host + " isn't a " + p.Info.Name + " machine", "NotOnProvider"
	}
	if pc.NodePorts && len(s.Status.Service.NodePorts) == 0 {
		return nil, nil, "waiting for its node ports", "Pending"
	}
	nps := map[string]int{}
	for _, np := range s.Status.Service.NodePorts {
		nps[np.Name] = np.NodePort
	}
	ann := annotations(sv.Annotations, p.Info.Name)
	for _, sp := range s.Spec.OpenIn(s.Name) {
		if !sp.LoadBalancer || sp.Service != name {
			continue
		}
		src := sp.Sources
		if pc.Announce {
			src = nil // the address arrives at the host with the client's own source: its rules check it
		} else if src != nil && !pc.FiltersSources {
			unenforced = append(unenforced, sp.Name)
			continue
		}
		if pc.NodePorts && nps[sp.Name] == 0 {
			return nil, nil, "waiting for the node port of " + sp.Name, "Pending"
		}
		ports = append(ports, kplugin.Port{Name: sp.Name, Protocol: sp.Protocol, Port: sp.HostNumber(), NodePort: nps[sp.Name], Sources: src,
			Service: v1.HolderSiloPrefix + s.Name, Backends: []kplugin.HostInfo{info(h.Name, hp)}, Annotations: ann})
	}
	return ports, unenforced, "", ""
}

// siloDone writes the balancers' outcome on s: the address (its first LoadBalancer service's),
// on loadBalancerIP and each load-balanced port in one write, the balancers' source ranges, and
// the LoadBalancer condition.
func (c *Balancers) siloDone(ctx context.Context, s *v1.Silo, outs []outcome) error {
	addr, announce := "", false
	var ranges []string
	cond := meta.Condition{Type: "LoadBalancer", Status: meta.ConditionTrue, Reason: "Ready", ObservedGeneration: s.Generation}
	var msgs []string
	for _, o := range outs {
		if o.addr != "" && addr == "" {
			addr, announce = o.addr, o.announce
		}
		for _, r := range o.ranges {
			if !slices.Contains(ranges, r) {
				ranges = append(ranges, r)
			}
		}
		msgs = append(msgs, o.service+": "+o.msg)
		if !o.ready && cond.Status == meta.ConditionTrue {
			cond.Status, cond.Reason = meta.ConditionFalse, o.reason
		}
	}
	cond.Message = strings.Join(msgs, "; ")
	return updateSiloStatus(ctx, c.Client, s, func(cur *v1.Silo) {
		// The ports' addresses with it, in the same write: a reader in between would see an
		// address with no port on it.
		scheduler.SetLoadBalancerIP(cur, &cur.Status.Service, addr)
		cur.Status.Service.SourceRanges, cur.Status.Service.Announce = ranges, announce
		meta.SetCondition(&cur.Status.Conditions, cond, c.now())
	})
}

// condition sets s's LoadBalancer condition alone (a failure, before the outcome is written).
func (c *Balancers) condition(ctx context.Context, s *v1.Silo, status meta.ConditionStatus, reason, msg string) {
	_ = updateSiloStatus(ctx, c.Client, s, func(cur *v1.Silo) {
		meta.SetCondition(&cur.Status.Conditions, meta.Condition{Type: "LoadBalancer", Status: status, Reason: reason, Message: msg, ObservedGeneration: cur.Generation}, c.now())
	})
}

// Map implements engine.Mapper: an IP reaches the silos holding or waiting for it (a kept IP
// fronting a balancer); a host's provider details or readiness reach the silos with a balancer
// (only when they changed: not on every heartbeat).
func (c *Balancers) Map(changed engine.Key) []engine.Key {
	var keys []engine.Key
	add := func(ns, name string) {
		keys = append(keys, engine.Key{Kind: "Silo", Namespace: ns, Name: name})
	}
	switch changed.Kind {
	case "IP":
		if o, ok := c.IPs.Get(changed.Namespace, changed.Name); ok {
			x := o.(*v1.IP)
			if h := x.Status.Holder; h != nil {
				if n, ok := strings.CutPrefix(h.Holder, v1.HolderSiloPrefix); ok {
					add(x.Namespace, n)
				}
			}
			for _, w := range x.Status.Waiting {
				if n, ok := strings.CutPrefix(w.Holder, v1.HolderSiloPrefix); ok {
					add(x.Namespace, n)
				}
			}
		}
	case "Host":
		if !c.hostChanged("silo", changed.Name) {
			return nil
		}
		for _, o := range c.Silos.List() {
			if s := o.(*v1.Silo); s.Spec.LoadBalanced() {
				add(s.Namespace, s.Name)
			}
		}
	}
	return keys
}

// hostChanged reports whether what balancers read of host changed since who last asked.
func (c *Balancers) hostChanged(who, name string) bool {
	key := ""
	if o, ok := c.Hosts.Get("", name); ok {
		h := o.(*v1.Host)
		hp, _ := c.Providers.Of(h)
		key = fmt.Sprintf("%v|%+v", meta.IsTrue(h.Status.Conditions, "Ready"), hp)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hostsSeen == nil {
		c.hostsSeen = map[string]string{}
	}
	prev, had := c.hostsSeen[who+"/"+name]
	c.hostsSeen[who+"/"+name] = key
	return !had || prev != key
}

// ── A standalone Service ─────────────────────────────────────────────────────

// ServiceBalancers is Balancers for standalone Services of type LoadBalancer: backends are the
// hosts of its routed endpoints, each on the Service's node ports.
type ServiceBalancers struct{ *Balancers }

// Name implements engine.Controller.
func (c ServiceBalancers) Name() string { return "service-balancers" }

// Kind implements engine.Controller.
func (c ServiceBalancers) Kind() string { return "Service" }

// ServiceFinalizer is the finalizer of a Service's balancer made by provider.
func ServiceFinalizer(provider string) string { return FinalizerBalancerPrefix + provider }

// Reconcile implements engine.Controller.
func (c ServiceBalancers) Reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	if !informer.AllSynced(c.IPs, c.Services, c.Hosts) {
		return engine.Result{RequeueAfter: time.Second}, nil
	}
	o, ok := c.Services.Get(k.Namespace, k.Name)
	if !ok {
		return engine.Result{}, nil
	}
	svc := o.(*v1.Service)
	want := ""
	if svc.DeletionTimestamp == nil && svc.Spec.TypeOrDefault() == v1.ServiceLoadBalancer && svc.Spec.LoadBalancer != nil {
		want = ServiceFinalizer(svc.Spec.LoadBalancer.Provider)
	}
	for _, f := range svc.Finalizers {
		provider, ok := strings.CutPrefix(f, FinalizerBalancerPrefix)
		if !ok || f == want {
			continue
		}
		if err := c.remove(ctx, provider, svc.UID); err != nil {
			_ = c.serviceStatus(ctx, svc, func(ss *v1.ServiceStatus) {
				meta.SetCondition(&ss.Conditions, meta.Condition{Type: "LoadBalancer", Status: meta.ConditionFalse, Reason: "Removing", Message: err.Error(), ObservedGeneration: svc.Generation}, c.now())
			})
			return engine.Result{}, err
		}
		if err := c.serviceFinalizers(ctx, svc, f, ""); err != nil {
			return engine.Result{}, err
		}
	}
	if want == "" {
		return engine.Result{}, nil
	}
	out, made, err := c.service(ctx, svc, want)
	if err != nil {
		return engine.Result{}, err
	}
	err = c.serviceStatus(ctx, svc, func(ss *v1.ServiceStatus) {
		cond := meta.Condition{Type: "LoadBalancer", Status: meta.ConditionTrue, Reason: "Ready", Message: out.msg, ObservedGeneration: svc.Generation}
		if !out.ready {
			cond.Status, cond.Reason = meta.ConditionFalse, out.reason
		}
		if made || out.addr != "" {
			ss.LoadBalancerIP, ss.SourceRanges = out.addr, out.ranges
			ss.IP = svc.Spec.LoadBalancerIP()
		} else {
			ss.LoadBalancerIP, ss.IP, ss.SourceRanges = "", "", nil
		}
		meta.SetCondition(&ss.Conditions, cond, c.now())
	})
	if err != nil {
		return engine.Result{}, err
	}
	return engine.Result{RequeueAfter: soonest([]outcome{out}, c.Resync)}, nil
}

// service ensures svc's balancer; made says whether it exists.
func (c ServiceBalancers) service(ctx context.Context, svc *v1.Service, finalizer string) (outcome, bool, error) {
	l := svc.Spec.LoadBalancer
	out := outcome{service: svc.Name, provider: l.Provider}
	wait := func(reason, msg string, again time.Duration) (outcome, bool, error) {
		out.reason, out.msg, out.again = reason, msg, again
		return out, false, nil
	}
	p, ok := c.plugin(l.Provider)
	if !ok {
		return wait("PluginMissing", "no plugin named "+l.Provider+" makes balancers", 30*time.Second)
	}
	pc := balancerClass(p, l.IP != "")
	lb := kplugin.LoadBalancer{Class: pc.Name, ID: svc.UID, Namespace: svc.Namespace, Name: svc.Name, Annotations: annotations(svc.Annotations, p.Info.Name)}
	if l.IP != "" {
		addr, why := c.frontIP(svc.Namespace, l.IP, svc.UID)
		if addr == "" {
			if slices.Contains(svc.Finalizers, finalizer) {
				if err := c.remove(ctx, p.Info.Name, lb.ID); err != nil {
					return out, false, err
				}
				if err := c.serviceFinalizers(ctx, svc, finalizer, ""); err != nil {
					return out, false, err
				}
			}
			return wait("WaitingForIP", why, 0)
		}
		lb.Address = addr
	}
	hosts, known := c.providerHosts(p.Info.Name)
	if !known {
		return wait("Pending", "waiting for the plugins to describe the hosts", 5*time.Second)
	}
	lb.Hosts = hosts
	ports, off, why, reason := c.servicePorts(svc, p, pc)
	lb.Ports = ports
	backends := map[string]kplugin.HostInfo{}
	for _, pt := range ports {
		for _, b := range pt.Backends {
			backends[b.Name] = b
		}
	}
	for _, n := range slices.Sorted(maps.Keys(backends)) {
		lb.Backends = append(lb.Backends, backends[n])
	}
	made := slices.Contains(svc.Finalizers, finalizer)
	if len(ports) == 0 && !made {
		return wait(reason, why, 0)
	}
	if !made {
		if err := c.serviceFinalizers(ctx, svc, "", finalizer); err != nil {
			return out, false, err
		}
	}
	st, exists, err := c.ensure(ctx, p, lb, why+fmt.Sprint(off))
	if errors.Is(err, kplugin.ErrInProgress) {
		return wait("Provisioning", err.Error(), 10*time.Second)
	}
	if err != nil {
		out.reason, out.msg = "Failed", err.Error()
		_ = c.serviceStatus(ctx, svc, func(ss *v1.ServiceStatus) {
			meta.SetCondition(&ss.Conditions, meta.Condition{Type: "LoadBalancer", Status: meta.ConditionFalse, Reason: "Failed", Message: err.Error(), ObservedGeneration: svc.Generation}, c.now())
		})
		return out, false, fmt.Errorf("service %s/%s: %s balancer: %w", svc.Namespace, svc.Name, p.Info.Name, err)
	}
	if !exists {
		return wait(reason, why, 0)
	}
	out.addr, out.ranges = st.Address, st.SourceRanges
	if out.addr == "" {
		out.addr = lb.Address
	}
	switch {
	case why != "":
		out.reason, out.msg = reason, why+" (the balancer is kept, sending nowhere)"
	default:
		out.ready, out.reason = true, "Ready"
		out.msg = fmt.Sprintf("%s at %s: %d port(s) to %d host(s)", p.Info.Name, out.addr, len(ports), len(lb.Backends))
		if len(off) > 0 {
			out.msg += "; endpoints on " + strings.Join(off, ", ") + " aren't " + p.Info.Name + " machines, so it can't reach them"
		}
	}
	return out, true, nil
}

// servicePorts are a Service's ports on its balancer, to the hosts of its routed endpoints (each
// such host sends them on to its own endpoints), or why it has none now.
func (c ServiceBalancers) servicePorts(svc *v1.Service, p *plugins.Plugin, pc kplugin.Class) (ports []kplugin.Port, off []string, why, reason string) {
	if pc.NodePorts && len(svc.Status.NodePorts) < len(svc.Spec.Ports) {
		return nil, nil, "waiting for its node ports", "Pending"
	}
	seen := map[string]bool{}
	var backends []kplugin.HostInfo
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
		hp, known := c.Providers.Of(h)
		if !known {
			return nil, nil, "waiting for the plugins to describe " + h.Name, "Pending"
		}
		if hp == nil || hp.Name != p.Info.Name {
			off = append(off, ep.Host)
			continue
		}
		backends = append(backends, info(h.Name, hp))
	}
	sort.Slice(backends, func(i, j int) bool { return backends[i].Name < backends[j].Name })
	if len(backends) == 0 {
		msg := "no ready endpoints on " + p.Info.Name + " machines yet"
		if len(off) > 0 {
			msg += " (" + strings.Join(off, ", ") + " aren't)"
		}
		return nil, off, msg, "NoBackends"
	}
	nps := map[string]int{}
	for _, np := range svc.Status.NodePorts {
		nps[np.Name] = np.NodePort
	}
	ann := annotations(svc.Annotations, p.Info.Name)
	for _, sp := range svc.Spec.Ports {
		proto := "TCP"
		if strings.EqualFold(sp.Protocol, "UDP") {
			proto = "UDP"
		}
		ports = append(ports, kplugin.Port{Name: sp.Name, Protocol: proto, Port: sp.Port, NodePort: nps[sp.Name],
			Service: v1.HolderServicePrefix + svc.Name, Backends: backends, Annotations: ann})
	}
	return ports, off, "", ""
}

func (c ServiceBalancers) serviceStatus(ctx context.Context, svc *v1.Service, mutate func(*v1.ServiceStatus)) error {
	for attempt := 0; attempt < 5; attempt++ {
		var cur v1.Service
		if err := c.Client.Get(ctx, "Service", svc.Namespace, svc.Name, &cur); err != nil {
			return client.IgnoreNotFound(err)
		}
		if cur.UID != svc.UID {
			return nil
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
		return client.IgnoreNotFound(err)
	}
	return errors.New("service kept changing; will retry")
}

// serviceFinalizers removes one finalizer and/or adds one on the latest copy of svc.
func (c ServiceBalancers) serviceFinalizers(ctx context.Context, svc *v1.Service, remove, add string) error {
	for attempt := 0; attempt < 5; attempt++ {
		var cur v1.Service
		if err := c.Client.Get(ctx, "Service", svc.Namespace, svc.Name, &cur); err != nil {
			return client.IgnoreNotFound(err)
		}
		if cur.UID != svc.UID {
			return nil
		}
		fs := slices.DeleteFunc(slices.Clone(cur.Finalizers), func(f string) bool { return f == remove })
		if add != "" && !slices.Contains(fs, add) {
			if cur.DeletionTimestamp != nil {
				return nil
			}
			fs = append(fs, add)
		}
		if slices.Equal(fs, cur.Finalizers) {
			return nil
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

// Map implements engine.Mapper: a silo reaches the Services whose endpoints it is or may become
// (by the selector); an IP the Services holding or waiting for it; a host's provider details or
// readiness every LoadBalancer Service.
func (c ServiceBalancers) Map(changed engine.Key) []engine.Key {
	var keys []engine.Key
	lbs := func(match func(*v1.Service) bool) {
		for _, o := range c.Services.List() {
			if svc := o.(*v1.Service); svc.Spec.TypeOrDefault() == v1.ServiceLoadBalancer && match(svc) {
				keys = append(keys, engine.Key{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name})
			}
		}
	}
	switch changed.Kind {
	case "IP":
		lbs(func(svc *v1.Service) bool {
			return svc.Namespace == changed.Namespace && svc.Spec.LoadBalancerIP() == changed.Name
		})
	case "Host":
		if c.hostChanged("service", changed.Name) {
			lbs(func(*v1.Service) bool { return true })
		}
	}
	return keys
}

var (
	_ engine.Controller = (*Balancers)(nil)
	_ engine.Mapper     = (*Balancers)(nil)
	_ engine.Controller = ServiceBalancers{}
	_ engine.Mapper     = ServiceBalancers{}
)
