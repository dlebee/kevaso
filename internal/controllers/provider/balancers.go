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
	"kevaso.com/core/sdk/kplugin"
)

// Balancers runs the balancer behind each IP of a plugin's class (design §7.2c-1). There is no
// load-balancer object: one EnsureLoadBalancer per IP, keyed by its UID, carries every open port
// of every service holding the IP, each port with its own backends (a silo's host; a Service's
// endpoints' hosts) and its own sources. The plugin packs them (one NodeBalancer, a config per
// port). The address goes back on every holder's status; for a class that can't reserve, it's
// the balancer's and becomes the IP's. The IP controller parks or unshares the balancer when the
// last holder goes, and releases it with the IP.
//
// Whether a port is open is decided per port and composes: a leased port with no open lease
// (design §7.2d) isn't in the list, nor is one whose sources can't be enforced or allowed at all.
// Annotations in the plugin's domain (NAME.kevaso.com/…) on the IP and on each service go to the
// plugin untouched; a refusal shows on the IP and its holders.
type Balancers struct {
	Client   *client.Client
	IPs      *informer.Informer
	Silos    *informer.Informer
	Services *informer.Informer
	Hosts    *informer.Informer
	Leases   *informer.Informer // optional
	Plugins  *plugins.Registry
	Clock    clock.Clock
	// Resync is how often an unchanged balancer is ensured anyway, to repair changes made outside
	// Kevaso (default 10m).
	Resync time.Duration

	mu        sync.Mutex
	ensured   map[string]asked  // IP UID → the request last ensured
	hostsSeen map[string]string // host → what balancers depend on, last seen
}

// Name implements engine.Controller.
func (c *Balancers) Name() string { return "balancers" }

// Kind implements engine.Controller.
func (c *Balancers) Kind() string { return "IP" }

func (c *Balancers) now() time.Time {
	if c.Clock == nil {
		return time.Now().UTC().Truncate(time.Second)
	}
	return c.Clock.Now().UTC().Truncate(time.Second)
}

// Domain is the annotation prefix a plugin reads: NAME.kevaso.com/.
func Domain(plugin string) string { return plugin + ".kevaso.com/" }

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

// holderState is one holder's part of the balancer, and what to tell it.
type holderState struct {
	silo       *v1.Silo
	svc        *v1.Service
	ports      int
	unenforced []string
	off        []string // a Service's endpoints on hosts that aren't the plugin's
	why        string   // why it has nothing on the balancer yet ("" when it does)
	reason     string
}

// Reconcile implements engine.Controller.
func (c *Balancers) Reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	o, ok := c.IPs.Get(k.Namespace, k.Name)
	if !ok {
		return engine.Result{}, nil
	}
	x := o.(*v1.IP)
	if x.DeletionTimestamp != nil || x.Spec.Class == v1.LBIPPool {
		return engine.Result{}, nil
	}
	c.tellWaiting(ctx, x)
	if len(x.Status.BoundTo) == 0 {
		forget(&c.mu, &c.ensured, x.UID)
		return engine.Result{}, nil // the IP controller parked or unshared it
	}
	p, pc, ok := c.Plugins.LoadBalancer(x.Spec.Class)
	if !ok {
		return engine.Result{RequeueAfter: 30 * time.Second}, nil // the IP says PluginMissing
	}
	if pc.Reserve && x.Status.Address == "" {
		return engine.Result{}, nil // reserved first
	}
	lb := kplugin.LoadBalancer{Class: x.Spec.Class, ID: x.UID, Namespace: x.Namespace, Name: x.Name,
		Annotations: annotations(x.Annotations, p.Info.Name)}
	if pc.Reserve {
		lb.Address = x.Status.Address
	}
	for _, ho := range c.Hosts.List() {
		if h := ho.(*v1.Host); h.Status.Provider != nil && h.Status.Provider.Name == p.Info.Name {
			lb.Hosts = append(lb.Hosts, info(h))
		}
	}
	sort.Slice(lb.Hosts, func(i, j int) bool { return lb.Hosts[i].Name < lb.Hosts[j].Name })
	var states []*holderState
	var leaseEnd time.Time
	var region *v1.Host
	backends := map[string]kplugin.HostInfo{}
	for _, h := range x.Status.BoundTo {
		st := &holderState{}
		states = append(states, st)
		switch {
		case strings.HasPrefix(h.Holder, v1.HolderSiloPrefix):
			so, ok := c.Silos.Get(x.Namespace, strings.TrimPrefix(h.Holder, v1.HolderSiloPrefix))
			if !ok || so.(*v1.Silo).UID != h.UID {
				continue
			}
			s := so.(*v1.Silo)
			st.silo = s
			if s.DeletionTimestamp != nil || v1.PluginLB(s) == "" {
				st.why = "-" // going, or only sending from it: nothing in
				continue
			}
			ports, host, end, why, reason := c.siloPorts(s, p, pc, &st.unenforced)
			st.why, st.reason = why, reason
			if why != "" {
				continue
			}
			if region == nil {
				region = host
			}
			if !end.IsZero() && (leaseEnd.IsZero() || end.Before(leaseEnd)) {
				leaseEnd = end
			}
			for _, pt := range ports {
				for _, b := range pt.Backends {
					backends[b.Name] = b
				}
			}
			st.ports = len(ports)
			lb.Ports = append(lb.Ports, ports...)
		case strings.HasPrefix(h.Holder, v1.HolderServicePrefix):
			vo, ok := c.Services.Get(x.Namespace, strings.TrimPrefix(h.Holder, v1.HolderServicePrefix))
			if !ok || vo.(*v1.Service).UID != h.UID {
				continue
			}
			svc := vo.(*v1.Service)
			st.svc = svc
			if svc.DeletionTimestamp != nil {
				st.why = "-"
				continue
			}
			ports, off, why, reason := c.servicePorts(svc, p, pc)
			st.off, st.why, st.reason = off, why, reason
			if why != "" {
				continue
			}
			for _, pt := range ports {
				for _, b := range pt.Backends {
					backends[b.Name] = b
				}
			}
			st.ports = len(ports)
			lb.Ports = append(lb.Ports, ports...)
		}
	}
	for _, n := range slices.Sorted(maps.Keys(backends)) {
		lb.Backends = append(lb.Backends, backends[n])
	}
	resync := c.Resync
	if resync <= 0 {
		resync = 10 * time.Minute
	}
	var again time.Duration // look again when a lease ends, even if nothing else changes
	if !leaseEnd.IsZero() {
		again = max(leaseEnd.Sub(c.now()), time.Second)
	}
	if len(lb.Ports) == 0 {
		lb.Backends = nil // parked: its holders have nothing open on it now
	}
	// Silos, Services and hosts change all the time (status, heartbeats); the cloud only when this does.
	reqKey := fmt.Sprintf("%+v", lb)
	for _, st := range states {
		reqKey += fmt.Sprintf("|%s%v%v", st.why, st.unenforced, st.off)
	}
	if x.Status.Address != "" && remember(&c.mu, &c.ensured, x.UID, reqKey, resync) {
		return engine.Result{RequeueAfter: again}, nil
	}
	res, err := p.Conn.EnsureLoadBalancer(ctx, lb)
	if len(lb.Ports) == 0 && errors.Is(err, kplugin.ErrNotFound) {
		err = nil // nothing to park yet
	}
	if errors.Is(err, kplugin.ErrInProgress) {
		c.tell(ctx, x, states, meta.ConditionFalse, "Provisioning", err.Error())
		return engine.Result{RequeueAfter: 10 * time.Second}, nil
	}
	if err != nil {
		c.tell(ctx, x, states, meta.ConditionFalse, "Failed", err.Error())
		return engine.Result{}, fmt.Errorf("IP %s/%s: %s balancer: %w", x.Namespace, x.Name, x.Spec.Class, err)
	}
	if !pc.Reserve && res.Address != "" {
		if err := ipAddress(ctx, c.Client, x, res.Address, region); err != nil {
			return engine.Result{}, err
		}
	}
	addr := res.Address
	if addr == "" {
		addr = x.Status.Address
	}
	if addr == "" {
		addr = "no address yet (no open port)"
	}
	for _, st := range states {
		if err := c.done(ctx, x, st, p.Info.Name, addr, res.SourceRanges, pc.Announce); err != nil {
			return engine.Result{}, err
		}
	}
	if err := c.ipCondition(ctx, x, meta.ConditionTrue, "Ready", fmt.Sprintf("%s at %s: %d port(s) for %s", x.Spec.Class, addr, len(lb.Ports), x.Status.Holders())); err != nil {
		return engine.Result{}, err
	}
	record(&c.mu, &c.ensured, x.UID, reqKey)
	if again > 0 && again < resync {
		return engine.Result{RequeueAfter: again}, nil
	}
	return engine.Result{RequeueAfter: resync}, nil
}

// siloPorts are a silo's open ports on its IP's balancer, to its host, or why it has none yet.
func (c *Balancers) siloPorts(s *v1.Silo, p *plugins.Plugin, pc kplugin.Class, unenforced *[]string) (ports []kplugin.Port, host *v1.Host, leaseEnd time.Time, why, reason string) {
	if s.Status.Host == "" {
		return nil, nil, time.Time{}, "waiting to be placed", "Pending"
	}
	ho, ok := c.Hosts.Get("", s.Status.Host)
	if !ok {
		return nil, nil, time.Time{}, "its host " + s.Status.Host + " is gone", "Pending"
	}
	h := ho.(*v1.Host)
	if h.Status.Provider == nil || h.Status.Provider.Name != p.Info.Name {
		return nil, nil, time.Time{}, s.Status.Host + " isn't a " + p.Info.Name + " machine", "NotOnProvider"
	}
	if pc.NodePorts && len(s.Status.Service.NodePorts) == 0 {
		return nil, nil, time.Time{}, "waiting for its node ports", "Pending"
	}
	nps := map[string]int{}
	for _, np := range s.Status.Service.NodePorts {
		nps[np.Name] = np.NodePort
	}
	closed, end := c.leased(s)
	ann := annotations(s.Annotations, p.Info.Name)
	for _, sp := range s.Spec.Open() {
		if !sp.LoadBalancer || slices.Contains(closed, sp.Name) {
			continue
		}
		src := sp.Sources
		// An announced address arrives at the silo's host with the client's own source, and the
		// host's rules check it. Otherwise only the balancer sees clients.
		if !pc.Announce {
			if src != nil && !pc.FiltersSources {
				*unenforced = append(*unenforced, sp.Name)
				continue
			}
		} else {
			src = nil
		}
		ports = append(ports, kplugin.Port{Name: sp.Name, Protocol: sp.Protocol, Port: sp.HostNumber(), NodePort: nps[sp.Name], Sources: src,
			Service: v1.HolderSiloPrefix + s.Name, Backends: []kplugin.HostInfo{info(h)}, Annotations: ann})
	}
	return ports, h, end, "", ""
}

// servicePorts are a Service's ports on its IP's balancer, to the hosts with its endpoints (each
// such host sends them to its own endpoints, so client addresses are kept), or why it has none.
func (c *Balancers) servicePorts(svc *v1.Service, p *plugins.Plugin, pc kplugin.Class) (ports []kplugin.Port, off []string, why, reason string) {
	if !pc.NodePorts {
		return nil, nil, svc.Spec.LoadBalancerClass + " routes one address to one host: a Service of several silos needs a class with node ports (e.g. linode-nodebalancer)", "ClassUnsuitable"
	}
	if len(svc.Status.NodePorts) < len(svc.Spec.Ports) {
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
		if h.Status.Provider == nil || h.Status.Provider.Name != p.Info.Name {
			off = append(off, ep.Host)
			continue
		}
		backends = append(backends, info(h))
	}
	sort.Slice(backends, func(i, j int) bool { return backends[i].Name < backends[j].Name })
	if len(backends) == 0 {
		msg := "no endpoints on " + p.Info.Name + " machines yet"
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

// done writes the address on one holder, with its LoadBalancer condition. Only the address in:
// the address out is the scheduler's (scheduler.Egress), which never takes a balancer's address,
// on no host, for a silo to send from.
func (c *Balancers) done(ctx context.Context, x *v1.IP, st *holderState, plugin, addr string, ranges []string, announce bool) error {
	class := x.Spec.Class
	switch {
	case st.silo != nil:
		if st.why == "-" {
			return nil
		}
		return updateStatus(ctx, c.Client, st.silo, func(ss *v1.SiloStatus) {
			cond := meta.Condition{Type: "LoadBalancer", Status: meta.ConditionTrue, Reason: "Ready",
				Message: fmt.Sprintf("%s at %s (IP %s)", class, addr, x.Name), ObservedGeneration: st.silo.Generation}
			if st.why != "" {
				cond.Status, cond.Reason, cond.Message = meta.ConditionFalse, st.reason, st.why
			} else {
				ss.Service.LoadBalancerIP, ss.Service.SourceRanges, ss.Service.Announce = x.Status.Address, ranges, announce
				if res := addr; !strings.HasPrefix(res, "no address") {
					ss.Service.LoadBalancerIP = res
				}
				if len(st.unenforced) > 0 {
					cond.Status, cond.Reason = meta.ConditionFalse, "SourcesNotEnforced"
					cond.Message = fmt.Sprintf("%s at %s without %s: class %s can't limit client sources (allowFrom), and its hosts only see the load balancer's; use an announced class or hostPort, or drop allowFrom",
						class, addr, strings.Join(st.unenforced, ", "), class)
				}
			}
			meta.SetCondition(&ss.Conditions, cond, c.now())
		})
	case st.svc != nil:
		if st.why == "-" {
			return nil
		}
		return c.serviceStatus(ctx, st.svc, func(ss *v1.ServiceStatus) {
			cond := meta.Condition{Type: "LoadBalancer", Status: meta.ConditionTrue, Reason: "Ready", Message: class + " at " + addr, ObservedGeneration: st.svc.Generation}
			if st.why != "" {
				cond.Status, cond.Reason, cond.Message = meta.ConditionFalse, st.reason, st.why
			} else {
				ss.LoadBalancerIP, ss.IP, ss.SourceRanges = x.Status.Address, x.Name, ranges
				if !strings.HasPrefix(addr, "no address") {
					ss.LoadBalancerIP = addr
				}
				if len(st.off) > 0 {
					cond.Message += "; endpoints on " + strings.Join(st.off, ", ") + " aren't " + plugin + " machines, so it can't reach them"
				}
			}
			meta.SetCondition(&ss.Conditions, cond, c.now())
		})
	}
	return nil
}

// tell sets the LoadBalancer condition on the IP and every holder.
func (c *Balancers) tell(ctx context.Context, x *v1.IP, states []*holderState, status meta.ConditionStatus, reason, msg string) {
	_ = c.ipCondition(ctx, x, status, reason, msg)
	for _, st := range states {
		cond := meta.Condition{Type: "LoadBalancer", Status: status, Reason: reason, Message: "IP " + x.Name + ": " + msg}
		switch {
		case st.silo != nil:
			cond.ObservedGeneration = st.silo.Generation
			_ = updateStatus(ctx, c.Client, st.silo, func(ss *v1.SiloStatus) { meta.SetCondition(&ss.Conditions, cond, c.now()) })
		case st.svc != nil:
			cond.ObservedGeneration = st.svc.Generation
			_ = c.serviceStatus(ctx, st.svc, func(ss *v1.ServiceStatus) { meta.SetCondition(&ss.Conditions, cond, c.now()) })
		}
	}
}

// tellWaiting says to each service waiting for x why (a port another holder has, an exclusive
// address someone holds), and takes the address off its status.
func (c *Balancers) tellWaiting(ctx context.Context, x *v1.IP) {
	for _, w := range x.Status.Waiting {
		cond := meta.Condition{Type: "LoadBalancer", Status: meta.ConditionFalse, Reason: "WaitingForIP", Message: w.Reason}
		switch {
		case strings.HasPrefix(w.Holder, v1.HolderSiloPrefix):
			if so, ok := c.Silos.Get(x.Namespace, strings.TrimPrefix(w.Holder, v1.HolderSiloPrefix)); ok {
				s := so.(*v1.Silo)
				cond.ObservedGeneration = s.Generation
				_ = updateStatus(ctx, c.Client, s, func(ss *v1.SiloStatus) {
					ss.Service.LoadBalancerIP, ss.Service.SourceRanges, ss.Service.Announce = "", nil, false
					meta.SetCondition(&ss.Conditions, cond, c.now())
				})
			}
		case strings.HasPrefix(w.Holder, v1.HolderServicePrefix) && c.Services != nil:
			if vo, ok := c.Services.Get(x.Namespace, strings.TrimPrefix(w.Holder, v1.HolderServicePrefix)); ok {
				svc := vo.(*v1.Service)
				cond.ObservedGeneration = svc.Generation
				_ = c.serviceStatus(ctx, svc, func(ss *v1.ServiceStatus) {
					ss.LoadBalancerIP, ss.IP, ss.SourceRanges = "", "", nil
					meta.SetCondition(&ss.Conditions, cond, c.now())
				})
			}
		}
	}
}

func (c *Balancers) ipCondition(ctx context.Context, x *v1.IP, status meta.ConditionStatus, reason, msg string) error {
	for attempt := 0; attempt < 5; attempt++ {
		var cur v1.IP
		if err := c.Client.Get(ctx, "IP", x.Namespace, x.Name, &cur); err != nil {
			return client.IgnoreNotFound(err)
		}
		if cur.UID != x.UID || !meta.SetCondition(&cur.Status.Conditions, meta.Condition{Type: "LoadBalancer", Status: status, Reason: reason,
			Message: msg, ObservedGeneration: cur.Generation}, c.now()) {
			return nil
		}
		err := c.Client.UpdateStatus(ctx, &cur)
		if client.IsConflict(err) {
			continue
		}
		return client.IgnoreNotFound(err)
	}
	return errors.New("IP kept changing; will retry")
}

func (c *Balancers) serviceStatus(ctx context.Context, svc *v1.Service, mutate func(*v1.ServiceStatus)) error {
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
		return err
	}
	return errors.New("service kept changing; will retry")
}

// Map implements engine.Mapper: a silo or Service (or a lease, through its silo) reaches the IPs it
// holds or waits for; a host's provider details or readiness reach every held IP of a plugin's
// class (only when they changed: not on every heartbeat).
func (c *Balancers) Map(changed engine.Key) []engine.Key {
	var keys []engine.Key
	add := func(x *v1.IP) { keys = append(keys, engine.Key{Kind: "IP", Namespace: x.Namespace, Name: x.Name}) }
	on := func(x *v1.IP, holder string) bool {
		return slices.ContainsFunc(x.Status.BoundTo, func(h v1.IPHolder) bool { return h.Holder == holder }) ||
			slices.ContainsFunc(x.Status.Waiting, func(h v1.IPWaiting) bool { return h.Holder == holder })
	}
	switch changed.Kind {
	case "Silo", "Service":
		holder := v1.HolderSiloPrefix + changed.Name
		if changed.Kind == "Service" {
			holder = v1.HolderServicePrefix + changed.Name
		}
		for _, o := range c.IPs.List() {
			if x := o.(*v1.IP); x.Namespace == changed.Namespace && on(x, holder) {
				add(x)
			}
		}
	case "Host":
		key := ""
		if o, ok := c.Hosts.Get("", changed.Name); ok {
			h := o.(*v1.Host)
			key = fmt.Sprintf("%v|%+v", meta.IsTrue(h.Status.Conditions, "Ready"), h.Status.Provider)
		}
		c.mu.Lock()
		if c.hostsSeen == nil {
			c.hostsSeen = map[string]string{}
		}
		prev, had := c.hostsSeen[changed.Name]
		c.hostsSeen[changed.Name] = key
		c.mu.Unlock()
		if had && prev == key {
			return nil
		}
		for _, o := range c.IPs.List() {
			if x := o.(*v1.IP); x.Spec.Class != v1.LBIPPool && len(x.Status.BoundTo) > 0 {
				add(x)
			}
		}
	}
	return keys
}

func forget(mu *sync.Mutex, m *map[string]asked, id string) {
	mu.Lock()
	defer mu.Unlock()
	delete(*m, id)
}

var (
	_ engine.Controller = (*Balancers)(nil)
	_ engine.Mapper     = (*Balancers)(nil)
)
