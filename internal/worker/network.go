package worker

import (
	"context"
	"crypto/x509"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kni"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/gate"
	"kevaso.com/core/internal/ingress"
	"kevaso.com/core/internal/names"
	"kevaso.com/core/internal/routing"
	"kevaso.com/core/sdk/kri"
)

// NetworkView builds this host's KNI view from the API: its silos (with their taps, addresses,
// what their grants open and the Ingress paths to them) and every running silo (allowFrom
// sources). A local silo's address here is its status's; WithBindings puts in the one its
// runtime made its port with. Pure.
func NetworkView(hostName string, h *v1.Host, silos []*v1.Silo, grants []*v1.Grant, paths map[string]map[string][]string) kni.Host {
	view := kni.Host{Bridge: cloudhypervisor.Bridge, Subnet: cloudhypervisor.Network, Gateway: cloudhypervisor.Gateway}
	if h != nil {
		view.InternalIP, _ = netip.ParseAddr(h.Internal())
		view.ExternalIP, _ = netip.ParseAddr(h.External())
		view.Reserved = h.ExtraReservedPorts() // numbers this host listens on, beyond the fixed set
		// IPv6 at the edge: only with a global address of its own (a host without one is IPv4
		// only) and an IPv6 silo subnet.
		if sub6, gw6, ok := SiloNetwork6(h); ok {
			view.Subnet6, view.Gateway6 = sub6, gw6
			view.ExternalIPv6, _ = hostAddr(h.ExternalIPv6())
		}
	}
	for _, s := range silos {
		ks := kni.Silo{Key: s.Namespace + "/" + s.Name, Spec: s.Spec}
		if c := meta.FindCondition(s.Status.Conditions, "HostPorts"); c != nil && c.Status == meta.ConditionFalse { // the controller says this silo does not hold a host port it asks for
			ks.HostPortsRefused = true
		}
		if ip, err := netip.ParseAddr(s.Status.SiloIP); err == nil {
			ks.IP = ip
			view.All = append(view.All, ks)
		}
		// A silo placed here is in the view from the start, address or not: its port is bound
		// to what its runtime gave it (WithBindings) or, until then, closed.
		if s.Status.Host != hostName {
			continue
		}
		if ip6, err := netip.ParseAddr(s.Status.SiloIPv6); err == nil && view.Subnet6.Contains(ip6) {
			ks.IP6 = ip6
		}
		ks.Tap = cloudhypervisor.NamesFor(kri.ID{Namespace: s.Namespace, Name: s.Name, UID: s.UID}).Tap
		ks.LoadBalancerIP, _ = netip.ParseAddr(s.Status.Service.LoadBalancerIP)
		if len(s.Status.Service.NodePorts) > 0 {
			// Reached through the load balancer's node ports, not on its address.
			ks.LoadBalancerIP = netip.Addr{}
			ks.NodePorts, ks.SourceRanges = s.Status.Service.NodePorts, s.Status.Service.SourceRanges
		}
		for _, g := range v1.GrantsFor(s, grants) {
			for _, r := range g.Spec.Egress {
				if e, err := r.Parse(); err == nil {
					ks.Egress = append(ks.Egress, e)
				}
			}
		}
		ks.GatePorts = gate.PolicyFor(s, grants).Ports()
		ks.Endpoint = v1.NeedsEndpoint(s, grants)
		// routeWhen (design §0.6), per service: no outside rule for a held service.
		ks.HeldServices = routing.HeldServices(s)
		ks.Held = len(s.Spec.Services) > 0 && len(ks.HeldServices) == len(s.Spec.Services)
		ks.Paths = paths[ks.Key]
		view.Local = append(view.Local, ks)
	}
	return view
}

// SiloNetwork6 is h's IPv6 silo subnet (status.network.siloSubnetIPv6, a /64) and its address in
// it on the bridge (the subnet's ::1), when h has IPv6 at the edge: a global address of its own
// (spec.externalIPv6). ok false: its silos are IPv4 only.
func SiloNetwork6(h *v1.Host) (subnet6 netip.Prefix, gateway6 netip.Addr, ok bool) {
	if h == nil {
		return netip.Prefix{}, netip.Addr{}, false
	}
	if a, ok := hostAddr(h.ExternalIPv6()); !ok || !a.Is6() {
		return netip.Prefix{}, netip.Addr{}, false
	}
	p, err := netip.ParsePrefix(h.Status.Network.SiloSubnetIPv6)
	if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() || p.Bits() != 64 || !p.Addr().IsPrivate() {
		return netip.Prefix{}, netip.Addr{}, false
	}
	p = p.Masked()
	return p, p.Addr().Next(), true
}

// ServiceView is the cluster's Services as this host's rules need them: each port's targets (the
// endpoints' addresses and target ports), marking the ones on this host. Pure.
func ServiceView(hostName string, svcs []*v1.Service) []kni.Service {
	var out []kni.Service
	for _, sv := range svcs {
		if sv.DeletionTimestamp != nil || len(sv.Status.Endpoints) == 0 {
			continue
		}
		ks := kni.Service{Key: sv.Namespace + "/" + sv.Name, SourceRanges: sv.Status.SourceRanges}
		ks.ClusterIP, _ = netip.ParseAddr(sv.Status.ClusterIP)
		nps := map[string]int{}
		for _, np := range sv.Status.NodePorts {
			nps[np.Name] = np.NodePort
		}
		for _, p := range sv.Spec.Ports {
			kp := kni.ServicePort{Proto: "tcp", Port: p.Port, NodePort: nps[p.Name]}
			if strings.EqualFold(p.Protocol, "UDP") {
				kp.Proto = "udp"
			}
			for _, ep := range sv.Status.Endpoints {
				ip, err := netip.ParseAddr(ep.SiloIP)
				if err != nil {
					continue
				}
				for _, t := range ep.Ports {
					if t.Name == p.Name {
						kp.Targets = append(kp.Targets, kni.Target{IP: ip, Port: t.NodePort, Local: ep.Host == hostName})
					}
				}
			}
			ks.Ports = append(ks.Ports, kp)
		}
		out = append(out, ks)
	}
	return out
}

// PoolAddresses are the host's own extra addresses this host's silos hold (IPs of type Host,
// status.service.hostAddresses): they go on its uplink.
func PoolAddresses(hostName string, silos []*v1.Silo) []string {
	var out []string
	for _, s := range silos {
		if s.Status.Host == hostName {
			for _, a := range s.Status.Service.HostAddresses {
				if v, ok := hostAddr(a); ok {
					out = append(out, v.String())
				}
			}
		}
	}
	return out
}

// hostV4 is a status address the host may put on an interface as a /32: one IPv4 unicast address,
// written canonically.
func hostV4(s string) (string, bool) {
	a, ok := hostAddr(s)
	if !ok || !a.Is4() {
		return "", false
	}
	return a.String(), true
}

// hostAddr is a status address the host may put on an interface as a /32 or a /128: one IPv4
// unicast address, or one global IPv6 unicast address (not link-local, not unique local: the
// silos' own /64s are fd00::/8), unmapped.
func hostAddr(s string) (netip.Addr, bool) {
	a, ok := listenAddr(s)
	if !ok || a.IsLinkLocalUnicast() {
		return netip.Addr{}, false
	}
	if a.Is6() && (!a.IsGlobalUnicast() || a.IsPrivate()) {
		return netip.Addr{}, false
	}
	return a, true
}

// AnnouncedAddresses are the shared addresses this host's silos are reached on (status.service
// announce): they go on its loopback, where the provider's node side announces them (BGP).
func AnnouncedAddresses(hostName string, silos []*v1.Silo) []string {
	var out []string
	for _, s := range silos {
		if s.Status.Host == hostName && s.Status.Service.Announce && s.Status.Service.LoadBalancerIP != "" && s.DeletionTimestamp == nil {
			if v, ok := hostV4(s.Status.Service.LoadBalancerIP); ok {
				out = append(out, v)
			}
		}
	}
	return out
}

// RunNetwork keeps the host's silo firewall and pool addresses in line with the API: on every
// change, and every minute to repair drift. The firewall is reloaded only when its text changes
// (atomically: nft -f replaces the tables in one transaction). With an egress CA it also runs the
// egress gate.
func RunNetwork(ctx context.Context, c *client.Client, hostName string, ca *gate.CA, upstream *x509.CertPool, log func(string, ...any)) {
	RunNetworkWith(ctx, c, hostName, ca, upstream, log, NetworkOptions{})
}

// NetworkOptions are RunNetworkWith's.
type NetworkOptions struct {
	// Held, if set, says when to change nothing on the host (§0.7: the control plane is older
	// than what this worker saw, or another cluster's): the rules, the pool and announced
	// addresses stay as they are, and the DNS listeners answer from what they have.
	Held func() bool
	// Bindings, if set, are the loaded rules' bindings, shared with the agent's local endpoint
	// (K-079: it takes an address only from the port they bind it to).
	Bindings *Bindings
	// StateFile, if set, keeps the last state seen (laststate.go): a start while the control
	// plane is away comes up from it (K-062).
	StateFile string
}

// RunNetworkWith is RunNetwork with options.
func RunNetworkWith(ctx context.Context, c *client.Client, hostName string, ca *gate.CA, upstream *x509.CertPool, log func(string, ...any), o NetworkOptions) {
	held := o.Held
	silos, hosts, grantsInf := informer.New(c, "Silo"), informer.New(c, "Host"), informer.New(c, "Grant")
	secretsInf := informer.New(c, "Secret")
	ingInf, classInf := informer.New(c, "Ingress"), informer.New(c, "IngressClass")
	svcInf := informer.New(c, "Service")
	leaseInf := informer.New(c, "Lease")
	ipInf := informer.New(c, "IP")
	kept := []*informer.Informer{silos, hosts, grantsInf, ingInf, classInf, svcInf, leaseInf, ipInf} // all but secrets
	sv := newServed(held, kept...)
	if o.StateFile != "" {
		if st, ok := seedLastState(o.StateFile, kept...); ok {
			sv.trust(st)         // also what a worker held from the start serves (K-097)
			secretsInf.Seed(nil) // never on disk: the gate asks for a secret when it injects it
			log("network: starting from the last state this host kept (%s), not waiting for the control plane", o.StateFile)
		}
	}
	changed := make(chan struct{}, 1)
	poke := func(informer.Key) {
		select {
		case changed <- struct{}{}:
		default:
		}
	}
	silos.AddHandler(poke)
	hosts.AddHandler(poke)
	grantsInf.AddHandler(poke)
	go silos.Run(ctx)
	go hosts.Run(ctx)
	go grantsInf.Run(ctx)
	go secretsInf.Run(ctx)
	ingInf.AddHandler(poke)
	classInf.AddHandler(poke)
	go ingInf.Run(ctx)
	go classInf.Run(ctx)
	svcInf.AddHandler(poke)
	go svcInf.Run(ctx)
	leaseInf.AddHandler(poke)
	go leaseInf.Run(ctx)
	ipInf.AddHandler(poke)
	go ipInf.Run(ctx)
	// Every input before the first ruleset: one built without the leases (or services, ingress
	// classes) closes their ports and resets what an open lease let in, on every restart.
	for _, inf := range []*informer.Informer{silos, hosts, grantsInf, secretsInf, ingInf, classInf, svcInf, leaseInf, ipInf} {
		if !inf.WaitReady(ctx) { // a seed, else the first list (K-062)
			return
		}
	}
	// What the DNS listeners and the gate answer from, at each question: while held, the last
	// trusted state, never the caches (K-097).
	current := func() []*v1.Silo { return sv.state().silos }
	currentGrants := func() []*v1.Grant { return sv.state().grants }
	currentHosts := func() []*v1.Host { return sv.state().hosts }
	currentServices := func() []*v1.Service { return sv.state().svcs }
	nameView := func() names.View { return sv.state().names() }
	loaded := o.Bindings
	if loaded == nil {
		loaded = NewBindings()
	}
	readBindings := func() map[string]Bound { return LocalBindings(stateHost) }
	go watchBindings(ctx, time.Second, readBindings, func() { poke(informer.Key{}) })
	dnsOn := &dnsListeners{run: map[string]context.CancelFunc{}}
	defer dnsOn.stop()
	gatePort := 0
	if ca != nil {
		eg := &egress{c: c, hostName: hostName, ca: ca, upstream: upstream, log: log, silos: current, grants: currentGrants, bound: loaded,
			hosts: currentHosts, services: currentServices, held: held}
		secretsInf.AddHandler(func(informer.Key) { eg.invalidate() })
		grantsInf.AddHandler(func(informer.Key) { eg.invalidate() })
		go runGate(ctx, eg)
		gatePort = GatePort
	}
	endpointAddr := netip.MustParseAddr(v1.EndpointAddress) // the silos' local endpoint, on the bridge (ADR 0009)
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	fw := &firewall{apply: func(ctx context.Context, text string) error { return applyRules(ctx, text) }}
	var opened kni.Host
	var haveOpened bool
	for {
		synced := informer.AllSynced(kept...) // before the lists: once listed, never a seed again
		st := sv.state()
		isHeld := st.held
		all, me, svcs := st.silos, st.me(hostName), st.svcs
		view := WithBindings(NetworkView(hostName, me, all, st.grants, WithIngressPaths(all, svcs, st.ings, st.classes)), readBindings())
		view.GatePort = gatePort
		view.Endpoint = endpointAddr
		view.Services = ServiceView(hostName, svcs)
		now := time.Now()
		view = WithLeases(view, all, st.leases, now)
		view = WithIPs(view, hostName, me, all, st.ips)
		leaseEnd, stopLeaseEnd := leaseTimer(st.leases, now)
		base := view
		base.Revoke = nil
		if haveOpened {
			prev := opened
			view.Revoke = &prev // an allowFrom the last loaded table had, and this one does not, is reset
		}
		rules, problems := kni.Generate(view)
		load := func() { // the rules, and once nft took them, their bindings
			if ok, err := fw.load(ctx, rules); err != nil {
				log("silo firewall: %v (the last one loaded stays; trying again in %s)", err, fw.retryAfter())
			} else if ok {
				loaded.set(kni.Bindings(view.Local))
				// Remember every allowFrom this host has loaded, not only the latest table. The
				// next table still resets a flow that is no longer allowed; a reload that dropped
				// the reset would let the established connection resume. Grants are not remembered.
				opened = kni.Remember(opened, base)
				haveOpened = true
			}
		}
		var retry <-chan time.Time
		switch {
		case st.none:
			// Held with no state trusted: nothing from a control plane this worker doesn't trust
			// (looked at again shortly).
			retry = time.After(2 * time.Second)
		case isHeld:
			// Held (K-097): the rules of the last state trusted, nothing written to the control
			// plane, the last state kept as it is.
			load()
			retry = time.After(2 * time.Second)
		default:
			load()
			if synced { // what this pass was built from, if it was all seen (never a seed) and not held
				sv.trust(st.raw)
				if o.StateFile != "" {
					if err := saveLastState(o.StateFile, st.raw); err != nil {
						log("network: keeping the last state: %v", err)
					}
				}
			}
			reportHost(ctx, c, hostName, me, hostFirewallCondition(fw.err, problems), now)
			reportPortRules(ctx, c, hostName, all, siloProblems(problems), now)
			if fw.err != nil {
				retry = time.After(fw.retryAfter())
			}
		}
		dnsOn.keep(ctx, DNSListeners(me), func(addr string, from names.Asker) *DNS {
			return &DNS{Listen: addr, From: from, View: nameView, Log: log,
				SiloNamespace: func(a netip.Addr) (string, bool) { return boundNamespace(hostName, current(), loaded, a) },
				HasGrant: func(a netip.Addr) bool {
					for _, s := range current() {
						if s.Status.SiloIP == a.String() && s.DeletionTimestamp == nil {
							return len(v1.GrantsFor(s, currentGrants())) > 0
						}
					}
					return false
				}}
		})
		if !isHeld { // no address added or removed either
			syncHostAddresses(ctx, hostName, me, all, st.ips, log)
		}
		select {
		case <-ctx.Done():
			stopLeaseEnd()
			return
		case <-changed:
			time.Sleep(100 * time.Millisecond) // let a burst of changes settle
		case <-leaseEnd: // a port's lease is up: its rule goes now, whether or not the API says so yet
		case <-retry: // the last table was refused: try again, changed or not
		case <-tick.C:
			fw.last = "" // reload anyway: someone may have flushed the ruleset
		}
		stopLeaseEnd()
	}
}

// syncHostAddresses keeps the host's pool, announced and local endpoint addresses as the silos say.
func syncHostAddresses(ctx context.Context, hostName string, me *v1.Host, all []*v1.Silo, ips []*v1.IP, log func(string, ...any)) {
	if me != nil {
		want := PoolAddresses(hostName, all)
		for _, a := range HeldAddresses(hostName, all, ips) {
			if !slices.Contains(want, a) {
				want = append(want, a)
			}
		}
		want4, want6 := split46(want)
		if err := syncPoolAddresses(ctx, me.Reach(), want4); err != nil {
			log("pool addresses: %v", err)
		}
		up6 := uplink6(me)
		switch {
		case up6 != "":
			if err := syncUplink6(ctx, up6, want6); err != nil {
				log("pool addresses (IPv6): %v", err)
			}
		case len(want6) > 0:
			log("pool addresses (IPv6): no interface has the host's address")
		}
		if err := syncBridge6(ctx, me, up6); err != nil {
			log("the silos' IPv6 gateway: %v", err)
		}
	}
	lo := AnnouncedAddresses(hostName, all)
	for _, a := range AnnouncedIPAddresses(hostName, all, ips) {
		if !slices.Contains(lo, a) {
			lo = append(lo, a)
		}
	}
	if err := syncAddresses(ctx, "lo", "lo:kv", lo); err != nil {
		log("announced addresses: %v", err)
	}
	if err := syncAddresses(ctx, cloudhypervisor.Bridge, cloudhypervisor.Bridge+":kv", []string{v1.EndpointAddress}); err != nil {
		log("the local endpoint's address: %v", err)
	}
}

// runDNS and runGate start a DNS listener and the egress gate (tests replace them: they can't
// listen on the bridge's gateway).
var (
	runDNS  = func(ctx context.Context, d *DNS) { d.Run(ctx) }
	runGate = func(ctx context.Context, e *egress) { e.run(ctx) }
)

// applyRules loads a ruleset (tests replace it).
var applyRules = applyNFT

func applyNFT(ctx context.Context, rules string) error {
	// Connection tracking on the bridge (for same-host allowFrom replies) is its own module, and
	// nft doesn't load it by itself.
	_ = exec.CommandContext(ctx, "modprobe", "nf_conntrack_bridge").Run()
	const path = "/etc/kevaso-silos.nft"
	if err := (cloudhypervisor.Local{}).WriteFile(path, []byte(rules), 0o600); err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, "nft", "-f", path).CombinedOutput()
	if err != nil {
		return &cmdError{"nft -f", err, string(out)}
	}
	return nil
}

type cmdError struct {
	cmd string
	err error
	out string
}

func (e *cmdError) Error() string {
	return e.cmd + ": " + e.err.Error() + ": " + strings.TrimSpace(e.out)
}

// syncPoolAddresses puts the wanted /32s on the interface that has hostAddr (labelled IFACE:kv so
// ours are told apart), and removes ours that aren't wanted any more.
func syncPoolAddresses(ctx context.Context, hostAddr string, want []string) error {
	iface := uplink(hostAddr)
	if iface == "" {
		if len(want) == 0 {
			return nil
		}
		return &cmdError{"find uplink", net.UnknownNetworkError(hostAddr), "no interface has the host's address"}
	}
	label := iface + ":kv"
	if len(label) > 15 {
		label = iface[:12] + ":kv"
	}
	return syncAddresses(ctx, iface, label, want)
}

// syncAddresses puts the wanted /32s on iface with label (ours), and removes ours not wanted.
func syncAddresses(ctx context.Context, iface, label string, want []string) error {
	out, err := exec.CommandContext(ctx, "ip", "-4", "-o", "addr", "show", "dev", iface, "label", label).Output()
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "inet" {
				have[strings.Split(f[i+1], "/")[0]] = true
			}
		}
	}
	wanted := map[string]bool{}
	for _, a := range want {
		wanted[a] = true
		if !have[a] {
			if b, err := exec.CommandContext(ctx, "ip", "addr", "add", a+"/32", "dev", iface, "label", label).CombinedOutput(); err != nil {
				return &cmdError{"ip addr add " + a, err, string(b)}
			}
			// Announce it (gratuitous ARP), like MetalLB: neighbours that knew it elsewhere, from
			// an earlier holder, update at once instead of when their cache expires.
			if iface != "lo" {
				_ = exec.CommandContext(ctx, "arping", "-U", "-c", "2", "-I", iface, a).Run()
			}
		}
	}
	for a := range have {
		if !wanted[a] {
			_ = exec.CommandContext(ctx, "ip", "addr", "del", a+"/32", "dev", iface).Run()
		}
	}
	return nil
}

// uplink is the interface carrying addr ("" if none).
func uplink(addr string) string {
	ip := net.ParseIP(addr)
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return i.Name
			}
		}
	}
	return ""
}

// WithIngressPaths returns the silos with the paths Ingresses open (design §7.3: "an Ingress opens
// its own path, visibly"): each rule's service port, reachable from its class's controller silos,
// as if that port's allowFrom named them (kni.Silo.Paths). For a standalone Service, every silo it
// selects, on the port it targets. Pure.
func WithIngressPaths(silos []*v1.Silo, svcs []*v1.Service, ingresses []*v1.Ingress, classes []*v1.IngressClass) map[string]map[string][]string {
	byClass := map[string]*v1.IngressClass{}
	for _, c := range classes {
		byClass[c.Name] = c
	}
	out := map[string]map[string][]string{} // silo NAMESPACE/NAME → port → callers
	for _, ing := range ingresses {
		c, ok := byClass[ing.Spec.IngressClass]
		if !ok || ing.DeletionTimestamp != nil {
			continue
		}
		for _, ctl := range silos {
			if !c.Spec.Controller.Runs(ctl) {
				continue
			}
			from := ctl.Namespace + "/" + ctl.Name
			for _, r := range ing.Spec.Rules {
				for t, port := range ingress.Targets(silos, svcs, ing.Namespace, r.Service) {
					key := t.Namespace + "/" + t.Name
					if out[key] == nil {
						out[key] = map[string][]string{}
					}
					if !slices.Contains(out[key][port], from) {
						out[key][port] = append(out[key][port], from)
					}
				}
			}
		}
	}
	return out
}

// DNSListeners are where a host answers names, and who asks on each (ADR 0010 §5): its silos'
// gateway (silos) and its mesh IP (hosts) always; its internal IP (machines on its network) and
// external IP (anyone) only when its spec.network.dns lists them. Pure.
func DNSListeners(h *v1.Host) map[string]names.Asker {
	out := map[string]names.Asker{net.JoinHostPort(cloudhypervisor.Gateway.String(), "53"): names.FromSilo}
	if h == nil {
		return out
	}
	if ip, ok := listenAddr(h.Status.Network.MeshIP); ok && ip.Is4() {
		out[net.JoinHostPort(ip.String(), "53")] = names.FromHost
	}
	for _, n := range h.Spec.Network.DNS {
		a, ok := listenAddr(h.IPOn(n))
		switch ip := a.String(); {
		case !ok:
		case n == v1.NetworkInternal:
			out[net.JoinHostPort(ip, "53")] = names.FromNetwork
		case n == v1.NetworkExternal:
			out[net.JoinHostPort(ip, "53")] = names.FromOutside
		}
	}
	return out
}

// listenAddr is s as an address a listener may bind: one specific unicast address. An
// unspecified one ("::", "0.0.0.0") would bind every address the host has, its global IPv6 one
// included; host addresses may come from a plugin (status.provider), so none is taken on trust.
func listenAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// dnsListeners runs one DNS server per wanted address, restarting none that stays the same.
type dnsListeners struct {
	run map[string]context.CancelFunc // ADDR/asker → its server's stop
}

func (l *dnsListeners) keep(ctx context.Context, want map[string]names.Asker, mk func(string, names.Asker) *DNS) {
	keys := map[string]bool{}
	for addr, from := range want {
		k := addr + "/" + from.String()
		keys[k] = true
		if _, ok := l.run[k]; ok {
			continue
		}
		c, cancel := context.WithCancel(ctx)
		l.run[k] = cancel
		go runDNS(c, mk(addr, from))
	}
	for k, stop := range l.run {
		if !keys[k] {
			stop()
			delete(l.run, k)
		}
	}
}

func (l *dnsListeners) stop() {
	for _, stop := range l.run {
		stop()
	}
}
