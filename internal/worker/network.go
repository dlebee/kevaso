package worker

import (
	"context"
	"crypto/x509"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kni"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/gate"
	"kevaso.com/core/internal/routing"
	"kevaso.com/core/sdk/kri"
)

// NetworkView builds this host's KNI view from the API: its silos (with their taps, addresses and
// what their grants open) and every running silo (allowFrom sources). Pure.
func NetworkView(hostName string, h *v1.Host, silos []*v1.Silo, grants []*v1.Grant) kni.Host {
	view := kni.Host{Bridge: cloudhypervisor.Bridge, Subnet: cloudhypervisor.Network, Gateway: cloudhypervisor.Gateway}
	if h != nil {
		view.Address, _ = netip.ParseAddr(h.Spec.Address)
	}
	for _, s := range silos {
		ip, err := netip.ParseAddr(s.Status.Address)
		if err != nil {
			continue
		}
		ks := kni.Silo{Key: s.Namespace + "/" + s.Name, IP: ip, Spec: s.Spec}
		view.All = append(view.All, ks)
		if s.Status.Host != hostName {
			continue
		}
		ks.Tap = cloudhypervisor.NamesFor(kri.ID{Namespace: s.Namespace, Name: s.Name, UID: s.UID}).Tap
		ks.PublicIP, _ = netip.ParseAddr(s.Status.Service.PublicIP)
		if len(s.Status.Service.NodePorts) > 0 {
			// Reached through the load balancer's node ports, not on its address.
			ks.PublicIP = netip.Addr{}
			ks.NodePorts, ks.SourceRanges = s.Status.Service.NodePorts, s.Status.Service.SourceRanges
		}
		if src := s.Spec.Network.Egress.Source; src == v1.EgressSameAsService || src == v1.EgressPool {
			ks.EgressIP, _ = netip.ParseAddr(s.Status.Service.EgressIP)
		}
		for _, g := range v1.GrantsFor(s, grants) {
			for _, r := range g.Spec.Egress {
				if e, err := r.Parse(); err == nil {
					ks.Egress = append(ks.Egress, e)
				}
			}
		}
		ks.GatePorts = gate.PolicyFor(s, grants).Ports()
		ks.Held = !routing.Routed(s) // routeWhen (design §0.6): no outside rule while held
		view.Local = append(view.Local, ks)
	}
	return view
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
				ip, err := netip.ParseAddr(ep.Address)
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

// PoolAddresses are the IPPool addresses this host's silos hold: they go on its uplink.
func PoolAddresses(hostName string, silos []*v1.Silo) []string {
	var out []string
	for _, s := range silos {
		if s.Status.Host == hostName && s.Status.Service.PoolIP != "" {
			out = append(out, s.Status.Service.PoolIP)
		}
	}
	return out
}

// AnnouncedAddresses are the shared addresses this host's silos are reached on (status.service
// announce): they go on its loopback, where the provider's node side announces them (BGP).
func AnnouncedAddresses(hostName string, silos []*v1.Silo) []string {
	var out []string
	for _, s := range silos {
		if s.Status.Host == hostName && s.Status.Service.Announce && s.Status.Service.PublicIP != "" && s.DeletionTimestamp == nil {
			out = append(out, s.Status.Service.PublicIP)
		}
	}
	return out
}

// RunNetwork keeps the host's silo firewall and pool addresses in line with the API: on every
// change, and every minute to repair drift. The firewall is reloaded only when its text changes
// (atomically: nft -f replaces the tables in one transaction). With an egress CA it also runs the
// egress gate.
func RunNetwork(ctx context.Context, c *client.Client, hostName string, ca *gate.CA, upstream *x509.CertPool, log func(string, ...any)) {
	silos, hosts, grantsInf := informer.New(c, "Silo"), informer.New(c, "Host"), informer.New(c, "Grant")
	secretsInf := informer.New(c, "Secret")
	ingInf, classInf := informer.New(c, "Ingress"), informer.New(c, "IngressClass")
	svcInf := informer.New(c, "Service")
	leaseInf := informer.New(c, "Lease")
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
	currentLeases := func() []*v1.Lease {
		var out []*v1.Lease
		for _, o := range leaseInf.List() {
			out = append(out, o.(*v1.Lease))
		}
		return out
	}
	currentServices := func() []*v1.Service {
		var out []*v1.Service
		for _, o := range svcInf.List() {
			out = append(out, o.(*v1.Service))
		}
		return out
	}
	if !silos.WaitSynced(ctx) || !hosts.WaitSynced(ctx) || !grantsInf.WaitSynced(ctx) {
		return
	}
	currentGrants := func() []*v1.Grant {
		var out []*v1.Grant
		for _, o := range grantsInf.List() {
			out = append(out, o.(*v1.Grant))
		}
		return out
	}
	current := func() []*v1.Silo {
		var out []*v1.Silo
		for _, o := range silos.List() {
			out = append(out, o.(*v1.Silo))
		}
		return out
	}
	go (&DNS{Listen: net.JoinHostPort(cloudhypervisor.Gateway.String(), "53"), Silos: current, Services: currentServices, Log: log}).Run(ctx)
	gatePort := 0
	if ca != nil {
		eg := &egress{c: c, hostName: hostName, ca: ca, upstream: upstream, log: log, silos: current, grants: currentGrants}
		secretsInf.AddHandler(func(informer.Key) { eg.invalidate() })
		grantsInf.AddHandler(func(informer.Key) { eg.invalidate() })
		go eg.run(ctx)
		gatePort = GatePort
	}
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	last := ""
	for {
		var all []*v1.Silo
		for _, o := range silos.List() {
			all = append(all, o.(*v1.Silo))
		}
		var me *v1.Host
		if o, ok := hosts.Get("", hostName); ok {
			me = o.(*v1.Host)
		}
		var ings []*v1.Ingress
		for _, o := range ingInf.List() {
			ings = append(ings, o.(*v1.Ingress))
		}
		var classes []*v1.IngressClass
		for _, o := range classInf.List() {
			classes = append(classes, o.(*v1.IngressClass))
		}
		view := NetworkView(hostName, me, WithIngressPaths(all, ings, classes), currentGrants())
		view.GatePort = gatePort
		view.Services = ServiceView(hostName, currentServices())
		now, ls := time.Now(), currentLeases()
		view = WithLeases(view, all, ls, now)
		leaseEnd, stopLeaseEnd := leaseTimer(ls, now)
		rules := kni.Rules(view)
		if rules != last {
			if err := applyNFT(ctx, rules); err != nil {
				log("silo firewall: %v", err)
			} else {
				last = rules
			}
		}
		if me != nil {
			if err := syncPoolAddresses(ctx, me.Spec.Address, PoolAddresses(hostName, all)); err != nil {
				log("pool addresses: %v", err)
			}
		}
		if err := syncAddresses(ctx, "lo", "lo:kv", AnnouncedAddresses(hostName, all)); err != nil {
			log("announced addresses: %v", err)
		}
		select {
		case <-ctx.Done():
			stopLeaseEnd()
			return
		case <-changed:
			time.Sleep(100 * time.Millisecond) // let a burst of changes settle
		case <-leaseEnd: // a port's lease is up: its rule goes now, whether or not the API says so yet
		case <-tick.C:
			last = "" // reload anyway: someone may have flushed the ruleset
		}
		stopLeaseEnd()
	}
}

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

// WithIngressPaths returns the silos with the paths Ingresses open (design §7.2b: "an Ingress opens
// its own path, visibly"): each Ingress's target port, reachable from its class's controller silo,
// as if the target's allowFrom said so. The silos given aren't changed. Pure.
func WithIngressPaths(silos []*v1.Silo, ingresses []*v1.Ingress, classes []*v1.IngressClass) []*v1.Silo {
	byClass := map[string]*v1.IngressClass{}
	for _, c := range classes {
		byClass[c.Name] = c
	}
	extra := map[string][]v1.AllowFrom{}
	for _, ing := range ingresses {
		c, ok := byClass[ing.Spec.IngressClass]
		if !ok || ing.DeletionTimestamp != nil {
			continue
		}
		from := c.Spec.Controller.Namespace + "/" + c.Spec.Controller.Silo
		for _, r := range ing.Spec.Rules {
			key := ing.Namespace + "/" + r.Silo.Name
			extra[key] = append(extra[key], v1.AllowFrom{Silo: from, Ports: []string{r.Silo.Port}})
		}
	}
	if len(extra) == 0 {
		return silos
	}
	out := make([]*v1.Silo, len(silos))
	for i, s := range silos {
		out[i] = s
		if add := extra[s.Namespace+"/"+s.Name]; len(add) > 0 {
			cp := *s
			cp.Spec.AllowFrom = append(append([]v1.AllowFrom(nil), s.Spec.AllowFrom...), add...)
			out[i] = &cp
		}
	}
	return out
}
