package worker

import (
	"context"
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
		view.Local = append(view.Local, ks)
	}
	return view
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

// RunNetwork keeps the host's silo firewall and pool addresses in line with the API: on every
// change, and every minute to repair drift. The firewall is reloaded only when its text changes
// (atomically: nft -f replaces the tables in one transaction).
func RunNetwork(ctx context.Context, c *client.Client, hostName string, log func(string, ...any)) {
	silos, hosts, grantsInf := informer.New(c, "Silo"), informer.New(c, "Host"), informer.New(c, "Grant")
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
	if !silos.WaitSynced(ctx) || !hosts.WaitSynced(ctx) || !grantsInf.WaitSynced(ctx) {
		return
	}
	current := func() []*v1.Silo {
		var out []*v1.Silo
		for _, o := range silos.List() {
			out = append(out, o.(*v1.Silo))
		}
		return out
	}
	go (&DNS{Listen: net.JoinHostPort(cloudhypervisor.Gateway.String(), "53"), Silos: current, Log: log}).Run(ctx)
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
		var grants []*v1.Grant
		for _, o := range grantsInf.List() {
			grants = append(grants, o.(*v1.Grant))
		}
		rules := kni.Rules(NetworkView(hostName, me, all, grants))
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
		select {
		case <-ctx.Done():
			return
		case <-changed:
			time.Sleep(100 * time.Millisecond) // let a burst of changes settle
		case <-tick.C:
			last = "" // reload anyway: someone may have flushed the ruleset
		}
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
			_ = exec.CommandContext(ctx, "arping", "-U", "-c", "2", "-I", iface, a).Run()
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
