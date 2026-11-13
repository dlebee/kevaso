package kni

import (
	"fmt"
	"math/rand"
	"net/netip"
	"slices"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/mesh"
)

// Properties of the rules a host gets, over random sets of silos (design §7.0, ADR 0010): what a
// packet can reach is exactly what the silos' services open, judged by sending packets through
// the generated ruleset (nfteval_test.go), not by reading its text.
//
//   - from outside, a silo's port is reached only on an address and number its service opens it
//     on, from its sources, while its lease (if any) is open and routing doesn't hold it; and then
//     it is reached (no undeclared port; sources never widen; a closed lease means no rule);
//   - from another silo, only a port whose allowFrom (or an Ingress's path) names that silo, by
//     its current address, whatever leases and routing say;
//   - a silo without a service is reached by nothing;
//   - the text doesn't depend on the order silos are given in.

const propRuns = 400

// The addresses a generated cluster uses.
var (
	propInternal = netip.MustParseAddr("10.0.0.5")
	propExternal = netip.MustParseAddr("198.51.100.10")
	propLBs      = []netip.Addr{netip.MustParseAddr("198.51.100.17"), netip.MustParseAddr("198.51.100.18"), netip.MustParseAddr("198.51.100.19"), netip.MustParseAddr("198.51.100.20")}
	// Outside clients: inside and outside every source range below.
	propClients = []netip.Addr{netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("192.0.2.200"), netip.MustParseAddr("10.0.0.9"), netip.MustParseAddr("203.0.113.4")}
	propSources = []string{"192.0.2.0/25", "192.0.2.7", "10.0.0.0/24", "203.0.113.0/24"}
	propNumbers = []int{22, 53, 80, 443, 5432, 8080, 30303}
	propAs      = []int{0, 0, 0, 443, 8443, 30000}
)

type genCluster struct {
	h      Host
	remote []Silo // on other hosts
}

func pickN[T any](r *rand.Rand, from []T, max int) []T {
	n := r.Intn(max + 1)
	var out []T
	for _, i := range r.Perm(len(from))[:min(n, len(from))] {
		out = append(out, from[i])
	}
	return out
}

// genCluster makes a host with up to four silos of its own and three elsewhere, each with random
// ports and services that admission and the scheduler would accept: one holder per host port,
// one load-balancer address per silo.
func genClusterOf(r *rand.Rand) genCluster {
	h := host()
	if r.Intn(4) == 0 {
		h.ExternalIP = netip.Addr{}
	}
	names := []string{"api", "db", "web", "cache", "worker", "ingress"}
	nss := []string{"dev", "prod"}
	held := map[string]bool{} // "network proto number" on this host
	key := func(n string) string { return nss[r.Intn(len(nss))] + "/" + n }
	var callers []string // every silo, by NAMESPACE/NAME
	var silos []*Silo
	var remotes []bool
	for i, n := range names[:3+r.Intn(4)] {
		s := &Silo{Key: key(n)}
		callers = append(callers, s.Key)
		if r.Intn(8) != 0 {
			s.IP = netip.AddrFrom4([4]byte{10, 64, 2, byte(2 + i)})
		}
		silos = append(silos, s)
	}
	for i, s := range silos {
		remote := i >= 4 || r.Intn(3) == 0
		remotes = append(remotes, remote)
		if remote && s.IP.IsValid() {
			s.IP = netip.AddrFrom4([4]byte{10, 64, 3, byte(2 + i)})
		}
		var ports []v1.SiloPort
		for j, num := range pickN(r, propNumbers, 4) {
			proto := []string{"", "TCP", "UDP"}[r.Intn(3)]
			ports = append(ports, v1.SiloPort{Name: fmt.Sprintf("p%d", j), Port: num, Protocol: proto})
		}
		s.Spec.Ports = ports
		if r.Intn(5) == 0 {
			silos[i] = s
			continue // no service
		}
		sv := &v1.SiloService{}
		for _, d := range pickN(r, ports, len(ports)) {
			sp := v1.ServicePort{Port: d.Name}
			for _, c := range pickN(r, callers, 2) {
				ns, name, _ := strings.Cut(c, "/")
				if ns == strings.SplitN(s.Key, "/", 2)[0] && r.Intn(2) == 0 {
					c = name // the short form
				}
				sp.AllowFrom = append(sp.AllowFrom, c)
			}
			sp.HostPort = pickN(r, []string{v1.NetworkInternal, v1.NetworkExternal}, 2)
			sp.LoadBalancer = r.Intn(4) == 0
			if sp.Outside() {
				sp.As = propAs[r.Intn(len(propAs))]
				sp.Sources = pickN(r, propSources, 2)
				at := sp.As
				if at == 0 {
					at = d.Port
				}
				ok := true
				for _, n := range sp.HostPort {
					ok = ok && !held[fmt.Sprintf("%s %s %d", n, d.Proto(), at)]
				}
				if !ok { // another silo on this host has it: the scheduler wouldn't put this one here
					sp.HostPort, sp.As, sp.Sources, sp.LoadBalancer = nil, 0, nil, false
				}
				if !remote {
					for _, n := range sp.HostPort {
						held[fmt.Sprintf("%s %s %d", n, d.Proto(), at)] = true
					}
				}
			}
			sv.Ports = append(sv.Ports, sp)
			if sp.Outside() && r.Intn(3) == 0 {
				s.Leased = append(s.Leased, d.Name)
				if r.Intn(2) == 0 {
					s.Closed = append(s.Closed, d.Name)
				}
			}
		}
		s.Spec.Service = sv
		if s.Spec.LoadBalanced() {
			sv.LoadBalancer = &v1.LoadBalancerSpec{Class: v1.LBIPPool}
			if !remote && r.Intn(4) != 0 {
				s.LoadBalancerIP = propLBs[i%len(propLBs)]
			}
		}
		s.Held = r.Intn(6) == 0
		if len(sv.Ports) > 0 && r.Intn(5) == 0 {
			s.Paths = map[string][]string{sv.Ports[0].Port: {callers[r.Intn(len(callers))]}}
		}
		silos[i] = s
	}
	var g genCluster
	for i, s := range silos {
		h.All = append(h.All, *s)
		if remotes[i] {
			g.remote = append(g.remote, *s)
			continue
		}
		s.Tap = fmt.Sprintf("kvt%02d", i)
		h.Local = append(h.Local, *s)
	}
	g.h = h
	return g
}

func inSources(a netip.Addr, sources []string) bool {
	if len(sources) == 0 {
		return true
	}
	for _, s := range sources {
		if p, err := netip.ParsePrefix(s); err == nil && p.Contains(a) {
			return true
		}
		if b, err := netip.ParseAddr(s); err == nil && b == a {
			return true
		}
	}
	return false
}

// outsideOracle: should a new connection from client to dst:port/proto reach silo s, and on which
// of its ports?
// A silo hairpinning through the address may also come in as itself, by its allowFrom (it may reach
// that port on the silo IP anyway): caller is its key then ("" from outside).
func outsideOracle(h Host, s Silo, client, dst netip.Addr, proto string, port int, caller string) (int, bool) {
	if !s.IP.IsValid() {
		return 0, false
	}
	for _, p := range s.Spec.Open() {
		if lower(p.Protocol) != proto || p.HostNumber() != port {
			continue
		}
		on := (p.On(v1.NetworkInternal) && h.InternalIP.IsValid() && dst == h.InternalIP) ||
			(p.On(v1.NetworkExternal) && h.ExternalIP.IsValid() && dst == h.ExternalIP) ||
			(p.LoadBalancer && s.LoadBalancerIP.IsValid() && dst == s.LoadBalancerIP)
		if !on || slices.Contains(s.Closed, p.Name) || s.Held {
			continue
		}
		if !inSources(client, p.Sources) && (caller == "" || !siloOracle(s, caller, proto, p.Number)) {
			continue
		}
		return p.Number, true
	}
	return 0, false
}

// siloOracle: may caller open a connection to s's port/proto on its silo IP?
func siloOracle(s Silo, caller string, proto string, port int) bool {
	ns := strings.SplitN(s.Key, "/", 2)[0]
	for _, p := range s.Spec.Open() {
		if lower(p.Protocol) != proto || p.Number != port {
			continue
		}
		for _, c := range append(append([]string(nil), p.AllowFrom...), s.Paths[p.Name]...) {
			if !strings.Contains(c, "/") {
				c = ns + "/" + c
			}
			if c == caller {
				return true
			}
		}
	}
	return false
}

func TestPropertyOutsideReachesOnlyWhatIsOpened(t *testing.T) {
	runs := propRuns
	if testing.Short() {
		runs = 50
	}
	dsts := append([]netip.Addr{propInternal, propExternal}, propLBs...)
	for seed := 0; seed < runs; seed++ {
		r := rand.New(rand.NewSource(int64(seed)))
		g := genClusterOf(r)
		text := Rules(g.h)
		rs := parseNFT(t, text)
		for _, client := range propClients {
			for _, iif := range []string{"eth0", g.h.Bridge} {
				src, caller := client, ""
				if iif == g.h.Bridge { // a silo here, hairpinning through the host's address
					if len(g.h.Local) == 0 || !g.h.Local[0].IP.IsValid() {
						continue
					}
					src, caller = g.h.Local[0].IP, g.h.Local[0].Key
				}
				for _, dst := range dsts {
					for _, proto := range []string{"tcp", "udp"} {
						for _, port := range append(append([]int(nil), propNumbers...), 443, 8443, 30000, 9) {
							got, reached := rs.reaches(t, g.h, pkt{iif: iif, saddr: src, daddr: dst, proto: proto, dport: port})
							var want netip.AddrPort
							wanted := false
							for _, s := range g.h.Local {
								if n, ok := outsideOracle(g.h, s, src, dst, proto, port, caller); ok {
									want, wanted = netip.AddrPortFrom(s.IP, uint16(n)), true
								}
							}
							if reached != wanted || got != want {
								t.Fatalf("seed %d: %s from %s (%s) to %s:%d: reached %v %v, want %v %v\n%s", seed, proto, src, iif, dst, port, reached, got, wanted, want, text)
							}
						}
					}
				}
			}
		}
	}
}

func TestPropertySiloToSiloOnlyByAllowFrom(t *testing.T) {
	runs := propRuns
	if testing.Short() {
		runs = 50
	}
	for seed := 0; seed < runs; seed++ {
		r := rand.New(rand.NewSource(int64(seed)))
		g := genClusterOf(r)
		text := Rules(g.h)
		rs := parseNFT(t, text)
		for _, dst := range g.h.Local {
			if !dst.IP.IsValid() {
				continue
			}
			for _, caller := range g.h.All {
				if !caller.IP.IsValid() || caller.Key == dst.Key {
					continue
				}
				local := g.h.Subnet.Contains(caller.IP)
				for _, proto := range []string{"tcp", "udp"} {
					for _, port := range propNumbers {
						want := siloOracle(dst, caller.Key, proto, port)
						var got bool
						if local {
							got = rs.bridged(t, pkt{iif: "kvt-caller", oif: "kvt-dst", saddr: caller.IP, daddr: dst.IP, proto: proto, dport: port})
						} else {
							_, got = rs.reaches(t, g.h, pkt{iif: "kevaso0", saddr: caller.IP, daddr: dst.IP, proto: proto, dport: port})
						}
						if got != want {
							t.Fatalf("seed %d: %s (%s) to %s %s:%d: %v, want %v\n%s", seed, caller.Key, caller.IP, dst.Key, proto, port, got, want, text)
						}
					}
				}
			}
			// Nobody else, by any address that isn't a running silo's.
			for _, stranger := range []netip.Addr{netip.MustParseAddr("10.64.9.9"), netip.MustParseAddr("10.64.2.250")} {
				for _, port := range propNumbers {
					if _, ok := rs.reaches(t, g.h, pkt{iif: "kevaso0", saddr: stranger, daddr: dst.IP, proto: "tcp", dport: port}); ok {
						t.Fatalf("seed %d: %s reached %s:%d\n%s", seed, stranger, dst.Key, port, text)
					}
					if rs.bridged(t, pkt{iif: "kvt-x", oif: "kvt-y", saddr: stranger, daddr: dst.IP, proto: "tcp", dport: port}) {
						t.Fatalf("seed %d: %s bridged to %s:%d\n%s", seed, stranger, dst.Key, port, text)
					}
				}
			}
		}
	}
}

// Removing a silo's service removes everything it opened: nothing reaches it any more, from
// anywhere, and every rule that named its ports is gone.
func TestPropertyRemovingTheServiceClosesEverything(t *testing.T) {
	for seed := 0; seed < propRuns/4; seed++ {
		r := rand.New(rand.NewSource(int64(seed)))
		g := genClusterOf(r)
		if len(g.h.Local) == 0 {
			continue
		}
		i := r.Intn(len(g.h.Local))
		s := &g.h.Local[i]
		if !s.IP.IsValid() {
			continue
		}
		s.Spec.Service, s.LoadBalancerIP, s.Paths, s.NodePorts = nil, netip.Addr{}, nil, nil
		for j := range g.h.All {
			if g.h.All[j].Key == s.Key {
				g.h.All[j] = *s
			}
		}
		text := Rules(g.h)
		rs := parseNFT(t, text)
		for _, l := range strings.Split(text, "\n") {
			if strings.Contains(l, "daddr "+s.IP.String()+" ") && strings.Contains(l, "accept") {
				t.Fatalf("seed %d: %s has no service, yet: %s", seed, s.Key, strings.TrimSpace(l))
			}
		}
		for _, port := range propNumbers {
			for _, from := range append([]netip.Addr{netip.MustParseAddr("10.64.3.2")}, propClients...) {
				if _, ok := rs.reaches(t, g.h, pkt{iif: "kevaso0", saddr: from, daddr: s.IP, proto: "tcp", dport: port}); ok {
					t.Fatalf("seed %d: %s reached %s:%d without a service", seed, from, s.Key, port)
				}
			}
			for _, dst := range append([]netip.Addr{propInternal, propExternal}, propLBs...) {
				if got, ok := rs.reaches(t, g.h, pkt{iif: "eth0", saddr: propClients[0], daddr: dst, proto: "tcp", dport: port}); ok && got.Addr() == s.IP {
					t.Fatalf("seed %d: %s:%d reached %s without a service", seed, dst, port, s.Key)
				}
			}
		}
	}
}

// The same silos in any order make the same text (unchanged means no reload, and no rule's
// position depends on the API's list order).
func TestPropertyRulesIgnoreOrder(t *testing.T) {
	for seed := 0; seed < propRuns/4; seed++ {
		r := rand.New(rand.NewSource(int64(seed)))
		g := genClusterOf(r)
		want := Rules(g.h)
		h := g.h
		h.Local, h.All = slices.Clone(h.Local), slices.Clone(h.All)
		r.Shuffle(len(h.Local), func(i, j int) { h.Local[i], h.Local[j] = h.Local[j], h.Local[i] })
		r.Shuffle(len(h.All), func(i, j int) { h.All[i], h.All[j] = h.All[j], h.All[i] })
		if got := Rules(h); got != want {
			t.Fatalf("seed %d: order changed the rules", seed)
		}
	}
}

// A packet from the host's uplink that claims to come from a silo elsewhere (its source spoofed:
// a machine on the host's network routing 10.64.0.0/16 through it) must not get through a port
// that allowFrom opens only to that silo. Silo traffic between hosts comes over the mesh only.
func TestSpoofedSiloSourceFromTheUplink(t *testing.T) {
	db := Silo{Key: "dev/db", IP: a("10.64.2.4"), Tap: "kvt04", Spec: v1.SiloSpec{
		Ports:   []v1.SiloPort{{Name: "pg", Port: 5432}},
		Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "pg", AllowFrom: []string{"api"}}}}}}
	api := Silo{Key: "dev/api", IP: a("10.64.3.7")} // on another host
	h := host(db)
	h.All = []Silo{api, db}
	rs := parseNFT(t, Rules(h))
	if _, ok := rs.reaches(t, h, pkt{iif: "kevaso0", saddr: api.IP, daddr: db.IP, proto: "tcp", dport: 5432}); !ok {
		t.Fatal("api over the mesh doesn't reach db: the evaluator or the rules are off")
	}
	for _, iif := range []string{"eth0", "kevaso1"} {
		_, ok := rs.reaches(t, h, pkt{iif: iif, saddr: api.IP, daddr: db.IP, proto: "tcp", dport: 5432})
		if want := iif != "eth0"; ok != want {
			t.Errorf("api's address arriving on %s reaches db: %v, want %v", iif, ok, want)
		}
	}
}

// The rules name the mesh's devices; they are internal/mesh's.
func TestMeshDevicesAreTheMeshes(t *testing.T) {
	if meshDevices[0] != mesh.Outer || meshDevices[1] != mesh.Inner {
		t.Fatalf("kni allows silo sources from %v; the mesh's devices are %s, %s", meshDevices, mesh.Outer, mesh.Inner)
	}
}
