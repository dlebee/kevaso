package names

import (
	"fmt"
	"math/rand"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Properties of Resolve over random clusters and every name shape (design §7.0, ADR 0010 §5):
// who asks decides the answer, and no asker learns an address it has no business with.
//
//   - a silo never resolves a host's name or a network-labelled name (refused), and never gets a
//     host's address;
//   - a machine on a host's network never gets a mesh or silo address; anyone else only external
//     addresses;
//   - a silo with no service has no name: only services (a silo's own, or a Service) make a name
//     exist, for every asker;
//   - whether a name exists doesn't depend on who asks (only whether they may ask);
//   - only silos get short names or have names forwarded; case and a trailing dot don't matter.

type genView struct {
	v          View
	hostAddrs  map[netip.Addr]string // address → network (mesh | internal | external)
	siloAddrs  map[netip.Addr]bool   // silo and cluster IPs
	services   map[string]bool       // NAMESPACE/SERVICE that exist
	noServices map[string]bool       // NAMESPACE/NAME of silos without a service
	namespaces []string
}

func genNames(r *rand.Rand) genView {
	g := genView{hostAddrs: map[netip.Addr]string{}, siloAddrs: map[netip.Addr]bool{}, services: map[string]bool{}, noServices: map[string]bool{}}
	var hosts []*v1.Host
	for i := range 1 + r.Intn(3) {
		h := &v1.Host{ObjectMeta: meta.ObjectMeta{Name: fmt.Sprintf("h%d", i)}}
		mesh := netip.AddrFrom4([4]byte{10, 63, 0, byte(i + 1)})
		h.Status.Network.MeshIP = mesh.String()
		g.hostAddrs[mesh] = v1.NetworkMesh
		if r.Intn(4) != 0 {
			a := netip.AddrFrom4([4]byte{192, 168, 1, byte(i + 1)})
			h.Spec.InternalIP = a.String()
			g.hostAddrs[a] = v1.NetworkInternal
		}
		if r.Intn(3) != 0 {
			a := netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)})
			h.Spec.ExternalIP = a.String()
			g.hostAddrs[a] = v1.NetworkExternal
		}
		if r.Intn(8) == 0 {
			now := time.Now()
			h.DeletionTimestamp = &now
		}
		hosts = append(hosts, h)
	}
	g.namespaces = []string{"dev", "prod"}
	var silos []*v1.Silo
	for i := range 2 + r.Intn(5) {
		ns := g.namespaces[r.Intn(2)]
		s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: fmt.Sprintf("s%d", i), Namespace: ns}}
		s.Spec.Ports = []v1.SiloPort{{Name: "web", Port: 80}, {Name: "adm", Port: 9000}}
		if r.Intn(5) != 0 {
			s.Status.Host = hosts[r.Intn(len(hosts))].Name
			ip := netip.AddrFrom4([4]byte{10, 64, 2, byte(i + 2)})
			s.Status.SiloIP = ip.String()
			g.siloAddrs[ip] = true
			s.Status.Phase = "Running"
		}
		if r.Intn(4) == 0 {
			g.noServices[ns+"/"+s.Name] = true
		} else {
			sv := &v1.SiloService{}
			if r.Intn(2) == 0 {
				sv.Name = fmt.Sprintf("svc%d", i)
			}
			for _, p := range []string{"web", "adm"} {
				if r.Intn(2) == 0 {
					sv.Ports = append(sv.Ports, v1.ServicePort{Port: p, HostPort: pick(r, []string{v1.NetworkInternal, v1.NetworkExternal})})
				}
			}
			s.Spec.Service = sv
			if r.Intn(5) == 0 { // held back by routeWhen: ready, not ready
				s.Spec.Probes = &v1.Probes{Readiness: &v1.Probe{TCP: &v1.TCPProbe{Port: "web"}}}
				sv.RouteWhen = v1.RouteWhenReady
			}
			g.services[ns+"/"+v1.ServiceName(s)] = true
		}
		silos = append(silos, s)
	}
	var svcs []*v1.Service
	for i := range r.Intn(3) {
		ns := g.namespaces[r.Intn(2)]
		sv := &v1.Service{ObjectMeta: meta.ObjectMeta{Name: fmt.Sprintf("vip%d", i), Namespace: ns}}
		if r.Intn(3) != 0 {
			ip := netip.AddrFrom4([4]byte{10, 65, 0, byte(i + 1)})
			sv.Status.ClusterIP = ip.String()
			g.siloAddrs[ip] = true
		}
		for _, s := range silos {
			if s.Namespace == ns && r.Intn(2) == 0 {
				sv.Status.Endpoints = append(sv.Status.Endpoints, v1.ServiceEndpoint{Silo: s.Name, Host: s.Status.Host, SiloIP: s.Status.SiloIP})
			}
		}
		g.services[ns+"/"+sv.Name] = true
		svcs = append(svcs, sv)
	}
	g.v = View{Silos: silos, Services: svcs, Hosts: hosts}
	return g
}

func pick(r *rand.Rand, from []string) []string {
	var out []string
	for _, x := range from {
		if r.Intn(2) == 0 {
			out = append(out, x)
		}
	}
	return out
}

// questions are every name shape over the view's names, and some that name nothing.
func (g genView) questions() []string {
	var out []string
	labels := []string{"nope", "h0", "h1", "s0", "s1", "s2", "svc0", "svc1", "vip0", "vip1"}
	for _, l := range labels {
		out = append(out, l, l+".kevaso")
		for _, n := range v1.Networks {
			out = append(out, l+"."+n+".kevaso")
		}
		for _, ns := range append(slices.Clone(g.namespaces), "nope") {
			out = append(out, l+"."+ns, l+"."+ns+".kevaso", strings.ToUpper(l+"."+ns+".kevaso."))
			for _, n := range v1.Networks {
				out = append(out, l+"."+ns+"."+n+".kevaso")
			}
		}
	}
	return append(out, "kevaso", "a.b.c.d.kevaso", "example.com", "", ".")
}

func TestPropertyWhoAsksDecides(t *testing.T) {
	runs := 300
	if testing.Short() {
		runs = 40
	}
	askers := []Asker{FromSilo, FromHost, FromNetwork, FromOutside}
	for seed := 0; seed < runs; seed++ {
		g := genNames(rand.New(rand.NewSource(int64(seed))))
		for _, name := range g.questions() {
			found := map[Asker]bool{}
			for _, from := range askers {
				a := Resolve(Question{Name: name, From: from, Namespace: "dev"}, g.v)
				fail := func(f string, args ...any) {
					t.Helper()
					t.Fatalf("seed %d: %s asks %q → %+v: %s", seed, from, name, a, fmt.Sprintf(f, args...))
				}
				lower := strings.TrimSuffix(strings.ToLower(name), ".")
				labels := strings.Split(strings.TrimSuffix(lower, ".kevaso"), ".")
				inZone := lower == "kevaso" || strings.HasSuffix(lower, ".kevaso")
				networkName := inZone && len(labels) >= 2 && Reserved(labels[len(labels)-1])
				if from == FromSilo && networkName && !a.Refused {
					fail("a silo resolved a host or network-labelled name")
				}
				if from != FromSilo && !inZone && a.InZone {
					fail("only silos get short names")
				}
				for _, ip := range a.IPs {
					net, isHost := g.hostAddrs[ip]
					switch from {
					case FromSilo:
						if isHost {
							fail("a silo got host address %s", ip)
						}
					case FromNetwork:
						if g.siloAddrs[ip] || net == v1.NetworkMesh {
							fail("a machine on the network got %s", ip)
						}
					case FromOutside:
						if net != v1.NetworkExternal {
							fail("someone outside got %s, not an external address", ip)
						}
					}
					if !isHost && !g.siloAddrs[ip] {
						fail("%s is nobody's address", ip)
					}
				}
				if a.Refused && (a.Found || len(a.IPs) > 0) {
					fail("refused, yet it says something")
				}
				if (a.Found || len(a.IPs) > 0) && !a.InZone {
					fail("an answer outside the zone")
				}
				// SERVICE.NAMESPACE[.NETWORK].kevaso exists only when a service has that name.
				if inZone && (len(labels) == 2 && !Reserved(labels[1]) || len(labels) == 3 && Reserved(labels[2])) && a.Found {
					key := labels[1] + "/" + labels[0]
					if !g.services[key] {
						fail("found, yet no service is named %s (no-service silo: %v)", key, g.noServices[key])
					}
				}
				if a.InZone && !a.Refused && inZone {
					found[from] = a.Found
				}
			}
			var seen []bool
			for _, f := range found {
				seen = append(seen, f)
			}
			if slices.Contains(seen, true) && slices.Contains(seen, false) {
				t.Fatalf("seed %d: whether %q exists depends on who asks: %v", seed, name, found)
			}
		}
	}
}

// Reserved is exactly the networks: the labels names use for them, and no others.
func TestReservedIsTheNetworks(t *testing.T) {
	for _, n := range []string{"mesh", "internal", "external"} {
		if !Reserved(n) {
			t.Errorf("%s isn't reserved", n)
		}
	}
	for _, n := range []string{"", "kevaso", "Mesh", "default", "kevaso-system", "meshes", "extern"} {
		if Reserved(n) {
			t.Errorf("%q reserved", n)
		}
	}
}
