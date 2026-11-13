package scheduler

import (
	"fmt"
	"math/rand"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// Placing random silos one after another, as the controller does (each placement seen by the
// next): no two silos on a host ever hold the same number on the same address (hostPort, as),
// no host gets more CPU or memory than it has, nor a silo it can't take (no such address, a taint
// it doesn't tolerate, not a worker, not Ready).
func TestPropertyPlacementsNeverClash(t *testing.T) {
	runs := 300
	if testing.Short() {
		runs = 40
	}
	for seed := 0; seed < runs; seed++ {
		r := rand.New(rand.NewSource(int64(seed)))
		var hosts []*v1.Host
		for i := range 2 + r.Intn(3) {
			h := host(fmt.Sprintf("h%d", i))
			h.Spec.InternalIP = fmt.Sprintf("10.0.0.%d", i+1)
			if r.Intn(2) == 0 {
				h.Spec.ExternalIP = fmt.Sprintf("198.51.100.%d", i+1)
			}
			switch r.Intn(8) {
			case 0:
				taint("dedicated", "db", v1.NoSchedule)(h)
			case 1:
				notReady()(h)
			case 2:
				controlPlaneOnly()(h)
			}
			hosts = append(hosts, h)
		}
		var placed []*v1.Silo
		for i := range 12 {
			s := silo(fmt.Sprintf("s%d", i), size(1+r.Intn(4), fmt.Sprintf("%dGi", 1+r.Intn(6))))
			if r.Intn(4) == 0 {
				tolerate("dedicated", "db", v1.NoSchedule)(s)
			}
			num := []int{80, 443, 5432}[r.Intn(3)]
			s.Spec.Ports = []v1.SiloPort{{Name: "p", Port: num, Protocol: []string{"TCP", "UDP"}[r.Intn(2)]}}
			if r.Intn(4) != 0 {
				sp := v1.ServicePort{Port: "p", HostPort: pick(r, []string{v1.NetworkInternal, v1.NetworkExternal})}
				if len(sp.HostPort) > 0 && r.Intn(3) == 0 {
					sp.As = []int{80, 443, 8443}[r.Intn(3)]
				}
				s.Spec.Service = &v1.SiloService{Ports: []v1.ServicePort{sp}}
			}
			d, err := Schedule(s, hosts, placed)
			if err != nil {
				t.Fatal(err)
			}
			if d.Host != "" {
				s.Status.Host = d.Host
				placed = append(placed, s)
			}
		}
		for _, h := range hosts {
			held := map[HostPort]string{}
			cpu, mem := 0, int64(0)
			for _, s := range placed {
				if s.Status.Host != h.Name {
					continue
				}
				if why := filter(s, h, h.Spec.Components.Worker, usage{}, 0); h.Spec.Components.Worker == nil || why != "" {
					t.Fatalf("seed %d: %s placed on %s: %s", seed, s.Name, h.Name, why)
				}
				for _, p := range HostPorts(s) {
					if other, ok := held[p]; ok {
						t.Fatalf("seed %d: %s and %s both hold %s on %s", seed, other, s.Name, p, h.Name)
					}
					if h.IPOn(p.Network) == "" {
						t.Fatalf("seed %d: %s holds %s on %s, which has no %s IP", seed, s.Name, p, h.Name, p.Network)
					}
					held[p] = s.Name
				}
				m, _ := v1.ParseBytes(s.Spec.Resources.Memory)
				cpu, mem = cpu+s.Spec.Resources.CPU, mem+m
			}
			alloc, _ := v1.ParseBytes(h.Status.Allocatable.Memory)
			if cpu > h.Status.Allocatable.CPU || mem > alloc {
				t.Fatalf("seed %d: %s overcommitted: %d CPU, %d bytes", seed, h.Name, cpu, mem)
			}
		}
	}
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
