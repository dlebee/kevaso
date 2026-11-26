package kni

import (
	"fmt"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/mesh"
)

func problemHas(problems []Problem, reason string) bool {
	for _, p := range problems {
		if strings.Contains(p.Reason, reason) {
			return true
		}
	}
	return false
}

func TestAHostPortOpensOnlyForTheSiloThatHoldsIt(t *testing.T) {
	spec := opens(8080, v1.ServicePort{As: 80}, v1.NetworkExternal)
	held := Silo{Key: "ns/c", IP: a("10.64.2.3"), Spec: spec}
	taken := Silo{Key: "ns/a", IP: a("10.64.2.2"), Spec: spec, HostPortsRefused: true}
	r, problems := Generate(host(taken, held))
	has(t, r, "dnat ip to 10.64.2.3:8080")
	hasNot(t, r, "dnat ip to 10.64.2.2:8080")
	if !problemHas(problems, "HostPorts condition is false") {
		t.Fatalf("the silo whose HostPorts condition is false was left out without that report: %+v", problems)
	}

	taken.HostPortsRefused = false
	r, problems = Generate(host(taken, held))
	hasNot(t, r, "dnat ip to 10.64.2.2:8080", "dnat ip to 10.64.2.3:8080")
	if len(problems) == 0 {
		t.Fatal("two silos ask for the port and it was opened, or left out without a report")
	}
}

func TestARefusedSiloOpensNoHostPortEvenAlone(t *testing.T) {
	spec := opens(8080, v1.ServicePort{As: 80}, v1.NetworkExternal)
	s := Silo{Key: "ns/a", IP: a("10.64.2.2"), Spec: spec, HostPortsRefused: true}
	r, problems := Generate(host(s))
	hasNot(t, r, "dport 80 dnat")
	if !problemHas(problems, "HostPorts condition is false") {
		t.Fatalf("a refused host port was left out without that report: %+v", problems)
	}
	// The same port on a load balancer too: the balancer's address still opens.
	s.Spec, s.LoadBalancerIP = opens(8080, v1.ServicePort{As: 80}, v1.NetworkExternal, lbWay), a("198.51.100.17")
	r, _ = Generate(host(s))
	has(t, r, "ip daddr 198.51.100.17 tcp dport 80 dnat")
	hasNot(t, r, "ip daddr 198.51.100.10 tcp dport 80 dnat")
}

func TestAPlatformHostPortIsNotTranslated(t *testing.T) {
	if v1.ReservedHostPort(mesh.DefaultPort) == "" || v1.ReservedHostPort(mesh.InnerPort) == "" {
		t.Fatal("the mesh ports are not reserved")
	}
	for _, n := range []int{22, 53, 2379, 2380, 6443, 15001, 51820, 51821} {
		spec := opens(9000, v1.ServicePort{As: n}, v1.NetworkExternal)
		if n == 51820 {
			spec.Ports[0].Protocol = "UDP"
		}
		r, problems := Generate(host(Silo{Key: "dev/a", IP: a("10.64.2.5"), Spec: spec}))
		if strings.Contains(r, fmt.Sprintf("dport %d dnat", n)) {
			t.Errorf("port %d was translated:\n%s", n, r)
		}
		if len(problems) == 0 {
			t.Errorf("port %d was left out without a report", n)
		}
	}
	for _, n := range []int{80, 443} {
		spec := opens(n, v1.ServicePort{}, v1.NetworkExternal)
		r, _ := Generate(host(Silo{Key: "dev/a", IP: a("10.64.2.5"), Spec: spec}))
		if !strings.Contains(r, fmt.Sprintf("dport %d dnat", n)) {
			t.Errorf("port %d, which a silo may take, was not translated", n)
		}
	}
	spec := opens(9000, v1.ServicePort{As: 2222}, v1.NetworkExternal)
	h := host(Silo{Key: "dev/a", IP: a("10.64.2.5"), Spec: spec})
	h.Reserved = map[int]string{2222: "the SSH port"}
	r, problems := Generate(h)
	if strings.Contains(r, "dport 2222 dnat") {
		t.Fatalf("this host's SSH port was translated:\n%s", r)
	}
	reported := false
	for _, p := range problems {
		if strings.Contains(p.Reason, "the SSH port") {
			reported = true
		}
	}
	if !reported {
		t.Fatalf("report: %+v", problems)
	}

	both := opens(6443, v1.ServicePort{As: 6443}, lbWay, v1.NetworkInternal)
	r, _ = Generate(host(Silo{Key: "dev/a", IP: a("10.64.2.5"), Spec: both, LoadBalancerIP: a("198.51.100.17")}))
	has(t, r, "ip daddr 198.51.100.17 tcp dport 6443 dnat ip to 10.64.2.5:6443")
	hasNot(t, r, "ip daddr 10.0.0.5 tcp dport 6443")
}
