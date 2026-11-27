package kvo

import (
	"bytes"
	"strings"
	"testing"
	"text/tabwriter"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// describe shows an IPv6 way in as "[ADDRESS]:PORT", like a client writes it: a worker: external
// port on the worker's externalIPv6 (also when the worker has no external IPv4: it is placed, not
// waiting), and a port on a kept IPv6 IP. Before, the first read "(when placed)" and the second
// "2001:db8:20::21:8080", which no client can use.
func TestDescribeIPv6WaysIn(t *testing.T) {
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "ai"}}
	s.Spec.Ports = []v1.SiloPort{{Name: "api", Port: 8000}, {Name: "web", Port: 8080}}
	s.Spec.Services = []v1.SiloService{
		{Name: "api6", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{Worker: v1.NetworkExternal}, Ports: []v1.ServicePort{{Port: "api", As: 8443}}},
		{Name: "web6", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: "edge6"}, Ports: []v1.ServicePort{{Port: "web"}}},
	}
	s.Status.Host, s.Status.SiloIP = "w2", "10.64.2.4"
	s.Status.Service.Ports = []v1.ServicePortStatus{
		{Port: "api", Mesh: "10.64.2.4:8000", ExternalIPv6: "[2001:db8::1]:8443"},
		{Port: "web", Mesh: "10.64.2.4:8080", External: "[2001:db8:20::21]:8080"},
	}
	edge6 := &v1.IP{ObjectMeta: meta.ObjectMeta{Name: "edge6", Namespace: "ai"}}
	edge6.Spec.Type, edge6.Spec.Family = v1.IPTypeHost, v1.FamilyIPv6
	edge6.Status.Address, edge6.Status.Host = "2001:db8:20::21", "w2"
	env := &netEnv{ips: []*v1.IP{edge6}}

	var b bytes.Buffer
	tw := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
	writeSiloServices(tw, s, env)
	writeSiloPorts(tw, s)
	_ = tw.Flush()
	out := b.String()
	for _, want := range []string{"[2001:db8::1]:8443", "[2001:db8:20::21]:8080"} {
		if strings.Count(out, want) != 2 { // once under Services, once under Ports
			t.Errorf("want %s in both tables:\n%s", want, out)
		}
	}
	for _, bad := range []string{"when placed", "2001:db8:20::21:8080"} {
		if strings.Contains(out, bad) {
			t.Errorf("describe says %q:\n%s", bad, out)
		}
	}
	if got := s.Status.Service.AddressesLine(); !strings.HasPrefix(got, "in 2001:db8::1, 2001:db8:20::21") {
		t.Errorf("In and out: %q", got)
	}
}
